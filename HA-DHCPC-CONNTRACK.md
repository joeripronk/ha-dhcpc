# HA-DHCPC Conntrack Sync (Plan)

Plan to add **conntrack state synchronization** to `ha-dhcpc` so that active
connection-tracking entries owned by traffic flowing through the current master
can be replicated to slaves. On failover, the promoted node can continue
forwarding established flows (NATed and forwarded connections, including SIP/VoIP
helper-assisted flows) with minimal disruption.

Status: **proposal / design plan** (not implemented).

## 1. Problem and motivation

`ha-dhcpc` already keeps DHCP lease/config, VIP ownership, and edge routing state
consistent across members, but the Linux kernel's conntrack table (`nf_conntrack`)
is local to each node. When the master fails over:

- established forwarded/TCP/UDP flows handled by the old master may break because
  the new master has no matching conntrack (and NAT) entries;
- stateful firewall rules (`-m conntrack --ctstate ESTABLISHED,RELATED`) drop
  packets that would otherwise have been valid continuations;
- helper-dependent protocols (SIP signaling/media expectations, related RTP
  pinholes where applicable) lose association state.

The desired outcome is **best-effort continuity** of non-local conntrack entries
across master/slave promotion, synchronized over a dedicated reliable channel and
applied only on passive nodes until they become master.

## 2. Goals

- **Sync non-local conntrack entries** from the master to all configured slaves.
- **TCP transport** for conntrack replication (reliable, ordered stream), separate
  from the existing UDP cluster heartbeat/state/control transport.
- **Run in a separate thread** (dedicated conntrack sync worker) so conntrack
  dump/event processing and replication do not block the main epoll/event loop or
  the heartbeat cadence thread.
- **Simple binary protocol optimized for CPU effectiveness:** fixed-layout headers,
  integer/network-order fields, minimal parsing/allocation, no JSON in the data
  path, cheap framing and validation.
- **SIP/VoIP helper support awareness:** observe and cache nfnetlink helper status;
  replicate helper-relevant conntrack attributes needed for SIP/VoIP continuity
  when present, and surface helper availability/capability explicitly.
- **Master-only source of truth:** only the current master originates conntrack
  sync updates; slaves receive/apply them passively.
- **Failover-safe behavior:** slaves keep a reconciled shadow view and can activate
  it on promotion; stale/invalid entries are expired conservatively rather than
  trusted blindly.
- **Operational visibility:** status/logging for connection state, queue depth,
  sync lag/versioning, dropped/filtered entries, and helper-cache state.

## 3. Non-goals (v1)

- Bidirectional multi-master conntrack merging or conflict-free replicated CT
  database semantics.
- Perfect lossless continuity for every protocol/flow (best-effort, bounded by
  kernel/helper semantics and replication lag).
- Replacing netfilter/conntrack tooling (`conntrackd`) as a general-purpose
  standalone daemon.
- Full userspace reimplementation of all protocol helpers; v1 focuses on
  **SIP/VoIP helper support** and generic conntrack/NAT tuple replication.
- **IPv6 deferred in v1** (IPv4-only scope, matching current cluster/VIP
  addressing). Protocol/wire format is extensible (address family/length fields)
  for future IPv6.
- Authentication/encryption redesign of all cluster traffic in v1 (conntrack sync
  runs on a trusted L2 sync network; HMAC/mTLS hooks are reserved for later
  hardening aligned with cluster transport v2).

## 4. Terminology and assumptions

- **Non-local conntrack entry:** a conntrack entry whose traffic is being
  forwarded/NATed by this node for other endpoints (not purely local process
  traffic owned by the node itself). Exact classification policy is defined in
  §6.2.
- **Master (owner):** the current `HADC_ROLE_MASTER`; authoritative source for
  conntrack replication.
- **Slave (replica):** `HADC_ROLE_SLAVE`; receives and stages/applies replicated
  entries but never originates replication.
- **Helper cache:** in-memory cache of conntrack helper/module status gathered via
  netlink (and/or procfs fallback) used to decide SIP/VoIP handling and report
  capability.
- **Trusted sync link:** replication uses the same trusted cluster segment and
  per-node `sync_address` identities as the UDP cluster transport (distinct
  per-node addresses).

Assumptions:
- Linux kernel with nf_conntrack and nfnetlink_conntrack support.
- Sufficient privileges/capabilities to read and (on apply) create/update
  conntrack entries (`CAP_NET_ADMIN` / root in typical deployments).
- Cluster members share equivalent NAT/firewall topology expectations for promoted
  ownership (same interfaces/zone intent), as with existing VIP failover.

## 5. High-level architecture

```
master node
  rtnetlink addr discovery/cache (IPv4 local+VIP) -+
  nfnetlink conntrack (dump + event monitor) ------+-- conntrack sync thread
  nfnetlink/helper status cache <------------------+      - classify/filter
                                                   |      - encode binary msgs
                                                   |      - TCP send to slaves
                                                   v
                                         TCP conntrack sync stream(s)

slave node
  TCP accept/connect endpoint ----------------------+-- conntrack sync thread
                                                   |      - decode/validate
                                                   |      - dedupe/version checks
                                                   |      - stage/apply via nfct API
                                                   v
                                          local conntrack table / shadow state

main ha-dhcpc thread remains owner of role/config/persist/event loop;
thread handoff uses lock-protected state snapshots + wake/eventfd channels.
```

Key principles:
- **Separate thread:** all blocking TCP I/O, conntrack event backlog handling,
  netlink address/helper cache refresh, and bulk encoding/decoding run off the main
  loop.
- **Role-aware:** replication direction follows cluster role transitions; a demoted
  node stops originating and becomes replica.
- **Idempotent updates:** entries are keyed by tuple/protocol/zone identity and
  version/timestamp metadata to avoid churn.
- **CPU-first protocol:** fixed-size records where possible, packed TLVs only for
  variable attributes, zero-copy-friendly parsing.
- **IPv4-only v1:** local/VIP discovery and conntrack sync scope are IPv4.

## 6. Conntrack data model and filtering

### 6.1 Sources

Use nfnetlink/conntrack as the primary source via **`libnetfilter_conntrack`** (with
libmnl/event integration as needed) for v1 attribute coverage and correctness:
- **Initial snapshot:** dump current conntrack table on master startup/promotion or
  on slave (re)connect/full-resync request.
- **Incremental updates:** subscribe to conntrack NEW/UPDATE/DESTROY events on the
  master and translate to replication messages.
- **Periodic reconciliation:** hybrid resync — generation/epoch/seq awareness,
  snapshot on gap/mismatch/overflow or reconnect, and optional bounded periodic
  anti-entropy when configured.

Avoid shelling out to `conntrack(8)` in steady state; CLI tools may be used only
for diagnostics. Direct `NETLINK_NETFILTER` handling is deferred unless profiling
requires it.

### 6.2 "Non-local" classification (v1 policy)

An entry is eligible for sync when it represents transit/NATed traffic relevant to
failover continuity, not purely host-local traffic. **v1 is IPv4-only.** The master
classifies entries using address ownership discovered via **netlink (rtnetlink,
`RTM_GETADDR`)** plus cluster state:

- **Local/owned IPv4 set (refreshed from netlink, cached):** addresses on the
  managed DHCP/cluster interfaces and the current **VIP/cluster addresses** owned by
  this node (as applied by the executor/role state). Discovery is event-driven where
  possible (netlink addr/link notifications) with periodic refresh fallback.
- **Include** (non-local/replicable): conntrack entries whose original/reply tuples
  indicate forwarded or NATed traffic for the managed path, e.g. SNAT/DNAT/MASQ or
  NAT-manipulated flows, and flows whose endpoints are associated with the public
  lease/VIP/managed-interface address set rather than host-local-only communication.
- **Include `RELATED`** helper-created expectations/flows associated with an
  eligible synced master flow (SIP/RTP as supported).
- **Exclude** by default: loopback/local-only process traffic not traversing managed
  forwarding paths, entries not associated with the discovered owned/managed IPv4 set
  or configured zones, and malformed/unusable entries missing required tuple/state
  fields.

The plan must preserve an explicit **classification reason** in logs/stats
(included/excluded + why) to make behavior debuggable. Exact rules are finalized in
implementation against existing firewall/NAT deployment patterns.

### 6.3 Entry attributes (minimum useful set)

Replicate enough to recreate/refresh kernel state (**v1 IPv4-only**):
- address family (`AF_INET` in v1), L4 protocol
- original/reply tuples (IPv4 src/dst addr, src/dst port as applicable)
- TCP state (if TCP), timeout/lifetime hint
- conntrack status flags (ASSURED, SEEN_REPLY, DNAT/SNAT-related flags, etc.)
- NAT/manipulation fields required for continuity
- zone/mark (if used and configured)
- helper name/type and nfct-exposed helper info required for SIP/VoIP continuity
  (bounded/explicit allowlist; unknown blobs omitted with reason; best-effort,
  capability-gated)

Entries that cannot be safely represented/applied are dropped with counters, not
partially corrupted. Wire encoding reserves address-family/length extensibility for
future IPv6.

## 7. SIP/VoIP helper support and netlink status cache

### 7.1 Helper status cache

Maintain a **cache of netlink-derived helper status** in the conntrack sync
thread:
- query helper/module availability (nfct helper info / ctnetlink helper queries,
  with optional `/proc` or module presence fallback for diagnostics);
- track whether SIP helper support is available, loaded, and usable for the active
  kernel/userspace configuration;
- refresh on startup, on role changes, and on timer/notification-driven invalidation
  (and expose last refresh/result).

Cache properties:
- lock-protected snapshot readable by status/reporting paths;
- explicit states: `unknown`, `available`, `unavailable`, `degraded`;
- includes observed helper names relevant to VoIP (e.g. `sip`, and `ftp`-style
  future extension hooks if generalized later) and reason strings.

### 7.2 SIP/VoIP handling

- **Best-effort, capability-gated:** sync SIP-related master/related flows and
  helper linkage metadata that `libnetfilter_conntrack`/kernel APIs expose and that
  can be safely applied on a replica (allowlisted helper name/info, related
  expectations/flows when observable).
- Do **not** claim RTP continuity unless the corresponding conntrack/expectation
  state was actually replicated and applied; report partial capability.
- If helper support is unavailable or degraded (`helpers.sip=auto`), continue
  syncing generic conntrack entries and emit clear warnings/metrics/status (no
  silent success). `helpers.sip=require` makes SIP helper unavailability a reported
  degraded condition for VoIP continuity.

## 8. TCP transport and connection model

### 8.1 Why TCP

Replication requires reliable delivery of snapshots and ordered incremental updates;
TCP is used instead of UDP for conntrack sync data. Existing UDP cluster transport
remains for low-latency heartbeats/role/conf control.

### 8.2 Topology and addressing

- Listen/connect on each node's distinct `sync_address` (same identity model as
  cluster membership), on a dedicated `conntrack.port` (configurable).
- **v1 direction: master-initiated.** The current master initiates outbound TCP
  connections to each configured slave `sync_address:conntrack.port`; slaves accept
  only configured cluster peers. This keeps sequencing, queueing/backpressure, and
  reconnect/resync ownership on the role that originates state (aligned with
  master-push cluster sync).
- One long-lived TCP connection per master->slave pair, with reconnect/backoff.

### 8.3 Session lifecycle

1. Master connects to slave TCP endpoint + protocol handshake (`HELLO`/`HELLO_ACK`
   with node id, role, protocol version, capabilities, generation/epoch, and
   config/cluster digest context as needed).
2. **Hybrid resync:** master starts a full snapshot on fresh peer, reconnect,
   promotion/demotion relevance, generation/epoch mismatch, or explicit `RESYNC_REQ`;
   slave may request resync on detected gap/lag.
3. Master streams snapshot records (`SNAPSHOT_BEGIN/ENTRY/END`) followed by
   incremental `UPSERT`/`DELETE` events with per-session monotonic `seq` and
   peer `ack_seq` watermark.
4. Keepalive/idle probes at application level (small fixed frames) to detect dead
   peers faster than TCP defaults where useful.
5. On disconnect, peer marks replica stale; master retries with bounded backoff;
   slave discards partial frame state safely. Force resync on decode/apply backlog
   overflow, detected gaps, or sustained lag. Optional periodic anti-entropy is off
   by default.

### 8.4 Backpressure and failure handling

- Bounded per-peer send queues; on overflow, drop/coalesce oldest superseded
  updates where safe and force a resync marker (never block the main thread).
- Per-peer stats: connected, last ack/seq, lag, drops, resync count, last error.
- During partition or slave minority states, replication continues only according
  to role ownership rules (master remains authoritative; slaves never originate).

## 9. Binary protocol (CPU-effective, v1 draft)

### 9.1 General encoding rules

- **Binary, fixed header + typed records/TLVs**, network byte order for integers.
- No JSON, no text parsing in steady state (except optional debug tooling outside
  data path).
- Versioned header/capabilities for forward compatibility; unknown non-critical TLVs
  can be skipped by length. **v1 payload scope is IPv4-only**, but records carry
  address family/length to reserve IPv6 extensibility.
- Alignment/padding chosen to keep decode simple (e.g. 4- or 8-byte alignment for
  TLV bodies where beneficial) while minimizing copies.

### 9.2 Frame format (proposed)

All frames share a common header:

```
struct hadc_ct_hdr {
    uint8_t  magic[4];      /* "HCT1" */
    uint8_t  ver;           /* protocol version = 1 */
    uint8_t  type;          /* HELLO, SNAPSHOT_BEGIN/END, UPSERT, DELETE, ... */
    uint16_t flags;         /* resync/generation/capability bits (reserved v1) */
    uint32_t len;           /* payload bytes following header */
    uint32_t seq;           /* per-connection monotonic sequence */
    uint32_t ack_seq;       /* peer ack/progress watermark */
}; /* 20 bytes, fixed */
```

Payload is one record or a small record batch (batching allowed for CPU/syscall
efficiency). Message types (initial set):
- `HELLO`, `HELLO_ACK` (capabilities, generation/epoch, auth hooks reserved)
- `SNAPSHOT_BEGIN`, `SNAPSHOT_ENTRY`, `SNAPSHOT_END`
- `UPSERT` (new/update), `DELETE` (destroy/timeout)
- `RESYNC_REQ`, `KEEPALIVE`, `ERROR`

### 9.3 Record/TLV layout (proposed)

Use compact fixed fields for common tuple/state data and TLVs for optional/helper
attributes:

- Fixed core (v1): `family` (`AF_INET`), `addr_len`, proto, flags/status, tcp_state,
  timeout_s, zone, mark, orig/reply IPv4 addrs+ports.
- TLVs: `NAT`, `HELPER_ID/NAME`, `HELPER_INFO` (bounded, allowlisted), `LABEL/MARK_EXT`,
  `TIMESTAMP_META` (reconciliation heuristics), reserved capability/auth TLVs.

Design constraints:
- deterministic encode/decode order;
- strict bounds checks on all lengths/counts/families;
- avoid per-record dynamic structures where fixed arrays suffice;
- prefer integer IDs/enums over strings in hot path (`HELPER_*` may use interned IDs;
  strings only in handshake/capability exchange if needed).

## 10. Threading model and integration

### 10.1 Dedicated conntrack sync thread

Add a separate worker thread (e.g. `ctsync`/`conntrack_thread`) responsible for:
- owning TCP sockets and peer state machines (master-initiated to slaves in v1);
- rtnetlink IPv4 local/VIP address discovery/cache refresh for classification;
- receiving nfnetlink conntrack events/dumps via `libnetfilter_conntrack`;
- encoding/decoding binary protocol frames;
- applying replicated entries on slaves through conntrack APIs (staged by default);
- maintaining helper-status cache (SIP/VoIP capability-gated).

The main thread remains the authority for role, lease/config, persistence, and
existing epoll-driven subsystems.

### 10.2 Cross-thread coordination

- **Role/state snapshot:** atomic or mutex-protected view (`role`, master id,
  member/sync addresses, VIP/managed interface context, enabled flags) updated on
  role changes/config reload/executor state changes.
- **Wake/eventfd pipe:** main loop notifies worker of role change, shutdown,
  config reload, address/VIP changes, or manual resync requests without polling races.
- **Stats snapshot:** worker publishes counters/state for `ctl status` and logs via
  a lock-protected read-only structure.
- **Shutdown:** coordinated stop flag + socket/eventfd wake + thread join; no
  blocking operations on main thread during teardown.

### 10.3 Interaction with existing modules

- `cluster.c`: consume promote/demote transitions to start/stop originating and to
  switch replica behavior (staged apply on promotion); reuse member identity
  (`sync_address`, ids), but keep TCP conntrack transport independent from UDP.
- `config.c` / `ha-dhcpc.conf`: add `conntrack_sync` (TCP port, filters, helpers,
  apply/resync settings); include in shared-config validation/digest semantics.
- `executor.c`/state: surface VIP/managed IPv4 ownership context to the conntrack
  classifier cache.
- `internal.h` / `main.c`: lifecycle init/start/stop hooks and status wiring.
- `persist.c`: optionally persist minimal conntrack-sync metadata (generation/last
  seq/capability observations) only if useful; do not persist full CT tables.
- `ctl`: expose status and optional `conntrack resync`/diagnostic commands.

## 11. Proposed configuration (draft)

```yaml
conntrack_sync:
  enabled: false            # default off
  port: 4501                # TCP conntrack replication port (separate from cluster UDP)
  mode: master-push         # v1 fixed: master initiates TCP to slaves
  max_queue_entries: 8192   # bounded per-peer/send buffering
  snapshot_on_connect: true
  resync_interval_s: 0      # 0 = event-driven + gap/overflow resync; >0 periodic anti-entropy

  filter:
    non_local_only: true
    families: [ipv4]        # v1 IPv4-only; reserved extensibility for ipv6
    include_related: true
    exclude_loopback: true
    # classification uses rtnetlink-discovered local IPv4 + VIP/managed addresses

  helpers:
    sip: auto               # auto | require | off (best-effort, capability-gated)
    cache_refresh_s: 30     # netlink helper-status cache refresh cadence

  apply:
    slave_apply: staged     # staged (default) | immediate
    max_entry_age_s: 300    # drop/expire stale replicated entries conservatively
```

Notes:
- Keep feature off by default; when enabled, require explicit cluster membership and
  trusted sync addressing.
- `helpers.sip=auto` uses SIP/VoIP helper support when cache reports it available;
  warn/report degraded/unavailable and continue with generic ct sync. `require`
  reports degraded VoIP continuity if unavailable.
- Do not co-run with `conntrackd` in the same replication domain by default.

## 12. Observability and operations

- **`ctl status` / structured logs:** enabled, role mode (originating/replica),
  thread running, peer connections, seq/ack/lag, queue depth, snapshot/resync state,
  sent/received/applied/dropped counts, classification drop reasons.
- **Helper cache visibility:** SIP/helper availability state, last refresh time,
  source/result, and capability caveats.
- **Failure visibility:** connect errors, protocol validation failures, apply errors
  (EPERM/EEXIST/ENOENT), overflow/resync events.
- **Debug tooling (later):** optional counters dump and safe protocol tracing hooks
  without changing wire format.

## 13. Security and safety considerations

- Treat conntrack replication as **trusted-fabric only** in v1 (same posture as
  current unauthenticated UDP cluster transport unless extended). **v1 uses
  plaintext TCP** on per-node `sync_address` with configured-peer allowlisting.
- Reserve protocol version/capability/auth hooks for future HMAC or mTLS hardening,
  aligned with cluster transport evolution.
- Strict bounds/validation on every frame, record, TLV, family/address length, and
  count; malformed input must close/reset peer state safely.
- Never trust replicated data to alter role/config ownership; only conntrack data
  path is affected.
- Apply only entries permitted by local policy/filter (IPv4, managed/local+VIP set,
  non-local classification); log and count rejects.
- Resource controls: bounded queues, bounded snapshot rate, bounded entry age/size.

## 14. Risks and mitigations

- **Replication lag / missed events:** TCP ordering + sequence numbers + periodic or
  reconnect-triggered resync.
- **State divergence between nodes:** conservative apply, idempotent upserts/deletes,
  reconciliation markers, and explicit stale-entry aging.
- **Kernel/helper API variability:** abstract conntrack/helper access; capability
  detection via helper cache; degrade gracefully.
- **CPU overhead under high flow churn:** binary protocol, batching, coalescing,
  filtering non-local entries early, and separate thread.
- **Incorrect classification causing noise or misses:** explicit policy, counters by
  reason, and staged rollout with observability.
- **Failover split-brain interaction:** master-only origination tied to existing
  cluster role/quorum decisions; replicas do not originate.

## 15. Implementation milestones

- **C0 — Design freeze:** confirm non-local classification rules, exact TCP
  connection direction, nfct/libnetfilter_conntrack vs direct netlink strategy,
  SIP/helper metadata scope, and config schema.
- **C1 — Core scaffolding:** config parsing/validation, status structs, dedicated
  conntrack sync thread lifecycle, TCP listener/connect plumbing, handshake and
  binary framing/decoder with strict validation tests.
- **C2 — Helper status cache:** netlink helper-status query/cache, refresh policy,
  SIP capability reporting, and observability.
- **C3 — Master export path:** conntrack snapshot + event subscription, non-local
  filtering/classification, encoding, batching/backpressure, and per-peer send.
- **C4 — Slave import/apply path:** decode/validate, dedupe/version handling,
  conntrack create/update/delete apply path, staged activation/resync support.
- **C5 — Role/failover integration:** master promotion/demotion transitions,
  reconnect/resync behavior, ctl status/resync hooks, persistence metadata (if any).
- **C6 — Validation and hardening:** lab/netns failover tests (TCP/UDP/NAT flows,
  SIP-signaling scenarios where helper support exists), fuzz/robustness tests for
  decoder, performance profiling, docs/runbook.

## 16. Open questions and proposed answers

1. **Non-local definition (exact):** *Resolved direction (v1, IPv4-only).* Discover
   local/owned IPv4 addresses via **netlink (rtnetlink `RTM_GETADDR`)** on managed
   interfaces and include current **VIP/cluster addresses** from cluster/executor
   state (cached, refreshed on netlink events/periodic). Classify by a combination:
   NAT/forwarding relevance + association with that owned/managed IPv4 set; include
   eligible `RELATED` helper flows; exclude loopback/local-only and unmanaged
   traffic. Keep reasons/counters configurable/debuggable.
2. **Connection direction:** **Master-initiated TCP** to each slave
   `sync_address:conntrack.port` (one connection per peer). Master owns sequencing,
   backpressure, reconnect and resync on promotion; slaves accept only configured
   peers.
3. **Conntrack API choice:** **`libnetfilter_conntrack` (+ libmnl integration as
   needed)** for v1 for correctness/attribute coverage, with compact internal records
   and low-allocation batching; consider direct `NETLINK_NETFILTER` only if profiling
   requires it.
4. **SIP metadata completeness:** **Best-effort, capability-gated.** Replicate core
   tuple/state/timeout/status/NAT/mark/zone + allowlisted nfct-exposed helper name/info
   and related/expected flows when observable/applicable. Helper cache reports
   `available/degraded/unavailable`; no continuity claim unless state was actually
   replicated/applied.
5. **Apply mode on slaves:** Default **`staged`** shadow state + age/validate, apply
   on promotion (optional `immediate` for warm replicas). Safer for passive nodes.
6. **IPv6 scope:** **Defer implementation; IPv4-only in v1.** Wire format/protocol
   reserves address-family/length extensibility for future IPv6.
7. **Resync strategy:** **Hybrid** — snapshot on connect/promotion or generation
   mismatch, incremental `UPSERT/DELETE` with seq/ack, forced resync on gap/overflow
   or sustained lag, optional periodic anti-entropy off by default.
8. **Security roadmap:** **v1 trusted-LAN plaintext TCP** on `sync_address` with
   strict validation, peer allowlisting and resource bounds; reserve auth/capability
   hooks (HMAC/mTLS) for later hardening aligned with cluster transport.
9. **Interaction with existing tools:** **Single sync authority.** Do not co-run
   with `conntrackd` in the same replication domain by default; explicit opt-in,
   status/warnings on suspected conflict, ha-dhcpc-owned behavior documented for
   OpenWrt targets.
