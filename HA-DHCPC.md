# HA-DHCPC — High-Availability DHCP Client

Plan for `ha-dhcpc`: a DHCP client cluster in which one **master** node owns the
DHCP protocol conversation and lease timers, **syncs lease state** to one or more
**slave** nodes, and every member **applies the same IP configuration**. When DHCP
fails (server unreachable, lease expiry), the cluster **retains the last known good
configuration** instead of tearing the address down.

Failover is **built in** (no keepalived needed): the designated master owns the
configured **cluster addresses (VIPs)**, the DHCP conversation and the lease
timers; when its heartbeats stop, the highest-priority live member with quorum
promotes itself, claims the VIPs and sends gratuitous ARP. A manual cmdline
override (`ha-dhcpc ctl promote <id>`) remains. A `default_role: master`
bootstrap election covers deployments without a designated master: single-node
nodes elect immediately; cluster nodes elect (by priority, ties by id) once all
members are alive and all slaves, or after `cluster_timeout_ms`. The new master's
duty is renew-only — it continues RENEW/REBIND on the synced lease with the same
identity. Every node carries the same **shared `ha-dhcpc.conf`** with the
designated master's MAC, which all members copy as their DHCP interface MAC — so
a promoted node is byte-for-byte the same DHCP client identity.

## 1. Goals

- Exactly one node (the master) speaks DHCP (RFC 2131/2136) on the network; the
  DHCP server sees a single client identity: the designated master's MAC, present
  on every member (copied from the shared `ha-dhcpc.conf`).
- All members run `ha-dhcpc` and apply the identical L3 configuration (address,
  netmask, gateway, routes, DNS — as a declarative desired state), so a failover
  needs no DHCP round-trip and no config re-add; convergence is
  heartbeat/notify-interval only.
- Lease renewal (T1 RENEW, T2 REBIND, T3 handling) is master-only; slaves are
  passive to DHCP.
- On DHCP failure, keep the current configuration (retention mode); never
  spontaneously release the address or pull the IP while the cluster is healthy.
- Failover is automatic: a dead master is replaced by the highest-priority live
  member once quorum is satisfied. The promoted master claims the cluster
  addresses, sends gratuitous ARP and continues renew-only on the synced lease.
  Manual override via `ha-dhcpc ctl promote <id>`; `ctl demote` hands over or
  withdraws the VIPs.
- Idempotent, event-driven config application (no flapping, no service restarts).

### Non-goals (v1)

- Multi-lease / multi-interface meshing (v1: one DHCP interface, one lease, N nodes).
- IPv6 cluster addresses (IPv4 only for now; the gARP path is IPv4. ARP/NS
  answering still follows address ownership).
- DHCPv6.
- Being a drop-in replacement for dhclient on non-clustered hosts (single-node
  mode is supported, but the cluster feature is the point).

## 2. Design decisions (confirmed direction)

1. **Shared identity via copied MAC:** every member uses the designated master's
   MAC on the DHCP interface, taken from the shared `ha-dhcpc.conf`. Promotion is
   seamless: correct MAC + applied config already in place. Duplicate-address
   detection between cluster members is suppressed (friends, not conflicts); DAD
   against the rest of the network stays enabled on the master.
2. **All members on the same network segment:** every slave sits on the same L2
   segment as the master and the DHCP server — otherwise failover cannot work (the
   promoted node must renew the same lease on the same link). Sync/heartbeat run
   on that shared link using **distinct per-node secondary addresses**
   (`sync_address` in `ha-dhcpc.conf`), since the shared primary address is
   identical cluster-wide and cannot route member-to-member traffic.
3. **Slaves are passive to DHCP:** they never send DISCOVER/REQUEST/RENEW and never
   time out the lease on their own. They only obey the master's state.
4. **Retention beats expiry:** a lease that cannot be renewed is *kept* (degraded),
   not dropped — dropping the IP is the failure mode we are designing away.
5. **Built-in election, keepalived-compatible behaviour:** each member's
   `priority` selects the new master on a dead-master timeout, gated by
   `quorum: majority|none` (use `none` for a two-node cluster). A manual
   `ctl promote/demote` still overrides. The `default_role` bootstrap election is
   for deployments with no designated master (single-node immediate; cluster
   elects when all members are alive and all slaves, or after
   `cluster_timeout_ms`; by priority, ties by id). A promoted node's duty is
   renew-only (continue RENEW/REBIND on the synced lease); the full DHCP lifecycle
   belongs to the designated master on cold start or after total lease loss.
6. **Master owns the VIP, slaves stay silent:** the master adds the configured
   `cluster.addresses` (per interface), so the kernel answers ARP/NS for them and
   only the master is reachable. Slaves remove them; they keep the advertised
   (primary) config applied but answer nothing. On promotion the node adds the
   VIPs and immediately announces them with a gratuitous ARP (refreshing switch
   CAM/fdb, as VRRP does), so traffic converges with the role change.

## 3. Architecture (per node)

```
automatic failover (heartbeat + quorum + priority)
   operator cmdline: ha-dhcpc ctl promote/demote <id>  (manual override)
                                                   |
+--------------------------------------------------v-------------------------+
|                                ha-dhcpc                                   |
|                                                                          |
|  +------------+   +-----------+   +-------------------+                  |
|  | DHCP engine|<->| Cluster   |<->| Config executor   |                  |
|  | (master-   |   | state     |   | (idempotent       |                  |
|  |  only)     |   | machine   |   |  + hooks)         |                  |
|  +------------+   +-----------+   +-------------------+                  |
|        |               |                  |                              |
|        |        +-----------+             |                              |
|        +------->| Persistence|            |                              |
|                  +-----------+             v     kernel (nl/routes)      |
|        sync/heartbeat transport        kernel                            |
|        (UDP, trusted LAN) on shared link                                 |
+--------------------------------------------------------------------------+

config inputs: ha-dhcpc.conf (shared: members + MAC, timers, retention, hooks;
               cluster-synced) + ha-dhcpc-local.conf (self, priority, overrides)
```

Components:

- **DHCP engine** — based on the **FreeBSD fork of dhclient** (ISC DHCP 4.x
  derivative, maintained in the FreeBSD base system, MPL-2.0 ISC-derived parts +
  BSD FreeBSD parts): reuse its wire codec, RFC 2131 state machine/timeouts
  (INIT-SELECT, REQUEST, RENEW/T1, REBIND/T2, INIT-REBOOT on restart, optional
  RELEASE/DECLINE), socket layer and lease-file handling. Runs only on the master,
  sending from the interface with the designated master's MAC from the shared config.
  Vendor the fork and track FreeBSD patches.
- **Cluster state machine** — role state (master/slave), heartbeats, lease-state
  versioning, dead-master detection, quorum + priority election, dual-master
  resolution.
- **Control interface** — local unix socket + `ha-dhcpc ctl promote|demote|status|update|renew`
  for operators (and optional external supervisors). Idempotent, logged,
  auditable; role changes propagate cluster-wide over the UDP control path, so
  every member always knows who the master is.
- **Cluster addresses (VIPs)** — configured per interface; only the master adds
  them, so the kernel answers ARP/NS for them. On promotion the master announces
  them with a gratuitous ARP (refreshing switch CAM/fdb, as VRRP does), so traffic
  converges with the role change. IPv4 only for now.
- **Config executor** — declarative desired state from the current lease state;
  idempotent netlink reconcile (addr/route add only on delta; Linux target);
  **dhclient-script compatible dispatch** (calls existing `dhclient-script`-style
  hooks with the standard reasons BOUND/RENEW/REBIND so site scripts keep working).
- **Persistence** — a cluster view **including the full lease information** (role,
  last lease-state version, interface, shared-config digest, lease address/mask/
  gateway/server-id/DNS/timer remainders) written to disk (JSON, fsynced) so a
  reboot resumes with its last state and a restarting node rejoins from it. The
  state file lives **next to the config** (`/etc/ha-dhcpc/state.json` by default);
  the dhclient-format lease DB is optional per node (`lease_file:` in the shared
  config, `none` to opt out) and is what a node uses to resume via INIT-REBOOT.
- **Transport** — UDP heartbeats/sync on a dedicated port over the **shared
  network segment** (all members on the same link as the DHCP server). The shared
  primary address is identical cluster-wide, so each member syncs via its **distinct
  per-node secondary address** (`sync_address` in `ha-dhcpc.conf`). v1 runs
  unauthenticated/unencrypted on a trusted LAN; HMAC and mTLS are deferred to v2.

## 4. Cluster protocol & roles

- **Heartbeat** (default every 2 s, bidirectional): cluster id, master id, node id
  (from the local overlay), lease-state version (monotonic), lease summary (state,
  address, mask, gateway, server-id, t1/t2/t3 remaining, retention flag, config
  hash). Node identity for sync is the configured id — never the (shared) MAC.
- **State push:** master pushes on every lease change (new ACK, renew, rebind,
  server change, retention entry/exit). Slaves confirm with an **apply-ack**
  (applied version + config hash) so cluster status is observable.
- **Full-state transfer:** on slave join, on version gap > 1, or on master change —
  full lease state, slave applies before acking.
- **Role assignment — automatic:** a heartbeat older than
  `election_deadline_ms` marks the designated master dead. If quorum is satisfied
  (`majority` default; `none` allows a lone survivor), the highest-priority live
  member (ties by node id) promotes itself. `default_role` still governs the
  no-master bootstrap, and `ctl promote/demote` overrides everything. Dual-master
  is settled by comparing `(priority, id)` on heartbeats and propagating the
  winner; a demote issued anywhere also settles it cluster-wide.
- **The new master's duty is renew-only:** it already has the master MAC and the
  applied config; it resumes at RENEW/REBIND timers against the pinned server-id on
  the synced lease — no DISCOVER, no config churn — adds the cluster addresses and
  announces them with a gratuitous ARP.
- **Safety rules:** only the master sends DHCP packets; only the master may
  DECLINE/RELEASE; slaves never expire the lease; a node in the minority partition
  keeps its config (retention) and does not self-promote (`quorum: majority`);
  roles change automatically, by `ctl promote/demote`, or by the bootstrap
  election, and every role change propagates cluster-wide over the UDP control
  path so all members agree on the master.

## 5. Lease & retention state machine (master)

```
INIT-SELECT --ACK--> BOUND --T1--> RENEW --ACK--> BOUND
     ^                 |            | (fail)      
     |                 |            v             
     |                 |         REBIND --ACK--> BOUND
     |                 |            | (T3/expire)        
     +--(no lease ever)--            v                    
                                     RETAINED  (keep last-known-good)
```

- A promoted master resumes directly at RENEW (renew-only duty) on the synced
  lease; INIT-SELECT/DISCOVER applies only to the designated master on cold start
  or after total lease loss. The remaining timers are aged from the last observed
  lease timestamp before the DHCP core arms them.
- **Restart always starts in retention**: a node that resumes on a persisted (or
  synced) lease applies its config and enters RETAINED first — nothing is sent —
  and only acts when a timer is due (the renewal goes unicast to the pinned
  server-id). It exits RETAINED on the first successful ACK. A node down through
  its renewal window therefore acts at boot (see clock jumps in §8).
- **RETAINED**: config stays applied, retention flag propagates to slaves;
  master keeps attempting RENEW → REBIND → (configurable) fresh DISCOVER with
  exponential backoff (e.g., 30 s → cap 10 min); logs/alerts at entry and exit.
  No DECLINE, no RELEASE, no config teardown. On first successful ACK the state
  machine returns to BOUND and pushes the updated state.
- Retention policy (per config): `forever` (default) | `max-duration` |
  `until-carrier-loss` | `off` (dhclient-like expiry behavior).
- Carrier/interface loss is the one event that *does* drop config (the link is
  gone); it re-enters INIT-SELECT when carrier returns.

## 6. Configuration files

Two files per node, one schema. The local overlay wins on any key it repeats.

`/etc/ha-dhcpc/ha-dhcpc.conf` — the **cluster-shared** config: identical on every
member, and the master is authoritative for it.

- When a member joins (first traffic from it), the master pushes its copy.
- `ha-dhcpc ctl update` (master-only) re-reads the file from disk, applies it
  here and publishes it to every member. On a slave it is refused.
- `ha-dhcpc ctl renew` (master-only) forces a RENEW DHCPREQUEST on the configured
  DHCP interface using the active lease and pinned server-id. On a slave it is
  refused.
- A receiver verifies the sha256 the master claims, writes the pushed copy to its
  own copy of this path (atomic, digest-verified) so the cluster converges across
  restarts, then reloads and acks. A member whose digest differs from the master's
  heartbeat digest asks for it (`conf_req`); digests are of the shared file's
  bytes, so a pushed copy keeps its comments and formatting.

```yaml
designated_master: node-a
master_mac: "aa:bb:cc:dd:ee:ff"
members:
  - { id: node-a, sync_address: 10.10.0.1 }   # distinct secondary addrs, same link
  - { id: node-b, sync_address: 10.10.0.2 }
  - { id: node-c, sync_address: 10.10.0.3 }
interface: eth0              # DHCP/data interface (MAC comes from master_mac)
cluster:
  port: 4227
  heartbeat_ms: 2000
  election_deadline_ms: 6000  # dead-master timeout before failover
  quorum: majority             # majority | none (two-node clusters need none)
  cluster_timeout_ms: 0        # default-role bootstrap deadline (0=off)
  addresses:                   # VIPs owned by the master, keyed by interface
    br-lan: [192.168.10.1/24]  # CIDR or dotted netmask (192.168.10.1/255.255.255.0)
    br-guest: [192.168.20.1/24]
default_role: slave            # master = bootstrap election when no master is known
dhcp:
  retention: forever          # forever | max_duration | until_carrier_loss | off
  rediscover_in_retention: true
  rate_limit_ms: 10000       # min ms between DHCP packets we send (0=off);
                             # required for Odido NL fiber (>= 10 s spacing)
  renew_retry_interval_s: 30 # retry interval after a failed RENEW/REBIND
                             # (0 = exponential backoff)
  request_options: [1, 3, 6, 15, 26, 28, 42, 121]
apply:
  routes: true
  backup_gateway: ""          # optional; slave-only backup default route (e.g.
                              # 192.168.10.1 on the OpenWrt routers). Installed
                              # with a higher metric while the node is a slave
                              # and removed again on promotion; usually set per
                              # node in ha-dhcpc-local.conf.
  dns_hook: /usr/lib/ha-dhcpc/hooks/resolvconf   # optional
  ddclient: /usr/bin/ddclient   # optional; run as a one-shot (ddclient -daemon=0
                                # -syslog) when the applied address changes, on the
                                # master only (the node that owns the public IP)
  suppress_member_dad: true  # compatibility no-op (only the master owns the VIP)
  arp_responder: true        # compatibility no-op (the kernel answers on the owner)
  announce_gratuitous: true  # gratuitous ARP to the switch on promotion
  slave_link_down: false     # administratively bring the DHCP link down on slaves
ctl_socket: /run/ha-dhcpc.ctl
lease_file: dhclient.leases  # optional; relative names resolve against this
                             # file's directory (/etc/ha-dhcpc/); none/off opts
                             # out entirely (the engine then starts with no
                             # stored lease: boot enters INIT-SELECT and a
                             # promoted node re-acquires); unset keeps
                             # /var/lib/ha-dhcpc/dhclient.leases.<interface>
```

`/etc/ha-dhcpc/ha-dhcpc-local.conf` — the **per-node overlay** (the old
`slave.conf` role): this node's identity and failover priority, plus any shared
key this node must run differently. It is never overwritten by a sync.

```yaml
self: node-b
priority: 90   # failover priority; highest live member wins
interface: eth1        # per-node overrides: interface, default_role, ...
default_role: slave
apply:
  backup_gateway: 192.168.10.1  # slave-only backup default route (OpenWrt
                                # routers); dropped when this node is promoted
```

**What a reload applies live:** the heartbeat timer, the cluster transport bind
(port or this node's sync address), the ctl socket, the DHCP send knobs
(retention, rate limit, renew retry), members, priority, `default_role`, the
election timers/quorum, the cluster addresses, and an executor re-apply — an
interface change moves the address on the new interface and the engine re-enters
there (master-only). **What needs a
restart:** requested DHCP options and the hook script (read at engine start). A
file that no longer parses is refused and the config in use is kept, so a bad edit
never takes a live node down.

The node's state file (cluster view + full lease information, JSON, fsynced)
defaults to **`state.json` next to the shared config** — `/etc/ha-dhcpc/state.json`
in a normal install; `--persist PATH` overrides it.

No keepalived integration is required. If an external supervisor already drives
roles, `notify.sh` still maps master → `ha-dhcpc ctl promote` and backup/fault →
`ha-dhcpc ctl demote`; it is idempotent, logged and non-blocking. Manual path:
`ha-dhcpc ctl promote <node-id>` / `ha-dhcpc ctl demote`.

## 7. Technology choices

- **Language:** C — the daemon is built on the vendored FreeBSD dhclient fork for
  the DHCP core (target OS is Linux, so the fork must build cleanly there; it
  derives from ISC DHCP 4.x which historically supported Linux), new C modules for
  cluster/sync/ctl. Config application via libnl/netlink. Minimal deps.
- **Deployment:** systemd unit on all members (role is runtime state, not
  config); failover and the VIP are built in, so keepalived is optional.
- **Observability:** `ha-dhcpc status` + JSON over the local control socket
  (role, versions, apply-acks, retention state, timers); structured logs.
- **Compat mode:** single-node operation = cluster of one (no election needed),
  retention still applies — useful as a standalone hardened dhclient.

## 8. Edge cases to handle explicitly

- Slaves must not apply state older than their last acked version (versioned
  full-state transfer closes the gap atomically).
- Clock jumps / monotonic timers: all lease timers are monotonic, persisted as
  remaining time, not wall-clock deadlines. The persisted remainders are the
  values at save time; on restart they are recalculated from UTC
  (`saved_at_utc` in state.json minus the downtime, clamped at zero), so a node
  down through its renewal window acts at boot instead of waiting the stale
  value. Adopted peer state and promotions age the same remainders from the last
  observed lease time before arming timers. Sanity check: a `saved_at_utc` ahead
  of the clock, or downtime beyond `min(2 × t3, 24 h)`, is not trusted and the
  stored remainders are kept as they are.
- Master restart: rejoin via persistence + full-state exchange; the persisted
  `master_id` restores the agreed master, so a restarting master either resumes
  its role or follows the current master. A restart **reuses the persisted state**: the daemon
  hands the engine the lease (address, server-id, timers as remaining time), the
  core enables the IP and enters BOUND quietly, and only acts when a timer is due
  (the renewal goes unicast to the pinned server-id) — no DISCOVER just because
  the process started, and a node with `lease_file: none` needs no lease DB for
  this.
- Duplicate transaction safety: server-id pinned per lease (RFC 2131) — only the
  master touches it; a promoted master continues using it with the copied MAC.
- Sync/heartbeat uses the distinct per-node secondary addresses on the shared
  link, never the shared identity address; only the master owns the cluster
  addresses, so the kernel answers ARP/NS for them (and the master fires gARP on
  promotion) — slaves are silent standbys with the advertised config pre-applied.
- Carrier/interface loss, DHCP server reboots (NAK → reselect, master-only),
  BOOTP vs DHCP options sanity, clock skew between members (informational only).
- Config executor must never fight other managers (networkd/NetworkManager must be
  disabled for the interface — documented prerequisite).
- Drift self-heal: the executor's applied-state memo is a fast path, not the
  truth — when the hash matches, verification against live kernel state decides
  whether the apply is really a no-op, so resources removed externally (netifd
  reloads, `ip addr flush`) are re-added. The rtnetlink monitor (link, neigh and
  IPv4 addr/route groups) queues a verify that the heartbeat tick acts on after
  a short debounce (so flush bursts settle first); a periodic audit (30 s)
  catches missed events; the status JSON reports the applied hash, last
  verification, reconciliation count and monitor state.
- Role changes can race (flapping, split brain); `ctl promote/demote` and the
  automatic election are idempotent, prio/id-tiebroken and cooldown-guarded.

## 9. Test plan

- **Unit:** wire codec (dhclient codec), state machine transitions (incl. RETAINED
  paths), versioned sync, persistence round-trip, ctl idempotency.
- **Integration (netns + one shared bridge, dnsmasq as server, 3 nodes;
  per-node secondary addresses for sync):**
  1. Master acquires lease, slaves apply identical config (apply-acks), all
     members show the master MAC on the DHCP interface; only the master answers
     ARP/NS for the shared address (slaves silent).
  2. kill the master → after `election_deadline_ms` the highest-priority live
     slave promotes itself, adds the VIP, sends gratuitous ARP, and continues
     RENEW at the server with the same MAC (assert via tcpdump); no IP flap on
     survivors (assert via `ip addr` event stream), no DISCOVER storm.
  3. Server down through T3 → all nodes in RETAINED, traffic config intact.
  4. Server returns → back to BOUND, lease updated cluster-wide.
  5. Partition: with `quorum: majority` the minority does not self-promote; in a
     two-node `quorum: none` split the prio/id tiebreak settles the dual master,
     and a `ctl demote` on one side propagates cluster-wide; exactly one node
     sends DHCP packets (assert via tcpdump).
  6. Slave join/restart mid-lease; full-state transfer correctness.
  7. Manual cmdline override: `ctl promote <id>` from an operator shell moves the
     role cleanly; the old master demotes.
  8. Dead-master/quorum detection: no self-promotion without quorum (dual-brain
     guard); demotes propagate to all members.
- **Fuzz/robustness:** malformed/misordered DHCP and sync packets.

## 10. Milestones

- **M0** — Decisions frozen (§2, §11); freeze interfaces and start M1.
- **M1** — Single-node DHCP client (FreeBSD dhclient fork) with persistence,
  retention mode, idempotent executor (standalone value, no cluster yet).
- **M2** — Heartbeat + versioned lease sync + slave pre-apply + apply-acks;
  ctl socket + `promote`/`demote`.
- **M3** — built-in failover (quorum + priority), cluster addresses (VIP) +
  gratuitous ARP, manual ctl override, dual-master resolution; integration tests
  1, 2, 5, 6, 7, 8.
- **M4** — Retention policy completion (backoff re-discover, hooks), observability
  (`status`, JSON socket), alerts.
- **M5** — Hardening: fuzz, docs, systemd packaging, demo topology.

## 11. Resolved decisions

1. Built-in failover and VIP ownership replace keepalived; keepalived is
   optional for deployments that already run it.
2. Dual-master/partition: resolved by demotion propagated over the UDP control
   path — a local demote signals all members who the master is.
3. Failover convergence target: ≤ 10 s end-to-end.
4. Downstream services consume the JSON status socket; no extra lease feed in v1.
5. Target OS: Linux — netlink executor, systemd, libnl; the FreeBSD dhclient fork
   must build cleanly on Linux.
