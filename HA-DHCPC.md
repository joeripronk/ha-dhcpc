# HA-DHCPC — High-Availability DHCP Client

Plan for `ha-dhcpc`: a DHCP client cluster in which one **master** node owns the
DHCP protocol conversation and lease timers, **syncs lease state** to one or more
**slave** nodes, and every member **applies the same IP configuration**. When DHCP
fails (server unreachable, lease expiry), the cluster **retains the last known good
configuration** instead of tearing the address down.

By default, **keepalived's VRRP handles the failover**: the VRRP master is the
ha-dhcpc master, and its notify script promotes the node via `ha-dhcpc ctl promote`
(backup/fault → `demote`). No built-in election is needed for now — selection is
keepalived's priority; a manual cmdline override (`ha-dhcpc ctl promote <id>`)
remains. A `default_role: master` bootstrap election covers deployments without
a designated master: single-node nodes elect immediately; cluster nodes elect
(by priority, ties by id) once all members are alive and all slaves, or after
`cluster_timeout_ms`. The new master's duty is renew-only — it continues RENEW/REBIND on the
synced lease with the same identity. Every node carries the same **shared `ha-dhcpc.conf`**
with the designated master's MAC, which all members copy as their DHCP interface
MAC — so a promoted node is byte-for-byte the same DHCP client identity.

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
- Failover is handled by keepalived VRRP by default: VRRP master = ha-dhcpc master
  (notify scripts promote/demote). The promoted master's duty is renew-only on the
  synced lease. Manual override via `ha-dhcpc ctl promote <id>`. Built-in election
  is deferred (v2); dual-master partitions alarm in v1.
- Idempotent, event-driven config application (no flapping, no service restarts).

### Non-goals (v1)

- Multi-lease / multi-interface meshing (v1: one DHCP interface, one lease, N nodes).
- Data-path failover ownership (who answers ARP/traffic) belongs to
  keepalived/VRRP/routing; HA-DHCPC guarantees the *configuration*, not traffic
  ownership.
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
5. **Keepalived decides, ha-dhcpc obeys:** failover is handled by keepalived VRRP
   by default — its `priority` selects the new master and its notify scripts drive
   `ha-dhcpc ctl promote/demote`. No built-in election for now (v2 candidate),
   except the `default_role` bootstrap election (single-node immediate; cluster
   elects when all members are alive and all slaves, or after `cluster_timeout_ms`;
   by priority, ties by id). Manual override via `ctl promote <id>`. A promoted
   node's duty is renew-only
   (continue RENEW/REBIND on the synced lease); the full DHCP lifecycle belongs to
   the designated master on cold start or after total lease loss.
6. **Silent standby + built-in ARP/NS responder:** because every member carries
   the same address on the same network, only the master answers ARP/NS for it,
   through ha-dhcpc's **built-in responder**; slaves keep the config applied but
   advertise nothing (responder off). On promotion the responder flips on and
   immediately announces the MAC to the switch with a gratuitous ARP / unsolicited
   NA (refreshing switch CAM/fdb, as VRRP does), so traffic converges with the
   role change.

## 3. Architecture (per node)

```
keepalived VRRP (failover) --notify_master/backup--> ha-dhcpc ctl (unix socket)
   operator cmdline: ha-dhcpc ctl promote <id>  (manual override)
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
  versioning, notify-driven promote/demote, dead-master detection.
- **Control interface** — local unix socket + `ha-dhcpc ctl promote|demote|status|update`
  for keepalived notify scripts and operators. Idempotent, logged, auditable; role
  changes propagate cluster-wide over the UDP control path, so every member always
  knows who the master is.
- **ARP/NS responder** — built-in; answers ARP/NS for the shared address, active
  only on the master; on promotion it also announces the MAC to the switch with a
  gratuitous ARP / unsolicited NA. IPv6 NS handling mirrors the ARP behavior.
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
- **Role assignment — keepalived VRRP (default):** VRRP handles failover; the
  VRRP master is the ha-dhcpc master. `notify_master` → `ha-dhcpc ctl promote`,
  `notify_backup`/`notify_fault` → `ha-dhcpc ctl demote`. Selection is by
  keepalived `priority` (single source of truth; `ha-dhcpc-local.conf` mirrors it for
  reference). No built-in election in v1 (except the `default_role` bootstrap
  election above); manual override via
  `ha-dhcpc ctl promote <id>`. Dead-master detection and quorum alarm in v1;
  dual-master is settled by a demote issued anywhere and propagated cluster-wide
  over the UDP control path.
- **The new master's duty is renew-only:** it already has the master MAC and the
  applied config; it resumes at RENEW/REBIND timers against the pinned server-id on
  the synced lease — no DISCOVER, no config churn — and its built-in responder flips
  on, announcing the MAC to the switch with a gratuitous ARP/unsolicited NA.
- **Safety rules:** only the master sends DHCP packets; only the master may
  DECLINE/RELEASE; slaves never expire the lease; a node in the minority partition
  keeps its config (retention) and does not self-promote; roles change only when
  the VRRP role changes (notify scripts) or an operator runs `ctl promote/demote`;
  every role change propagates cluster-wide over the UDP control path so all
  members agree on the master (a demote issued anywhere settles a dual-master).

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
  or after total lease loss.
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
  election_deadline_ms: 6000  # dead-master detection (alarm-only in v1)
  quorum: majority             # alarm-only in v1 (dual-master guard)
  cluster_timeout_ms: 0        # default-role bootstrap deadline (0=off)
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
  dns_hook: /usr/lib/ha-dhcpc/hooks/resolvconf   # optional
  ddclient: /usr/bin/ddclient   # optional; run as a one-shot (ddclient -daemon=0
                                # -syslog) when the applied address changes, on the
                                # master only (the node that owns the public IP)
  suppress_member_dad: true
  arp_responder: true        # built-in ARP/NS for the shared address (master only)
  announce_gratuitous: true  # gARP/unsolicited NA to the switch on promotion
ctl_socket: /run/ha-dhcpc.ctl
lease_file: dhclient.leases  # optional; relative names resolve against this
                             # file's directory (/etc/ha-dhcpc/); none/off opts
                             # out entirely (the engine then starts with no
                             # stored lease: boot enters INIT-SELECT and a
                             # promoted node re-acquires); unset keeps
                             # /var/lib/ha-dhcpc/dhclient.leases.<interface>
```

`/etc/ha-dhcpc/ha-dhcpc-local.conf` — the **per-node overlay** (the old
`slave.conf` role): this node's identity and priority (mirrors its keepalived
VRRP priority — keepalived is the failover authority), plus any shared key this
node must run differently. It is never overwritten by a sync.

```yaml
self: node-b
priority: 90   # mirrors keepalived priority; informational for ha-dhcpc in v1
interface: eth1        # per-node overrides: interface, default_role, ...
default_role: slave
```

**What a reload applies live:** the heartbeat timer, the cluster transport bind
(port or this node's sync address), the ctl socket, the DHCP send knobs
(retention, rate limit, renew retry), members, priority, `default_role` and the
election timers, and an executor re-apply — an interface change moves the address
on the new interface and the engine re-enters there (master-only). **What needs a
restart:** requested DHCP options and the hook script (read at engine start). A
file that no longer parses is refused and the config in use is kept, so a bad edit
never takes a live node down.

The node's state file (cluster view + full lease information, JSON, fsynced)
defaults to **`state.json` next to the shared config** — `/etc/ha-dhcpc/state.json`
in a normal install; `--persist PATH` overrides it.

Keepalived notify hook (per node):

```
notify_master "/usr/lib/ha-dhcpc/notify.sh master"
notify_backup "/usr/lib/ha-dhcpc/notify.sh backup"
notify_fault  "/usr/lib/ha-dhcpc/notify.sh fault"
```

`notify.sh` maps master → `ha-dhcpc ctl promote` (this node won VRRP), backup/fault
→ `ha-dhcpc ctl demote`; idempotent, logged, non-blocking.
Manual path: `ha-dhcpc ctl promote <node-id>`.

## 7. Technology choices

- **Language:** C — the daemon is built on the vendored FreeBSD dhclient fork for
  the DHCP core (target OS is Linux, so the fork must build cleanly there; it
  derives from ISC DHCP 4.x which historically supported Linux), new C modules for
  cluster/sync/ctl. Config application via libnl/netlink. Minimal deps.
- **Deployment:** systemd unit on all members (role is runtime state, not config);
  keepalived (2.x) as the external failover authority via notify scripts.
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
  value. Sanity check: a `saved_at_utc` ahead of the clock, or downtime beyond
  `min(2 × t3, 24 h)`, is not trusted and the stored remainders are kept as
  they are.
- Master restart: rejoin via persistence + full-state exchange; if keepalived
  still considers it master, it resumes the role after cooldown; otherwise it
  obeys the current master. A restart **reuses the persisted state**: the daemon
  hands the engine the lease (address, server-id, timers as remaining time), the
  core enables the IP and enters BOUND quietly, and only acts when a timer is due
  (the renewal goes unicast to the pinned server-id) — no DISCOVER just because
  the process started, and a node with `lease_file: none` needs no lease DB for
  this.
- Duplicate transaction safety: server-id pinned per lease (RFC 2131) — only the
  master touches it; a promoted master continues using it with the copied MAC.
- Sync/heartbeat uses the distinct per-node secondary addresses on the shared
  link, never the shared identity address; only the master's built-in responder
  answers ARP/NS for the shared address (and fires gARP/unsolicited NA on
  promotion) — slaves are silent standbys with the config pre-applied.
- Carrier/interface loss, DHCP server reboots (NAK → reselect, master-only),
  BOOTP vs DHCP options sanity, clock skew between members (informational only).
- Config executor must never fight other managers (networkd/NetworkManager must be
  disabled for the interface — documented prerequisite).
- Notify scripts can be invoked repeatedly/spuriously (fault→master flapping);
  `ctl promote/demote` must be idempotent and cooldown-guarded.

## 9. Test plan

- **Unit:** wire codec (dhclient codec), state machine transitions (incl. RETAINED
  paths), versioned sync, persistence round-trip, ctl idempotency.
- **Integration (netns + one shared bridge, dnsmasq as server, 3 nodes,
  keepalived; per-node secondary addresses for sync):**
  1. Master acquires lease, slaves apply identical config (apply-acks), all
     members show the master MAC on the DHCP interface; only the master answers
     ARP/NS for the shared address (slaves silent).
  2. keepalived failover (master killed) → VRRP promotes the highest-priority
     slave, its notify script runs `ctl promote` → it continues RENEW at the
     server with the same MAC, its responder sends gratuitous ARP/NA announcing the
     MAC to the switch (assert via tcpdump), no IP flap on survivors (assert via
     `ip addr` event stream), no DISCOVER storm (assert via tcpdump).
  3. Server down through T3 → all nodes in RETAINED, traffic config intact.
  4. Server returns → back to BOUND, lease updated cluster-wide.
  5. Partition: dual-master detection alarms (VRRP may dual-master across a
     partition); a `ctl demote` on one side propagates cluster-wide over the UDP
     control path and all members agree on the master afterwards; exactly one node
     sends DHCP packets (assert via tcpdump).
  6. Slave join/restart mid-lease; full-state transfer correctness.
  7. Manual cmdline override: `ctl promote <id>` from an operator shell moves the
     role cleanly; the old master demotes (via notify or ctl).
  8. Dead-master/quorum detection: alarms, no self-promotion (dual-brain guard);
     demotes propagate to all members.
- **Fuzz/robustness:** malformed/misordered DHCP and sync packets.

## 10. Milestones

- **M0** — Decisions frozen (§2, §11); freeze interfaces and start M1.
- **M1** — Single-node DHCP client (FreeBSD dhclient fork) with persistence,
  retention mode, idempotent executor (standalone value, no cluster yet).
- **M2** — Heartbeat + versioned lease sync + slave pre-apply + apply-acks;
  ctl socket + `promote`/`demote`.
- **M3** — keepalived VRRP integration (notify → promote/demote) + manual ctl
  override + dual-master alarm; integration tests 1, 2, 5, 6, 7, 8. Built-in
  election deferred to v2.
- **M4** — Retention policy completion (backoff re-discover, hooks), observability
  (`status`, JSON socket), alerts.
- **M5** — Hardening: fuzz, docs, systemd packaging, demo topology.

## 11. Resolved decisions

1. keepalived: one VRRP instance shared with the data path (VIP); its notify
   scripts drive ha-dhcpc roles.
2. Dual-master/partition: resolved by demotion propagated over the UDP control
   path — a local demote signals all members who the master is.
3. Failover convergence target: ≤ 10 s end-to-end.
4. Downstream services consume the JSON status socket; no extra lease feed in v1.
5. Target OS: Linux — netlink executor, systemd, libnl; the FreeBSD dhclient fork
   must build cleanly on Linux.
