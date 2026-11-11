# HA-DHCPC Inter-Cluster Routing (Plan)

Plan for simple routing between local `ha-dhcpc` clusters so the current holder of a
cluster's public DHCP address is reachable over the shortest path. The mechanism is
a small, well-defined subset of **OSPFv2 spoken directly by `ha-dhcpc`**. `ha-dhcpc`
does **not** rely on an external OSPF daemon, but it **can talk directly** to
external OSPF routers/daemons on the fabric (standard OSPF adjacency/LSA exchange).

This is **edge-only routing**: an `ha-dhcpc` node originates only its own
locally owned prefixes and is not a transit/full OSPF router. It must never
advertise, redistribute, re-originate, or forward non-local routes learned via OSPF.

Status: **proposal / design plan** (not implemented).

## 1. Problem and motivation

Today each `ha-dhcpc` cluster manages one public DHCP lease and its local
VIP/subnets. When multiple clusters are connected by local L3 links (a site fabric,
a set of routers, or interconnected LAN segments), there is no automatic way for
one cluster/site to reach the active master of another cluster:

- The public IPv4 address obtained via DHCP is owned by whichever node is currently
  master of that cluster and may move on failover or renewal-to-a-new-address.
- Local VIP subnets (`cluster.addresses`) are also master-owned and move with the
  role.
- Static routes between clusters cannot follow failover, and manually maintaining
  host routes does not scale.

The desired outcome is that traffic for a cluster's public address (and optionally
for its local VIP subnet) is forwarded along the shortest available path to the
node that currently owns it, and converges automatically when roles or leases
change.

## 2. Goals

- **Advertise the public DHCP IPv4 address as a /32 host route** from the cluster
  that currently owns it, so other participating routers/clusters on the fabric can
  install a shortest-path route to the current master.
- **Optionally advertise local VIP subnets** (`cluster.addresses` prefixes, or a
  configured subset) for reachability of cluster-local services.
- **Follow ha-dhcpc state:** advertise only while this node is the authoritative
  owner of the prefix; withdraw promptly on demotion, loss of ownership, or
  configured unhealthy states.
- **Edge-only, local-only origination:** participate on the fabric only to announce
  locally owned prefixes. Never act as a transit router and never advertise,
  redistribute, re-originate, or forward non-local routes learned via OSPF.
- **Shortest-path reachability to the origin** on the local inter-cluster fabric
  using dynamic OSPFv2 routing, interoperable with external OSPF speakers.
- **No external OSPF daemon dependency:** `ha-dhcpc` implements the required OSPF
  subset itself while remaining able to peer directly with external OSPF routers.
- **Minimal, explicit configuration:** reuse existing cluster/lease concepts where
  possible; avoid coupling core DHCP/HA behavior to routing internals.
- **Safe failure behavior:** never create a persistent blackhole or a routing loop
  due to stale advertisements; prefer withdraw-on-uncertainty.

## 3. Non-goals (initial scope)

- Full OSPF feature parity (multiple areas, NSSA/virtual links, traffic
  engineering, BFD integration in v1 unless trivial).
- Acting as a transit/full OSPF router or carrying transit traffic for non-local
  destinations; propagating, redistributing, or re-advertising any non-local routes
  learned via OSPF.
- IPv6 / OSPFv3 (IPv4 only, matching current cluster/VIP scope).
- Replacing the existing default-route, backup-gateway, or gateway-probe logic
  managed by the executor for the DHCP uplink.
- Automatic discovery of arbitrary network topologies beyond the explicitly
  configured fabric interfaces/peers as required by the minimal profile.

## 4. Terminology and assumptions

- **Local cluster:** an existing `ha-dhcpc` member set sharing one DHCP lease and
  role election (`ha-dhcpc.conf` / cluster protocol).
- **Routing domain / fabric:** the set of local clusters and transit routers that
  participate in inter-cluster routing and exchange reachability for the
  advertised prefixes.
- **Public /32:** the current leased IPv4 address (`lease.address/32`) of a
  cluster, owned and advertised only by that cluster's master while valid.
- **VIP subnet (optional):** a prefix derived from `cluster.addresses` on a
  master-owned interface (e.g. `192.168.10.0/24`), advertised only when owned.
- **Assumptions:**
  - Nodes that advertise/forward between clusters have L3 connectivity on the
    fabric links.
  - The fabric links are administratively controlled and can be placed in a single
    OSPF area (Area 0) with a simple topology.
  - The public /32 is meaningful/reachable inside this routing domain (e.g.
    clusters share an upstream or a common NAT/routed environment); the plan does
    not assume global Internet routing of the /32.

## 5. Design options

### Option A — Native minimal OSPFv2 speaker in ha-dhcpc (recommended)

`ha-dhcpc` determines *what* must be advertised from authoritative local state
(role, lease, VIP ownership) and **speaks OSPFv2 directly** to originate and
withdraw those prefixes. It participates in the minimal protocol machinery needed
for interoperable edge routing (Hello/adjacency, LSDB synchronization, LSA
origination/aging/flooding relevant to the supported subset, and shortest-path
calculation for learned routes of interest). No external OSPF daemon is required.

**Interoperability:** `ha-dhcpc` can form adjacencies and exchange routing
information directly with external OSPF routers/daemons (e.g. FRR, BIRD, other
OSPF speakers) on configured fabric interfaces, provided they use the same minimal
Area 0 profile and compatible authentication/timers.

**Pros:** no external routing dependency/packaging coupling; behavior derived
directly from ha-dhcpc state; direct interoperability with existing OSPF fabric.
**Cons:** protocol correctness and security burden in `ha-dhcpc` (state machine,
LSDB/sequence/aging/flooding, SPF, timers, parsing/validation).

### Option B — External OSPF daemon integration (not chosen)

Delegate OSPF speaking to FRR/BIRD via kernel redistribution or control hooks.

**Pros:** mature protocol implementation.
**Cons:** external dependency and per-platform integration; rejected because the
routing function should be owned by `ha-dhcpc` and not depend on an external OSPF
daemon. Direct peering with external daemons is still achieved by Option A.

### Option C — Non-OSPF fallback (contingency only)

A bespoke non-OSPF announcer is not preferred because it would not interoperate
with standard OSPF routers/daemons. Consider only if OSPFv2 interoperability is
explicitly dropped for a constrained deployment.

**Decision:** pursue **Option A** (native minimal OSPFv2 speaker), constrained to an
edge-only subset that interoperates directly with external OSPF speakers.

### 5.1 Minimal interoperable OSPF subset (“heartbeats and route exchange”)

OSPF cannot be reduced to a custom “heartbeat + announce route” message without
breaking correctness, but `ha-dhcpc` can implement a **minimal interoperable**
profile:

- **Hello packets are the heartbeat.** Neighbor liveness uses OSPF Hello and
  Dead-interval handling on configured fabric interfaces.
- **Correct route exchange:** implement the adjacency/LSDB exchange required for
  interoperability in the supported topology (Hello, Database Description,
  LSR/LSU/LSAck as applicable), originate/age/flood LSAs for locally owned prefixes,
  and run SPF/path selection to compute reachability for learned prefixes of
  interest. A bespoke non-OSPF shortcut is out of scope.
- **Minimal edge-only profile:** single Area 0, explicit fabric interfaces only,
  simple network types (point-to-point preferred; broadcast where required),
  originate only ha-dhcpc-owned `/32`/VIP prefixes and optional primary default
  route, and never originate/redistribute/re-flood learned non-local routes as own
  advertisements.
- **Edge-only, non-transit role:** this node is never a transit OSPF router and only
  originates prefixes it locally owns. It must not redistribute, re-originate, or
  propagate/forward non-local routes in the routing protocol. Implementation must
  avoid generating LSAs for learned routes, must not advertise transit capability
  for unrelated traffic, and must scope installed/used learned routes to the
  intended fabric prefixes where practical. Installing routes to reach other
  clusters’ ha-dhcpc-originated prefixes is in scope; providing transit for
  unrelated third-party destinations is not.

## 6. Proposed design (native speaker)

**Edge-only constraint (invariant):** this node is an originator of locally owned
prefixes only — never a transit/full OSPF router. It must not redistribute, re-
originate, or propagate non-local routes learned via OSPF. It must not be used as a
transit path for unrelated third-party destinations; reachability to other clusters’
originated prefixes remains in scope.

### 6.1 Ownership and advertisement state

A prefix is **advertisable** from this node only when all of the following hold:

- `ctx->role == HADC_ROLE_MASTER` for the cluster that owns the prefix.
- For the public /32: `lease` is present/valid (`HADC_LEASE_BOUND` or the project’s
  defined "retained-but-owned" state — see §6.4) and `lease.address` is non-zero.
- For a VIP subnet: the corresponding `cluster.addresses` entry is owned/applied on
  this master.
- A local routing health policy allows advertisement (see §6.4).

On any transition that ends ownership or validity, the node **withdraws** the
advertisement (flush/age-out the corresponding self-originated LSA(s) per OSPF
rules) before or atomically with relinquishing ownership where possible; must be
idempotent and conservative.

### 6.2 What is advertised and accepted

| Prefix/route | Source | Direction | Default | Notes |
|---|---|---|---|---|
| Public DHCP IPv4 `/32` | `lease.address` | publish (originate) | **enabled** (when routing feature on) | Primary goal; moves with failover/new lease. |
| VIP subnet(s) | `cluster.addresses` | publish (originate) | **optional** | Network prefix calculated from configured address/mask; only explicitly enabled. |
| Default route `0.0.0.0/0` | primary DHCP/uplink default path | publish and/or accept (configurable) | **disabled** | Optional edge default-route signaling. **Backup routes must never be published** (see below). |

- Prefixes/routes are originated only by the owning/eligible master; slaves never
  advertise.
- Each cluster must advertise a stable, non-overlapping set of prefixes within the
  routing domain (the public /32 is naturally unique per lease; VIP planning must
  avoid overlap across clusters).
- **Default route publish:** when enabled, only the node’s primary healthy default
  path may be announced as `0.0.0.0/0` (subject to ownership/health policy). Routes
  via `apply.backup_gateway`, `apply.master_backup_gateway`, gateway-probe failover
  backup paths, or other backup/fallback mechanisms must **never** be published.
  If the node is using a backup route, default-route advertisement must be withdrawn.
- **Default route accept:** when enabled, a `0.0.0.0/0` learned on the fabric is
  handled as a backup path (never as the primary local working default route):
  - A default route learned from a **local cluster member (originated only by that
    cluster’s master)** is treated as the node’s `apply.backup_gateway` candidate
    (local backup path), not installed as a primary default and never published.
  - If the **local cluster’s master is down/unavailable**, the node may use a default
    route from a **remote cluster’s master** as the backup/fallback path.
  - The local (working) default route always takes precedence over any fabric-learned
    default route. When disabled, learned default routes are ignored.
  Accepting/publishing a default route is explicitly opt-in and must remain
  compatible with the edge-only intent.

### 6.3 OSPF subset and topology

To keep complexity bounded, the supported subset is:

- **OSPFv2, single Area 0** only.
- **Explicit fabric interfaces:** OSPF runs only on configured `ospf.interfaces`;
  no implicit enablement on other interfaces. `ha-dhcpc` can peer directly with
  external OSPF routers/daemons on these interfaces.
- **Router ID:** configured explicitly when provided; otherwise defaults to this
  node’s cluster/sync IP (stable per-node identity from cluster configuration).
- **Network type:** implementation-selected for simplicity (point-to-point preferred
  on dedicated inter-cluster links; broadcast where required). No NBMA/virtual links
  in scope.
- **Local-only origination (no transit):** originate LSAs only for prefixes owned by
  this ha-dhcpc instance (public `/32`, optional selected VIP subnets, optional
  primary healthy default route). **No redistribution and no origination/re-flooding
  of any non-local route learned via OSPF.** The implementation must not become a
  transit path for unrelated third-party destinations.
- **Learned routes handling:** routes to other clusters’ ha-dhcpc-originated
  prefixes may be learned and installed as needed for reachability and shortest-path
  selection. `local_master` default-route attribution for backup selection is derived
  from cluster information (heartbeat/designated master), not from unverified
  non-cluster origin claims; remote defaults require explicit attribution/feed
  mapping as designed. Fabric-learned defaults are backup-path only and never
  published.
- **Authentication:** optional simple authentication when configured (none,
  plaintext/simple, or MD5 as supported), applied to configured fabric interfaces.
- **Cost/metric:** fixed/default in v1 for simplicity (no separate metric tuning in
  the minimal config), unless a minimal knob is added later.

### 6.4 Lease/health interaction (avoid blackholes)

Advertising a /32 or a default route while the master cannot actually forward traffic
to/from the upstream creates a blackhole. Policy (configurable, with safe defaults):

- **BOUND (healthy), primary path:** advertise eligible prefixes (and default route
  only if `publish` is enabled and no backup route is in use).
- **RETAINED / degraded uplink:** default **withdraw** because reachability of the
  public path is uncertain; allow an explicit opt-in to keep advertising during
  retention for deployments that accept this risk.
- **Gateway probe unreachable / master backup route active / any backup route in use:**
  treat as degraded for advertisement unless explicitly overridden; ties into existing
  `apply.master_backup_gateway` / `gwping` signals. **Backup routes must never be
  published as `0.0.0.0/0`; withdraw default-route advertisement while on backup.**
- **No lease / address withdrawn / role not master:** withdraw unconditionally.

VIP subnet advertisement may use a simpler policy (advertise while master owns the
VIP) if those prefixes are purely local, but must still withdraw on demotion.

### 6.5 Integration with ha-dhcpc

Add a native routing/OSPF coordination layer that reacts to existing events:

- **Triggers:** role transitions (`set_role`/promote/demote/handoff), lease
  acquire/renew/change/loss, retention entry/exit, gateway-probe verdict changes,
  and executor apply results affecting ownership.
- **Source of truth:** computed desired advertisement/origination set derived from
  `ctx->role`, `ctx->lease`, and config — reconciled idempotently (similar to
  executor desired state), not driven by fragile edge-only hooks.
- **Native actions:** originate/update/withdraw self-originated LSAs and maintain the
  minimal LSDB/neighbor state on configured fabric interfaces; install/remove
  accepted learned routes via the system routing table according to policy (never
  overwriting unrelated/direct local routes, never publishing backups, local working
  default precedence preserved).
- **Ordering:** withdraw before demotion/release where possible; advertise after the
  address/ownership is actually applied (or ready) to avoid transient blackholes.

### 6.6 Data plane notes

- **Public /32 placement:** ensure the master has a concrete forwarding path for the
  /32 (typically the leased address is already on the DHCP interface; a loopback
  host route may be used where appropriate, but must not conflict with executor
  behavior). Implementation must define and document the exact binding.
- **Ingress/egress symmetry:** shortest-path return traffic depends on all relevant
  clusters advertising correctly; asymmetric routing is acceptable only if intended.
- **Interaction with existing routes:** this feature must not alter the DHCP
  default-route / backup-gateway behavior except through explicitly documented,
  opt-in policy. The local (working) default route always takes precedence over any
  fabric-learned default route. A fabric-learned default from a local cluster member
  (master only), when accepted, is mapped to `apply.backup_gateway` as a backup path;
  if the local cluster master is down/unavailable, a default route from a remote
  cluster’s master may be used as the backup/fallback path. **Backup routes
  (`apply.backup_gateway`, `apply.master_backup_gateway`, and probe/failover backup
  paths) are never advertised/published to OSPF, regardless of default-route publish
  or accept settings.**

## 7. Proposed configuration (illustrative)

OSPF settings live in a separate, minimal `ospf` block. Routing behavior/ownership
remains driven by ha-dhcpc state (edge-only, local prefixes only).

```yaml
routing:
  enabled: false
  advertise:
    public_ip32: true        # lease.address/32 (master/owner only)
    vip_subnets: false       # optional: selected local VIP prefixes
    default_route: false     # publish 0.0.0.0/0 only on primary healthy path (never backup routes)
  accept:
    default_route: false     # accept/install 0.0.0.0/0 learned from fabric (backup path only)

ospf:
  # router_id: 10.0.0.2      # optional; defaults to this node's cluster/sync IP
  interfaces:                # fabric interfaces to run OSPF on (required when enabled)
    - br-fabric
    # - br-fabric2
  # auth:                    # optional simple authentication (applies to all interfaces)
  #   type: plaintext        # none | plaintext | md5
  #   key: "secret"          # required for plaintext/md5
  #   key_id: 1              # md5 only
```

Notes:
- Keep `ospf` minimal (router-id defaulted from cluster config, interfaces, optional
  simple auth). Area is implicitly 0.
- `routing.advertise.default_route` and `routing.accept.default_route` are
  independent and default off. Only the primary healthy path may be published. A
  local-cluster-master fabric default, when accepted, maps to `apply.backup_gateway`;
  remote-cluster-master default may be used only when the local master is down.
  Backup/fabric-learned defaults are never published.
- **Backup routes are never published:** `apply.backup_gateway`,
  `apply.master_backup_gateway`, and probe/failover backup paths must not be
  advertised as `0.0.0.0/0`.
- Defaults keep the feature off. When enabled, only locally owned/eligible prefixes
  are originated and never non-local/learned routes (see §6.3).
- `vip_subnets` selection must be precise to prevent accidental leakage of
  non-routable/private prefixes into the fabric.

## 8. Observability and operations

- Extend `ctl status` / JSON with routing/OSPF state: enabled, router-id, interfaces,
  neighbor/adjacency summary (as available), originated prefixes, accepted/selected
  backup candidates, last withdraw/announce reason, errors.
- Structured logs on every originate/withdraw/adjacency change with prefix, role,
  lease version, router-id, and reason.
- A safe manual control (e.g. `ctl routing withdraw|reconcile`) may be added, but
  must not override mastership/ownership invariants.

## 9. Security considerations

- Treat OSPF as a trusted-fabric protocol: require/encourage authentication on
  fabric interfaces; never enable OSPF on untrusted/DHCP uplink interfaces.
- Strictly validate and filter originated prefixes so `ha-dhcpc` cannot be induced
  to advertise arbitrary routes.
- Robustly parse/validate all received OSPF packets and LSAs (lengths, checksums,
  auth, LSA types/ages/sequence handling) to reduce crash/injection risk, given
  direct protocol exposure.

## 10. Risks and mitigations

- **Blackhole during retention/uplink loss:** default withdraw / conservative
  policy (§6.4).
- **Stale advertisement after crash/failover:** idempotent reconcile on startup and
  periodic verification; withdraw on uncertainty; age out/flush self-originated LSAs
  on loss of ownership.
- **Route flapping on rapid role/lease changes:** debounce/reconcile using current
  desired state (not per-event churn) and respect existing cluster cooldowns.
- **Native OSPF correctness/interop risk:** implement only the minimal interoperable
  subset, test against external OSPF routers/daemons (e.g. FRR/BIRD) in Area 0
  topologies, and prefer conservative behavior on ambiguity.
- **Leaking non-local routes / transit:** never originate LSAs for learned routes,
  enforce edge-only/non-transit behavior, and scope installed/used routes to
  intended fabric prefixes.
- **Complexity creep:** enforce the v1 OSPF subset and edge-only scope; avoid full
  general-purpose routing-daemon features.

## 11. Implementation milestones

- **R0 — Design freeze:** confirm target topologies/interop peers (FRR/BIRD/other),
  exact minimal LSA/adjacency/timer/auth profile, retention/probe policy, /32
  binding model, VIP selection semantics, and router-id defaulting; finalize config
  schema and status fields.
- **R1 — Routing core (state-driven):** compute desired originated prefix set from
  role/lease/VIP state; idempotent reconcile engine; local-master default
  attribution from cluster information (heartbeat/designated master); in-memory
  candidate/selection for backup defaults; status/logging; unit tests for state
  transitions and selection rules.
- **R2 — Native OSPFv2 speaker (interop):** minimal Area 0 speaker on configured
  fabric interfaces (Hello/adjacency, LSDB sync, originate/withdraw owned-prefix
  LSAs, receive/process neighbor LSAs) with router-id/auth support; direct interop
  with external OSPF routers/daemons; shortest-path reachability and failover
  convergence validation.
- **R3 — Route install and hardening:** policy-compliant install of learned fabric
  routes and accepted backup defaults (local working precedence, no backup publish,
  no overwrite of unrelated/direct local routes), retention/probe wiring,
  startup/crash reconciliation, docs and operational runbook.
- **R4 — Multi-cluster validation:** netns/lab topology with >=2 clusters, external
  OSPF peers, and alternate paths; verify /32 (and optional VIP) reachability across
  failover and shortest-path changes.

## 12. Open questions

1. Which minimal LSA types and origination strategy best fit edge-only interop in
   Area 0 for `/32`, VIP subnets, and optional default route (while remaining
   interoperable with FRR/BIRD)?
2. Which external OSPF speakers/topologies must be validated first for direct
   interoperability, and what Hello/Dead/timer defaults are acceptable?
3. During `RETAINED` with an unreachable gateway, should the default be strict
   withdraw of the public /32, or a configurable metric/penalty if supported?
4. Should the public /32 be bound to the DHCP interface, a loopback, or a
   routing-only construct to decouple advertisement from forwarding specifics?
5. Which `cluster.addresses` (all, per-interface allowlist, or explicit CIDRs) are
   eligible for optional advertisement?
6. Is equal-cost multipath (ECMP) across fabric links desired/acceptable in v1?
7. How should the edge-only/non-transit constraint be enforced concretely in the
   native speaker (no self-originated transit LSAs/routes, no learned-route
   re-origination, scoped route installation) to guarantee no non-local routes are
   propagated?
8. How are fabric-learned default routes from remote clusters attributed
   (router-id/origin mapping or equivalent) to identify a remote cluster master for
   fallback, given local-master attribution is derived from cluster information?
9. (Resolved) Local (working) default route always takes precedence over any
   fabric-learned `0.0.0.0/0`. A default route learned from a local cluster member
   (master only), if accepted, is mapped to `apply.backup_gateway` as a backup path.
   If the local cluster master is down/unavailable, a default route from a remote
   cluster’s master may be used as backup/fallback. Fabric-learned defaults must
   never cause backup-route publication and must remain compatible with edge-only
   intent.
