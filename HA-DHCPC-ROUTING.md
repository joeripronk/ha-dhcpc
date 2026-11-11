# HA-DHCPC Inter-Cluster Routing (Plan)

Plan for simple routing between local `ha-dhcpc` clusters so the current holder of a
cluster's public DHCP address is reachable over the shortest path. The preferred
mechanism is a small, well-defined subset of OSPF, used only where it keeps
complexity low.

This is **edge-only routing**: an `ha-dhcpc` node originates only its own
locally owned prefixes and is not a transit/full OSPF router. It must never
advertise, redistribute, or forward non-local routes learned via OSPF.

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
  redistribute, or forward non-local routes learned via OSPF.
- **Shortest-path reachability to the origin** on the local inter-cluster fabric
  using dynamic routing, with OSPFv2 preferred if the resulting design stays simple.
- **Minimal, explicit configuration:** reuse existing cluster/lease concepts where
  possible; avoid coupling core DHCP/HA behavior to routing internals.
- **Safe failure behavior:** never create a persistent blackhole or a routing loop
  due to stale advertisements; prefer withdraw-on-uncertainty.

## 3. Non-goals (initial scope)

- Full OSPF feature parity (multiple areas, NSSA/virtual links, traffic
  engineering, BFD integration in v1 unless trivial via the routing daemon).
- Acting as a transit/full OSPF router or carrying transit traffic for non-local
  destinations; propagating, redistributing, or re-advertising any non-local routes
  learned via OSPF.
- IPv6 / OSPFv3 (IPv4 only, matching current cluster/VIP scope).
- Replacing the existing default-route, backup-gateway, or gateway-probe logic
  managed by the executor for the DHCP uplink.
- Providing a general-purpose routing daemon inside `ha-dhcpc`.
- Automatic discovery of arbitrary network topologies beyond the explicitly
  configured routing neighbors/interfaces.

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
    fabric links and a working dynamic-routing stack available where needed.
  - The fabric links are administratively controlled and can be placed in a single
    OSPF area (Area 0) with a simple topology.
  - The public /32 is meaningful/reachable inside this routing domain (e.g.
    clusters share an upstream or a common NAT/routed environment); the plan does
    not assume global Internet routing of the /32.

## 5. Design options

### Option A — Integrate with an external OSPF daemon (recommended)

`ha-dhcpc` determines *what* must be advertised based on authoritative local state
(role, lease, VIP ownership) and delegates *how* to speak OSPF to a mature routing
daemon (e.g. FRRouting `ospfd`, BIRD, or an OpenWrt-packaged OSPF implementation).

Mechanisms (one or a combination, chosen per platform):

1. **Kernel route injection + redistribute:** on become-owner, install a host/connected
   route for the prefix in a dedicated table or with a specific protocol/tag/metric;
   configure OSPF to redistribute that route (and filter everything else). On lose-
   owner, remove it so OSPF withdraws the LSA.
2. **Daemon control hook:** invoke a small, idempotent helper (e.g. `vtysh`, `birdc`,
   or a generated include file + reload) to add/remove a prefix advertisement.
3. **Sidecar announcer:** a tiny companion process reads ha-dhcpc status/socket and
   maintains OSPF origination; keeps the core daemon routing-agnostic.

**Pros:** correct OSPF behavior, fast convergence features, authentication, and
ecosystem tooling without implementing SPF/LSDB/adjacencies in C. Matches
"subset of OSPF" by constraining configuration, not by reimplementing protocol.
**Cons:** external dependency and per-platform packaging/integration work.

### Option B — Minimal built-in OSPFv2 speaker (not recommended)

Implement a constrained OSPFv2 speaker (single area, fixed neighbor set, limited
LSA types) inside or alongside `ha-dhcpc`.

**Pros:** no external routing dependency.
**Cons:** high implementation and correctness risk (adjacency state machine,
flooding, aging, SPF, sequence numbers, MTU/auth edge cases). Disproportionate
complexity for "simple routing functionality"; violates the preference to keep
complexity low.

### Option C — Non-OSPF fallback (distance-vector/simple) — contingency only

Use RIP, Babel, or a static/overlay scheme if OSPF integration proves too heavy on
a target platform.

**Pros:** sometimes lighter to deploy.
**Cons:** weaker fit for "shortest path" in some topologies, different operational
model; considered only if Option A is impractical on a required target.

**Decision:** pursue **Option A**. Constrain usage to an OSPF subset (single area,
point-to-point or broadcast on fabric links as appropriate, no exotic LSA types)
rather than building a protocol implementation.

### 5.1 Can OSPF be limited to “heartbeats and route exchange”?

Partly, but only by **configuration/profile**, not by implementing a stripped-down
OSPF speaker:

- **Hello packets are the heartbeat.** Neighbor liveness is exactly OSPF Hello +
  Dead-interval handling.
- **Route exchange is not a single simple message.** Correct, interoperable OSPF
  requires adjacency formation, Database Description/LSR/LSU/LSAck exchange, LSAs
  (at least Router/Network as topology requires and AS-external/summary forms for
  originated prefixes), sequence-number/aging/flooding rules, and SPF to compute
  shortest paths. A bespoke “Hello + announce/withdraw route” implementation would
  omit LSDB consistency and loop/flood protections and would be non-interoperable
  and correctness-risky (see Option B).
- **Minimal OSPF profile with Option A (recommended):** run a mature external
  daemon but limit *our* footprint and daemon config to the essentials: single
  Area 0, explicit fabric interfaces only, point-to-point where possible, originate
  only ha-dhcpc-owned `/32`/VIP prefixes (no full connected/kernel redistribution),
  strict prefix/tag filtering, and tuned Hello/Dead (and SPF throttle) timers for
  the desired convergence. Operationally this is “heartbeats + route exchange of a
  few prefixes”, with protocol correctness handled by the daemon.
- **Edge-only, non-transit role:** this node is never a transit OSPF router and only
  originates prefixes it locally owns. It must not redistribute, re-originate, or
  propagate/forward non-local routes in the routing protocol (no re-advertisement of
  routes learned from OSPF). To keep it off transit paths, enforce strict outbound
  filtering to local prefixes only and, where supported, a non-transit/stub-router
  style configuration (e.g. FRR `max-metric router-lsa` / equivalent). Installing
  routes to reach other clusters’ ha-dhcpc-originated prefixes is in scope for
  reachability; providing transit for unrelated third-party destinations is not.
- **Bespoke non-OSPF minimal protocol (contingency, not OSPF):** if an external
  OSPF dependency is unacceptable on a target, a ha-dhcpc-native announcer could
  gossip owned prefixes over periodic UDP heartbeats carrying `(prefix, owner/cost,
  seq/ttl)` and install/remove kernel host routes. This is simpler to build but is
  **not OSPF**, gives distance-vector-like behavior rather than proven OSPF SPF
  semantics, and needs explicit loop prevention/horizon rules; it is suitable only
  for very simple, well-controlled topologies and would be a separate design track.

## 6. Proposed design (Option A)

**Edge-only constraint (invariant):** this node is an originator of locally owned
prefixes only — never a transit/full OSPF router. It must not redistribute, re-
originate, or propagate non-local routes learned via OSPF (no forwarding of
non-local routes within the routing protocol). It must not be used as a transit
path for unrelated third-party destinations; reachability to other clusters’
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
advertisement before or atomically with relinquishing ownership (best-effort; must
be idempotent).

### 6.2 What is advertised and accepted

| Prefix/route | Source | Direction | Default | Notes |
|---|---|---|---|---|
| Public DHCP IPv4 `/32` | `lease.address` | publish (originate) | **enabled** (when routing feature on) | Primary goal; moves with failover/new lease. |
| VIP subnet(s) | `cluster.addresses` | publish (originate) | **optional** | Only prefixes explicitly enabled; avoids leaking internal ranges by default. |
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
  Accepting/publishing a default route can affect transit behavior and must remain
  explicitly opt-in and compatible with the edge-only intent of this feature.

### 6.3 OSPF subset and topology

To keep complexity bounded, the supported subset is:

- **OSPFv2, single Area 0** only.
- **Explicit fabric interfaces:** OSPF runs only on the configured fabric interfaces;
  no implicit enablement on other interfaces.
- **Network type:** implementation-selected for simplicity (point-to-point preferred
  on dedicated inter-cluster links; broadcast where required). No NBMA/virtual links
  in scope.
- **Local-only origination (no transit):** originate only the specific prefixes
  owned by this ha-dhcpc instance (e.g. its public `/32`, optional selected VIP
  subnets). **No redistribution of the full kernel/connected table and no
  propagation/re-advertisement of any non-local route learned via OSPF.** Enforce
  with explicit outbound allowlists (prefix-list/route-map filtered to
  ha-dhcpc-owned prefixes only) and reject/omit all other routes. Where supported,
  configure the daemon in a non-transit/stub-router mode (e.g. FRR
  `max-metric router-lsa` or equivalent) so other routers do not select this node
  as transit for unrelated traffic.
- **Learned routes handling:** routes to other clusters’ ha-dhcpc-originated
  prefixes may be learned/installed as needed for reachability and shortest-path
  selection to those prefixes. Non-local learned routes must never be redistributed
  or re-originated by this node, and the node must not provide transit for
  unrelated third-party destinations. Implementation should scope accepted/used
  routes to the intended fabric prefixes where practical.
- **Authentication:** optional simple authentication when configured, applied to the
  configured fabric interfaces (see `ospf` config).
- **Cost/metric:** backend/default-determined in v1 for simplicity (no separate
  metric tuning in the minimal config).

### 6.4 Lease/health interaction (avoid blackholes)

Advertising a /32 or a default route while the master cannot actually forward traffic
to/from the upstream creates a blackhole. Policy (configurable, with safe defaults):

- **BOUND (healthy), primary path:** advertise eligible prefixes (and default route
  only if `publish` is enabled and no backup route is in use).
- **RETAINED / degraded uplink:** default **withdraw** (or raise metric if supported
  and explicitly configured) because reachability of the public path is uncertain;
  allow an explicit opt-in to keep advertising during retention for deployments that
  accept this risk.
- **Gateway probe unreachable / master backup route active / any backup route in use:**
  treat as degraded for advertisement unless explicitly overridden; ties into existing
  `apply.master_backup_gateway` / `gwping` signals. **Backup routes must never be
  published as `0.0.0.0/0`; withdraw default-route advertisement while on backup.**
- **No lease / address withdrawn / role not master:** withdraw unconditionally.

VIP subnet advertisement may use a simpler policy (advertise while master owns the
VIP) if those prefixes are purely local, but must still withdraw on demotion.

### 6.5 Integration with ha-dhcpc

Add a routing/advertisement coordination layer that reacts to existing events:

- **Triggers:** role transitions (`set_role`/promote/demote/handoff), lease
  acquire/renew/change/loss, retention entry/exit, gateway-probe verdict changes,
  and executor apply results affecting ownership.
- **Source of truth:** computed desired advertisement set derived from `ctx->role`,
  `ctx->lease`, and config — reconciled idempotently (similar to executor desired
  state), not driven by fragile edge-only hooks.
- **Action backends (pluggable, platform-specific):**
  - `backend: frr` — manage a prefix-list/route-map fragment or call `vtysh` to
    originate/withdraw (exact mechanism chosen in implementation).
  - `backend: bird` — `birdc`/config fragment + reload or protocol control.
  - `backend: kernel` — install/remove tagged host routes in a dedicated table for
    redistribution by an independently managed OSPF daemon (lowest coupling).
  - `backend: hook` — exec an operator-supplied idempotent script with structured
    env/args (`up|down`, prefix, interface, reason) for custom integration.
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

OSPF settings live in a separate, minimal `ospf` block: fabric interfaces and
optional simple authentication. Routing behavior/ownership remains driven by
ha-dhcpc state (edge-only, local prefixes only).

```yaml
routing:
  enabled: false
  advertise:
    public_ip32: true        # lease.address/32 (master/owner only)
    vip_subnets: false       # optional: selected local VIP prefixes
    default_route: false     # publish 0.0.0.0/0 only on primary healthy path (never backup routes)
  accept:
    default_route: false     # accept/install 0.0.0.0/0 learned from fabric

ospf:
  interfaces:                # fabric interfaces to run OSPF on (required when enabled)
    - br-fabric
    # - br-fabric2
  # auth:                    # optional simple authentication (applies to all interfaces)
  #   type: plaintext        # none | plaintext | md5
  #   key: "secret"         # required for plaintext/md5
  #   key_id: 1              # md5 only
```

Notes:
- Keep `ospf` as simple as possible (interfaces + optional simple auth). Area is
  implicitly 0 and advanced OSPF/backend knobs are omitted from the minimal config.
- `routing.advertise.default_route` and `routing.accept.default_route` are
  independent and default off. Publishing/accepting a default route is opt-in and
  may affect edge/transit behavior; only the primary healthy path may be published.
  The local (working) default route always takes precedence over any fabric-learned
  default route. An accepted default route learned from a local cluster member
  (master only) maps to `apply.backup_gateway`; if the local cluster master is down,
  a default route from a remote cluster’s master may be used instead. Backup routes
  are never published.
- **Backup routes are never published:** `apply.backup_gateway`,
  `apply.master_backup_gateway`, and probe/failover backup paths must not be
  advertised as `0.0.0.0/0`.
- Defaults keep the feature off. When enabled, only locally owned/eligible prefixes
  are originated and never non-local/learned routes (see §6.3).
- `vip_subnets` selection must be precise to prevent accidental leakage of
  non-routable/private prefixes into the fabric.
- The schema is illustrative; exact names/validation are finalized at implementation.

## 8. Observability and operations

- Extend `ctl status` / JSON with routing advertisement state: enabled, backend,
  advertised prefixes, last withdraw/announce reason, backend health/errors.
- Structured logs on every announce/withdraw with prefix, role, lease version, and
  reason.
- A safe manual control (e.g. `ctl routing withdraw|reconcile`) may be added, but
  must not override mastership/ownership invariants.

## 9. Security considerations

- Treat OSPF as a trusted-fabric protocol: require/encourage authentication on
  fabric interfaces; never enable OSPF on untrusted/DHCP uplink interfaces.
- Strictly filter originated prefixes so `ha-dhcpc` cannot be induced to advertise
  arbitrary routes.
- Hook/backend commands run with daemon privileges: paths must be absolute,
  arguments controlled, and failures surfaced (no silent partial state).

## 10. Risks and mitigations

- **Blackhole during retention/uplink loss:** default withdraw / conservative
  policy (§6.4).
- **Stale advertisement after crash/failover:** idempotent reconcile on startup and
  periodic verification; withdraw on uncertainty; keep external daemon state
  minimal and derived.
- **Route flapping on rapid role/lease changes:** debounce/reconcile using current
  desired state (not per-event churn) and respect existing cluster cooldowns.
- **External dependency drift (FRR/BIRD differences):** isolate via a narrow
  backend interface and contract tests per backend.
- **Complexity creep:** enforce the v1 OSPF subset; reject features that require a
  built-in protocol engine.
- **Over-trimming OSPF:** attempting a “heartbeat + route only” custom speaker
  reintroduces LSDB/SPF/flooding correctness risks; prefer the minimal external
  OSPF profile (§5.1) or an explicitly non-OSPF bespoke track for trivial topologies.
- **Leaking non-local routes:** misconfiguration could propagate learned routes;
  enforce strict local-prefix-only outbound filtering and non-transit settings, and
  verify no non-local prefixes are originated.

## 11. Implementation milestones

- **R0 — Design freeze:** confirm target platforms/backends (OpenWrt packages
  available?), exact retention/probe policy, /32 binding model, and VIP selection
  semantics; finalize config schema and status fields.
- **R1 — Advertisement core (backend-agnostic):** compute desired prefix set from
  role/lease/VIP state; idempotent reconcile engine; `kernel` or `hook` backend;
  status/logging; unit tests for state transitions.
- **R2 — OSPF backend integration:** one concrete backend (e.g. FRR or BIRD) with a
  documented Area-0/point-to-point subset, prefix filtering, and packaging notes;
  lab validation of shortest-path selection and failover convergence.
- **R3 — Hardening:** retention/probe policy wiring, startup/crash reconciliation,
  optional VIP subnet advertisement, auth/config passthrough, docs and operational
  runbook.
- **R4 — Multi-cluster validation:** netns/lab topology with >=2 clusters and
  alternate paths; verify /32 (and optional VIP) reachability across failover and
  shortest-path changes.

## 12. Open questions

1. Which OSPF daemon(s) must be supported first on the target deployments (FRR,
   BIRD, `ospfd` package on OpenWrt), and what control interface is stable there?
2. During `RETAINED` with an unreachable gateway, should the default be strict
   withdraw of the public /32, or a configurable metric penalty?
3. Should the public /32 be bound to the DHCP interface, a loopback, or a
   routing-only construct to decouple advertisement from interface specifics?
4. Which `cluster.addresses` (all, per-interface allowlist, or explicit CIDRs) are
   eligible for optional advertisement?
5. Is equal-cost multipath (ECMP) across fabric links desired/acceptable in v1, or
   should the design assume a single best path?
6. What convergence target (seconds) is required for inter-cluster reroute on
   failover, and is it achievable with the chosen backend’s default timers?
7. Is the minimal external-OSPF profile (§5.1) sufficient for all target
   topologies, or do any require the non-OSPF bespoke announcer contingency (and
   if so, is the topology simple enough to bound loops/convergence)?
8. How should the edge-only/non-transit constraint be enforced per backend
   (outbound-only local prefix filters, non-transit/max-metric LSA, and scoping of
   installed learned routes) to guarantee no non-local routes are propagated?
9. Is global `ospf.auth` sufficient for all fabric interfaces, or is simple
   per-interface auth needed while keeping the config minimal?
10. (Resolved) Local (working) default route always takes precedence over any
    fabric-learned `0.0.0.0/0`. A default route learned from a local cluster member
    (master only), if accepted, is mapped to `apply.backup_gateway` as a backup path.
    If the local cluster master is down/unavailable, a default route from a remote
    cluster’s master may be used as backup/fallback. Fabric-learned defaults must
    never cause backup-route publication and must remain compatible with edge-only
    intent.
11. How are fabric-learned default routes attributed to a local cluster member
    (master only) versus a remote cluster’s master (router-id/origin mapping or
    equivalent) to drive `apply.backup_gateway` selection?
