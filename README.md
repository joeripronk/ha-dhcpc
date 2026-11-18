# ha-dhcpc

`ha-dhcpc` is a high-availability DHCP client cluster for Linux. One **master** node runs the DHCP conversation and lease timers, syncs lease/state to **slave** nodes, and all members apply the same L3 configuration. On DHCP failure the cluster can retain the last known-good configuration instead of tearing addresses/routes down.

Failover is built in (no external VRRP/keepalived required): members exchange heartbeats, elect/promote based on priority and quorum, and the master owns configured cluster VIPs (with gratuitous ARP on takeover). Every member uses the same shared DHCP client identity (designated master MAC from the shared config), so a promoted node can continue renew/rebind on the synced lease without a fresh DISCOVER.

## Project goals

- Single authoritative DHCP speaker with a consistent client identity across the cluster.
- Lease and role state synchronized to peers so failover does not require a DHCP round-trip or config re-apply churn.
- Idempotent, declarative application of addresses, routes, DNS/hooks and cluster VIP ownership.
- Retention/degraded operation on renew failure or server outage (policy-driven), rather than dropping the active configuration.
- Built-in role management, observability, and safe cluster behavior on Linux routers/hosts (including OpenWrt targets).

See [`HA-DHCPC.md`](HA-DHCPC.md) for the full design.

## Current status

Actively developed and used in deployment-specific setups. Core HA DHCP functionality and several advanced data-plane/fabric features are implemented; some areas remain minimal, best-effort, or partially validated.

### Implemented

- **Cluster & roles:** heartbeat-based membership, quorum/priority election and preemption controls, master/slave/promoting/demoting states, role propagation, manual `ctl promote|demote`, graceful restart handling, startup/join state restore from persisted cluster/lease view.
- **DHCP & lease handling:** vendored FreeBSD-derived dhclient engine (`src/dhcp/`), master-only DHCP protocol/timers, shared MAC identity, lease persistence, retention behavior, renew/rebind flow and `ctl renew`.
- **Config & control:** shared `ha-dhcpc.conf` + local overlay merge, config digest/sync, `ctl` for status, update, renew, promote/demote, graceful restart, shutdown (`shutdown now`/`kill` to force), and `conntrack resync`, JSON status over a unix control socket.
- **Executor/apply:** idempotent netlink-based reconcile of addresses/routes, VIP ownership and gratuitous ARP, slave isolation behavior, hook/DNS/ddclient integration points, gateway probe and backup-gateway handling, drift reconciliation/monitoring.
- **Neighbor sync:** optional sync of REACHABLE VIP/interface neighbors to peers for smoother takeover.
- **Conntrack sync (v1, IPv4):** optional master-push TCP replication worker (`conntrack_sync`) with snapshot/incremental updates, staged apply on replicas, non-local classification, helper/SIP awareness (best-effort/capability-gated), status and `ctl conntrack resync`.
- **Inter-cluster routing / OSPF (minimal edge-only):** native OSPFv2 speaker and routing core (`routing`/`ospf`) for originating locally owned prefixes on a fabric (e.g. public /32, optional VIP subnets/default-route policy), learning/installing fabric routes, and selecting backup default paths according to policy. Area 0, local-prefix origination only (no transit/redistribution of learned non-local routes). Fast convergence: dead cluster peers have their LSAs flushed with MaxAge on the heartbeat cadence (router-id == member sync_address), dead OSPF neighbors' LSAs are flushed when the adjacency drops, and a shutting-down node announces its own death (`ospf.announce_death`: `true`/`false`/`auto`; auto = on in a cluster, off standalone); graceful-restart windows keep the LSDB quiet.
- **Seamless demotion handoff (opt-in):** `apply.demote_route_via_new_master` can steer traffic over a non-VIP fabric during the demoting hold (split /1 and VIP-subnet steering), keep VIPs assigned through the hold while suppressing VIP ARP replies and dropping VIP-source traffic, reconcile `rp_filter`, and apply mark/NOTRACK nftables hooks to avoid conntrack/NAT on the demoting node. See [`SEAMLESS_TAKEOVER.md`](SEAMLESS_TAKEOVER.md) and [`SEAMLESS_FIREWALL_HOWTO.md`](SEAMLESS_FIREWALL_HOWTO.md).

### Limitations / known gaps

- **OSPF MD5 authentication is not implemented.** `ospf.auth.type: md5` is parsed/configurable but packets are not MD5-signed and MD5-authenticated peers are rejected; use `none` or `plaintext`.
- **Conntrack sync** is IPv4-only, best-effort, and bounded by kernel/helper semantics, replication lag, and deployment topology. It is not a general replacement for all `conntrackd` use cases.
- **OSPF/routing** implements a minimal interoperable edge subset, not full OSPF feature parity; interoperability/topology coverage should be validated for your environment.
- **Seamless takeover** is opt-in and best-effort (not zero-loss). Automated netns/nft integration coverage exists (`tests/seamless-takeover-netns.sh`, requires root), but controlled handoff under load and WAN-ingress-during-hold scenarios remain manual validation items.
- **Platform:** Linux-focused (netlink/nftables/sysctl/capabilities). Some features require specific kernel support, privileges, and a trusted L2/fabric as documented.
- **No repository license file** is currently included; verify licensing/redistribution terms before external distribution.

## Repository layout

- `src/`, `include/ha-dhcpc/` — daemon implementation (`src/dhcp/` contains the vendored FreeBSD/ISC-derived DHCP client engine)
- `tests/` — unit/integration test sources and scripts
- `production/` — deployment-specific configs/units (host router, OpenWrt examples)
- `HA-DHCPC.md` — primary design document
- `SEAMLESS_TAKEOVER.md`, `SEAMLESS_FIREWALL_HOWTO.md` — seamless handoff behavior and firewall cooperation

## Build

Dependencies: `libnl-3.0`, `libnl-route-3.0`, `libyaml` (`yaml-0.1`), `jansson`, pthreads, and a C toolchain (GNU11). A git checkout is used for version stamping when available.

```sh
make            # build ./ha-dhcpc
make test       # build and run unit tests
```

Cross-build example (OpenWrt SDK/rootfs):

```sh
make CROSS_COMPILE=/path/to/toolchain/bin/<target>- \
     SYSROOT=/path/to/target-rootfs
```

## Configuration and usage

`ha-dhcpc` uses a shared cluster config plus an optional local overlay (local values win on repeated keys). Configuration covers cluster membership/identity, DHCP/interface/retention policy, apply behavior, routing/OSPF, conntrack sync, and control socket paths. Start from the examples in `production/` and the schema/behavior described in [`HA-DHCPC.md`](HA-DHCPC.md).

Typical runtime operations (exact commands/options depend on build/config):

```sh
ha-dhcpc ctl status
ha-dhcpc ctl promote <id> | ha-dhcpc ctl demote <id>
ha-dhcpc ctl update
ha-dhcpc ctl renew
ha-dhcpc ctl newip                  # master: force a fresh DISCOVER
ha-dhcpc ctl graceful-restart enable|disable
ha-dhcpc ctl shutdown [now]         # kill/quit/stop also accepted
ha-dhcpc ctl conntrack resync
```

`status` also works without `ctl` and accepts section/detail arguments (e.g. `ha-dhcpc status cluster`, `status ip`, `status ospf routes|neighbors`, `status detailed`). Unambiguous command/argument prefixes are accepted.

## Testing and deployment notes

- Prefer `make test` after code changes.
- Integration scripts (e.g. `tests/seamless-takeover-netns.sh`, routing/failover scripts) may require root, namespaces, nftables, or lab topology access.
- This repo includes environment-specific deploy helpers (`deploy-local.sh`, `deploy-openwrt.sh`, `production/` assets); review them before use as they can affect live routers/failover behavior.

## Documentation

- [`HA-DHCPC.md`](HA-DHCPC.md) — architecture, goals, cluster/lease behavior
- [`SEAMLESS_TAKEOVER.md`](SEAMLESS_TAKEOVER.md) — demotion handoff/steering behavior
- [`SEAMLESS_FIREWALL_HOWTO.md`](SEAMLESS_FIREWALL_HOWTO.md) — firewall/conntrack cooperation for seamless takeover
