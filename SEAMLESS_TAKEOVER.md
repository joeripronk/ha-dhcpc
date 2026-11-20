# Seamless takeover plan (demote → route via new master)

## Goal

Make master demotion/handoff as seamless as possible by keeping the demoting node forwarding traffic to the newly promoted master over a separate cluster/OSPF fabric, instead of blackholing or hairpinning flows during the ownership transition.

Target behavior (when explicitly enabled and prerequisites are met):
- **The new master prepares before it announces ownership**: it sets up its local environment (public IP + routing, VIPs assigned **without GARP**, confirmed active), signals the old master to start steering traffic to it via the /+1 split routes, and only **GARPs the VIPs after the old master confirms the routes are installed** (see "Takeover sequence"). The **old master keeps the VIP addresses assigned during the hold** and simply stops answering/originating for them: **no ARP replies and no locally-originated traffic from VIP sources**. The VIP addresses are removed only **after the migration completes** (hold ends → SLAVE). As long as the demoting node neither replies to ARP nor sends traffic from the VIPs, temporarily holding both copies is safe enough, and it prevents the demoting master from dropping traffic it can still forward to the new master.
- **Return/inbound traffic that still arrives at the old master is forwarded to the new master** over the non-VIP fabric during a controlled hold window.
- **Outbound/forwarded traffic from the old master is steered to the new master** without relying on the old upstream/default path.
- **NAT/masquerading ownership moves to the new master**; the demoting master forwards packets without creating/rewriting NAT state.

This is an opt-in, best-effort forwarding bridge during handoff — not a guarantee of zero loss under all failures.

## Current implementation (baseline)

- `apply.demote_route_via_new_master` (opt-in): on demotion handoff hold, if valid, steers
  outbound/forwarded traffic via the new master’s cluster `sync_address` (fabric nexthop) using
  additive split /1 routes (see "Outbound" below; this replaced the earlier `default_via`
  override) while keeping the public WAN IP/default route and — with steering active — the VIP
  addresses installed (VIPs are removed only after the hold completes). Validation at startup/reload requires:
  - at least one `ospf.interfaces` entry
  - every `ospf.interfaces` entry must **not** be an interface that carries `cluster.addresses` (VIPs)
- Invalid configuration: behavior disabled, runtime state marked invalid, and an error logged (`demote_route_via_new_master(...): invalid configuration: ...; behaviour disabled`).
- Status: exposed via `ctl status` as `demote_route_via_new_master.{configured,active,invalid,reason}`.

## Prerequisites

1. **Separate non-VIP fabric** for cluster sync/OSPF/routing (e.g. dedicated VLAN/interface). `sync_address` peers and `ospf.interfaces` must remain reachable when VIP interfaces/addresses change. An interface used for OSPF in this mode must not host VIP/cluster addresses.
2. **L3 forwarding enabled** on the demoting node for the relevant families/paths; firewall must permit forwarding between WAN/VIP-facing ingress and the fabric toward the new master during the hold.
3. **Conntrack/state replication** (`conntrack_sync`) healthy enough for the new master to continue existing flows where applicable; helper/expectation coverage and replication lag are limiting factors.
4. **Timely promotion** of the new master (VIP add + GARP + route/neighbor readiness) within/around `apply.handoff_hold_ms` (default 5000 ms).

## Takeover sequence (new master side)

For seamless takeover to work correctly, the new master must be fully prepared and confirmed
before it announces VIP ownership; otherwise it GARPs (and starts claiming) the VIP while the
old master's steering routes are not yet in place, and stray traffic during that window is
blackholed. Required order:

1. **Prepare locally** on the takeover node: apply the public IP + routing (from the synced
   lease), assign the VIP addresses **without GARP**, and confirm everything is active.
   **Always verify the public IP and routing — above all a working default route — are up and
   correct before announcing the VIPs** (GARP): announcing ownership without a correct default
   route risks disconnects, because return traffic and NAT would follow a wrong or missing
   route the moment clients start sending us their flows.
2. **Signal the old master** (the node in the demoting hold) to start sending its traffic to
   this node, i.e. install the /+1 split steering routes (VIP-subnet splits and the /1
   defaults) pointing at the takeover node's fabric address.
3. **Wait for the old master to signal back** that its steering routes are installed.
4. **GARP the VIPs** — only now announce ownership (GARP burst, then role/readiness), so
   clients, the old master's steering, and NAT/conntrack ownership converge on the new master
   only after the forwarding bridge is up.

Implemented (new-master side): promotion prepares locally (public IP + routing from
the synced lease, VIPs assigned without GARP, verified active — a working default
route must be present before any announce), then signals the old master via the
cluster protocol (`takeover_prep`). The old master, holding for this node with its
/+1 steering routes installed, answers `takeover_ack` (steered=false when it cannot
steer); only then the new master GARPs the VIPs and announces ready. The ack wait is
bounded by `handoff_hold_ms` (min 1000 ms). With no handshake peer (dead master or
single-node) the handshake is skipped: promotion goes straight to MASTER, verifies
the local WAN path, and withholds the role announcement until GARP is done (see
"Dead-master failover").

## Ordering: NOTRACK before steering (critical)

On the demoting node the mark/NOTRACK chains must be installed **before** the /1 and
VIP-split steering routes, and removed **after** those routes on teardown. Otherwise
steered packets are tracked and SNATed by the old master before they reach the new
master: the new master then sees a public-IP source and installs a no-NAT conntrack
entry for the flow. Survival snapshots are not enough — the flow is broken.

```
WRONG (steering before NOTRACK):
  client 172.16.202.42:50636
      -> OLD MASTER (SNAT -> 82.174.239.91) --fabric--> NEW MASTER
      -> NEW MASTER sees src=82.174.239.91 -> creates no-SNAT entry
      -> reply goes to 82.174.239.91, tuple mismatch -> retransmits -> RST

RIGHT (NOTRACK before steering):
  client 172.16.202.42:50636
      -> OLD MASTER (NOTRACK, forward as-is) --fabric--> NEW MASTER
      -> NEW MASTER applies SNAT once: 172.16.202.42 -> 82.174.239.91
```

Teardown order is the reverse: remove steering routes first, then the mark/NOTRACK
chains, so traffic during route cleanup still bypasses conntrack/NAT.

## Conntrack/NAT state rules

The replica table on the slave is the source of truth for the new master. These
rules were added after flow-loss traces:

- **Port-preserving NAT only.** Reject replicated entries whose translated source
  port differs from the original source port; adopting them installs a wrong reply
  tuple on the new master.
- **CREATE must send the un-translated reply tuple.** Netfilter sets `IPS_SRC_NAT`
  only when the NAT range actually changes the reply tuple. Sending the already-NATed
  public IP produces only `IPS_SRC_NAT_DONE` and no SNAT, so outbound packets leave
  with the private source and replies are dropped.
- **A master DELETE during handoff is local teardown, not a flow end.** Keep the
  replica shadow entry for 30 s (pending-delete) and reinstall it at promotion with
  DELETE then CREATE; a plain in-place update cannot fix TCP state/NAT.
- **Retry on EEXIST/EOPNOTSUPP without NAT attributes**, and actually schedule the
  retry (`next_retry_ms = 0` means "no retry"). Unexpected netlink failures are
  logged.
- **Routing state is state-aware:** a demoted node keeps its primary default route
  through the hold and a short post-handoff grace; it does not switch to the slave
  backup route while clients still send to the old VIP. A node designated master
  installs its primary route before the old node starts steering to it.

## Dead-master failover (poweroff)

No handshake, no old-master DELETE sequence. Election/failover detection is
~0.75 s on the routers (100 ms heartbeat, 500 ms deadline, 250 ms maintenance tick);
defaults are ~6.5 s. The chosen slave goes **straight to MASTER** — PROMOTING is only
used for a live handoff with a demoting peer.

```
  MASTER dies (no heartbeat, no takeover_prep / takeover_ack)
        |
        v  ~0.75 s
  slave wins -> role=MASTER (no PROMOTING step)
        |
        +-- verify public IP + default route
        +-- withhold wire role + role_change until ready
        +-- apply VIPs, GARP, start DHCP
        +-- notify conntrack, apply replica shadow (DELETE+CREATE)
        |
        v
  peers see MASTER only after the announce
```

A dead master's OSPF LSAs are flushed at MaxAge by a surviving node; a poweroff
cannot flush its own LSAs, so the LSA dead timer is the fallback. If the dead master
left a graceful-restart window active, failover is suppressed for up to 180 s.

## Routing strategies

### Outbound: split defaults (/1 routes)

To force outbound traffic via the new master without deleting the existing default route, install two more-specific routes on the demoting node during the hold:
- `0.0.0.0/1 via <new_master_fabric_next_hop>`
- `128.0.0.0/1 via <new_master_fabric_next_hop>`

Properties:
- Longest-prefix match beats `0.0.0.0/0`, so outbound/forwarded packets prefer the new master.
- Does not remove a connected/local route for addresses still assigned locally.
- Nexthop must be resolved on the fabric (not on a VIP interface).

This can replace/augment the current `default_via` override for the keep-default case and is compatible with keeping the WAN/public address present during hold.

### VIP prefixes: split more-specific routes (implemented)

Example: VIP subnet `192.168.10.0/24` → `192.168.10.0/25` and `192.168.10.128/25` via `<new_master_fabric_next_hop>`.
Installed per configured cluster address with a CIDR prefix while steering; host-prefix addresses and subnets containing the nexthop are skipped.

Purpose: forward traffic destined to the VIP subnet toward the new master even if a connected subnet route would otherwise exist.

**Important:** installing split routes does **not** replace correct VIP ownership transfer.
- The demoting master **keeps the VIP IP address assigned during the hold** but must **stop answering ARP for it and stop sending any traffic from it** (ARP replies suppressed; no locally-originated VIP-source traffic). This is safe because the new master owns and GARPs the VIP; the demoting node only forwards.
- The VIP address is **removed only after the migration completes** (hold ends → SLAVE). Removing it earlier would drop the connected route and cause the demoting master to discard stray traffic it could otherwise forward to the new master.
- Local delivery to the VIP IP on the demoting node is intentionally impossible during the hold (no ARP reply), even though the address is still present; only forwarding is intended.

### Inbound from internet and source filtering (rp_filter)

If WAN ingress continues to hit the demoting node while its best route to the packet source points out the fabric (asymmetric path), strict reverse-path filtering can drop packets.

- `apply.disable_rp_filter` (default **on**): reconciles rp_filter on managed interfaces and `all`/`default` to `0` so asymmetric forwarding during takeover is permitted. Set to `false` to disable this management for environments that require strict rp_filter.
- Tradeoff: disabling rp_filter weakens anti-spoofing; prefer scoping and firewall controls on the fabric/WAN edges. Sysctl management is idempotent and reconciled like existing IPv6 sysctl handling.

## VIP ARP behavior during demotion

Problem: after VIP ownership moves, stale ARP/cache or L2 flooding may still deliver frames for VIP IPs to the demoting node. The demoting node still holds the VIP address during the hold (so it can forward), but it must not claim the VIP (no ARP replies) and must not originate traffic from it, while still forwarding legitimate stray IP packets it receives toward the new master.

Mechanism (while the demoting hold is steering):
- **Keep the VIP address assigned** throughout the hold; only remove it when the hold completes and the node transitions to SLAVE.
- **Suppress ARP replies for VIP addresses** on VIP interfaces on the demoting node (scoped nftables rules dropping replies for the configured VIP target addresses). IPv4 forwarding of received packets is not suppressed.
- **Drop locally-originated traffic from VIP sources** during the hold.
- Keep forwarding and fabric routes active; per-VIP-subnet split routes via the new master steer stray traffic as described above.
- Remove suppression (and then the VIP addresses) when the hold completes/is aborted or steering is no longer active.

Constraints: requires nft/netlink capabilities and careful rule scoping (only VIP IPs, only while demoting/steering). Must not interfere with the new master’s GARP/ownership.

## NAT / masquerading considerations

**Principle:** the node that owns external/VIP identity and the authoritative flow state should perform NAT. During takeover, the **demoting master should forward packets as-is**; the **new master should handle SNAT/DNAT/masquerade**.

Why:
- If the demoting master NATs, return traffic must come back to it and state diverges from conntrack sync expectations.
- Conntrack sync typically replicates original/reply tuples; rewriting on a node that is giving up ownership risks inconsistent translations, missed reverse matches, and leaks after handoff.

Recommended policy during demoting hold:
- Conntrack must stay **enabled on the new master's sync/traffic interface**: steered traffic
  arrives there and NAT runs there; a NOTRACK on the new master's fabric ingress would mean no
  conntrack state and no masquerade for steered flows. The daemon's own takeover NOTRACK is
  already scoped correctly — it is active only on the demoting node while steering. Guardrail:
  do not deploy the platform-firewall raw NOTRACK drop-in (SEAMLESS_FIREWALL_HOWTO.md) on all
  nodes; keep the new master's fabric ingress tracked.
- Bypass/skip masquerade/SNAT/DNAT rules on the demoting master for flows being forwarded to the new master over fabric (scoped by interface/mark/state/routing decision as appropriate).
- Ensure forwarding path is allowed; let new master apply its normal NAT once traffic arrives there.
- After hold, demoting node becomes slave per normal isolation (`slave_isolation`, nft egress, etc.) and must not perform master NAT.

### ASCII flow diagram

Steady state (master owns VIP/WAN NAT):
```
          Internet
              |
        [WAN uplink]
              |
       +--------------+
       |   MASTER     |  NAT/MASQUERADE here (state owner)
       | VIPs + WAN   |
       +--------------+
          |        \
      LAN/VIP      fabric (sync/OSPF, no VIPs)
          |        \
       clients   [SLAVE(s)] (no VIP ownership, isolated as configured)
```

Demotion/handoff hold (seamless forwarding):
```
          Internet
              |
        [WAN uplink]
              |  (stale path / in-flight packets may still arrive)
        +-------------------+        fabric (non-VIP, routed)        +-------------------+
        |  DEMOTING MASTER  | -------------------------------------> |    NEW MASTER     |
        | - VIP addrs kept  |   forward AS-IS (no NAT rewrite)        | - VIPs added+GARP |
        |   (removed after  |   /1 or split routes via new master     | - NAT/MASQUERADE  |
        |   migration)      |                                         | - conntrack owner |
        | - ARP reply for VIP|                                        |                   |
        |   suppressed       | <------------------------------------- |                   |
        | - rp_filter relaxed|        return traffic to fabric/WAN?    +-------------------+
        +-------------------+                                                |
                  \                                                          +--> LAN/VIP clients
                   \  local delivery to old VIP IP: NO (no ARP reply)
                    \ forwarding only; asymmetric path possible
```

Notes:
- Exact return path depends on routing, WAN attachment, and whether the old master still receives uplink traffic; the goal is to forward any stray ingress to the new master until convergence.
- If conntrack is not fully synchronized, some flows may still break despite correct L3 forwarding.

## Limitations and risks

- **Not zero-drop:** promotion detection, GARP propagation, route programming, and conntrack sync are not instantaneous.
- **Conntrack/NAT gaps:** unsynced entries, helpers/expectations, TCP window/checksum edge cases, and udp timeouts can break flows.
- **Asymmetric forwarding:** relies on rp_filter relaxation and permissive forwarding/firewall rules; can weaken spoofing protection if over-broad.
- **Local services on VIP/WAN IP:** cannot be served by the demoting node during the hold (it does not answer ARP for the VIP); transit forwarding only. After the migration the VIP is removed as with any slave.
- **Dual VIP ownership window:** the demoting node keeps the VIP address assigned while the new master also owns it. This is safe only because the demoting node sends no ARP replies and no VIP-source traffic; if that suppression fails, ARP/neighbor churn can result.
- **Fabric dependence:** if the separate fabric/OSPF path is unavailable, steering/forwarding to new master fails.
- **Split-brain or dual ownership:** prevented operationally by existing cluster safety rules; misconfiguration (VIPs on fabric/OSPF iface) is rejected for this feature.
- **PMTU/ICMP:** forwarded/asymmetric paths may expose PMTU issues; ICMP errors must be routable to the correct state owner.
- **State scope:** return-traffic steering is most relevant while the demoting node can still receive stray traffic (WAN/public path or stale L2); once upstream/L2 fully converges, traffic should go directly to the new master.

## Implementation notes

- Opt-in and validated at startup/reload: at least one non-VIP `ospf.interfaces` entry (fabric must not carry VIPs); invalid config disables the behavior and reports it in status/logs.
- `apply.disable_rp_filter` (default on) reconciles rp_filter on managed/all/default interfaces.
- Steering uses additive split /1 routes via the new master's fabric nexthop during the demoting hold (the lease default route stays in place); per-VIP-subnet splits are installed where applicable.
- VIP addresses remain assigned through the hold; ARP replies for VIPs are suppressed and locally-originated VIP-source traffic is dropped (scoped nftables), then VIPs are removed at hold completion. nft rules are reconciled on state transitions.
- NAT/conntrack bypass: `apply.demote_nat_bypass_mark` (default 0) marks steered traffic (prerouting/postrouting, raw priority); `apply.demote_notrack` (default on) NOTRACKs steered traffic at prerouting so conntrack/NAT do not run on the demoting node. Chains are installed **before** the steering routes and removed **after** them. Zone-based forward policies may need cooperation (see `SEAMLESS_FIREWALL_HOWTO.md`).
- Takeover handshake (implemented): the new master verifies its local environment (public IP + default route + VIPs, no GARP), sends `takeover_prep`; the old master (in hold, steering installed) acks via `takeover_ack`; the new master GARPs only after the ack, the ack budget (`handoff_hold_ms`, min 1000 ms), or a non-steering ack. No handshake peer (dead-master failover, single-node) skips the handshake: straight to MASTER, WAN verification, then announce.
- Validation (`failover-openwrt.sh`): baseline uses only the current master's long-lived flows; post/recheck presence checks do not apply the lifetime filter; the old master's teardown events and daemon-issued reinstall DELETEs are ignored.
- Tests: unit coverage for steering/suppression/mark and config parsing; netns integration `tests/seamless-takeover-netns.sh` (root; nft checks when available). Load and WAN-ingress-under-load cases remain manual.
