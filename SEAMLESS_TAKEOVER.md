# Seamless takeover plan (demote → route via new master)

## Goal

Make master demotion/handoff as seamless as possible by keeping the demoting node forwarding traffic to the newly promoted master over a separate cluster/OSPF fabric, instead of blackholing or hairpinning flows during the ownership transition.

Target behavior (when explicitly enabled and prerequisites are met):
- **VIP ownership moves immediately** (new master adds VIPs and GARPs), but the **old master keeps the VIP addresses assigned during the hold** and simply stops answering/originating for them: **no ARP replies and no locally-originated traffic from VIP sources**. The VIP addresses are removed only **after the migration completes** (hold ends → SLAVE). As long as the demoting node neither replies to ARP nor sends traffic from the VIPs, temporarily holding both copies is safe enough, and it prevents the demoting master from dropping traffic it can still forward to the new master.
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
  - `apply.slave_sync_wan: true`
  - at least one `ospf.interfaces` entry
  - every `ospf.interfaces` entry must **not** be an interface that carries `cluster.addresses` (VIPs)
- Invalid configuration: behavior disabled, runtime state marked invalid, and an error logged (`demote_route_via_new_master(...): invalid configuration: ...; behaviour disabled`).
- Status: exposed via `ctl status` as `demote_route_via_new_master.{configured,active,invalid,reason}`.

## Prerequisites

1. **Separate non-VIP fabric** for cluster sync/OSPF/routing (e.g. dedicated VLAN/interface). `sync_address` peers and `ospf.interfaces` must remain reachable when VIP interfaces/addresses change. An interface used for OSPF in this mode must not host VIP/cluster addresses.
2. **L3 forwarding enabled** on the demoting node for the relevant families/paths; firewall must permit forwarding between WAN/VIP-facing ingress and the fabric toward the new master during the hold.
3. **Conntrack/state replication** (`conntrack_sync`) healthy enough for the new master to continue existing flows where applicable; helper/expectation coverage and replication lag are limiting factors.
4. **Timely promotion** of the new master (VIP add + GARP + route/neighbor readiness) within/around `apply.handoff_hold_ms`.

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

Plan:
- Add `apply.disable_rp_filter` (default **enabled behavior**: disable rp_filter on managed interfaces) to set `net.ipv4.conf.all.rp_filter=0` and/or per-interface `rp_filter=0` (and `default`) as appropriate for managed paths so asymmetric forwarding during takeover is permitted.
- Provide config to disable this management for environments that require strict rp_filter.
- Document security/anti-spoofing tradeoff; prefer scoping and firewall controls on the fabric/WAN edges.

(Implementation note: sysctl management should be idempotent and reconciled like existing IPv6 sysctl handling, without clobbering unrelated interfaces unnecessarily unless explicitly configured.)

## VIP ARP behavior during demotion (planned)

Problem: after VIP ownership moves, stale ARP/cache or L2 flooding may still deliver frames for VIP IPs to the demoting node. The demoting node still holds the VIP address during the hold (so it can forward), but it must not claim the VIP (no ARP replies) and must not originate traffic from it, while still forwarding legitimate stray IP packets it receives toward the new master.

Planned mechanism (during demoting hold / while steering active):
- **Keep the VIP address assigned** throughout the hold; only remove it when the hold completes and the node transitions to SLAVE.
- **Suppress ARP replies for VIP addresses** on VIP interfaces on the demoting node (e.g. nftables arp/netdev ingress/egress rules dropping ARP replies for specific target protocol addresses, or equivalent netlink/neighbor policy). Do not suppress IPv4 forwarding of already-received packets.
- **Do not send locally-originated traffic from VIP sources** during the hold.
- Keep forwarding and fabric routes active; optionally install per-VIP /32 (or split) routes via the new master to ensure forwarded delivery.
- Remove suppression (and then the VIP addresses) when hold completes/is aborted or when the node is no longer in the demoting-forwarding state.

Constraints: requires nft/netlink capabilities and careful rule scoping (only VIP IPs, only while demoting). Must not interfere with the new master’s GARP/ownership.

## NAT / masquerading considerations

**Principle:** the node that owns external/VIP identity and the authoritative flow state should perform NAT. During takeover, the **demoting master should forward packets as-is**; the **new master should handle SNAT/DNAT/masquerade**.

Why:
- If the demoting master NATs, return traffic must come back to it and state diverges from conntrack sync expectations.
- Conntrack sync typically replicates original/reply tuples; rewriting on a node that is giving up ownership risks inconsistent translations, missed reverse matches, and leaks after handoff.

Recommended policy during demoting hold:
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

Demotion/handoff hold (seamless forwarding, planned/partial today):
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

## Rollout / implementation steps

Progress is tracked in `SEAMLESS_TODO.md`; integration test `tests/seamless-takeover-netns.sh`.

1. Keep/require separate non-VIP fabric and validate config (done for base opt-in).
2. Add `apply.disable_rp_filter` (default on) and reconcile sysctls on managed interfaces. (done)
3. Add optional split /1 (and/or VIP split/host) steering during demoting hold, with explicit
   cleanup. Implemented as split /1 only (VIP split routes remain the optional/advanced part);
   the split /1s replace the earlier default_via override as the steering mechanism. (done)
4. Keep VIP addresses assigned throughout the demoting hold (no removal at demote); add temporary VIP ARP-reply suppression and no VIP-source traffic during the hold (nft/netlink), scoped and auditable; remove the VIPs only when the hold completes and the node becomes SLAVE. (done)
5. Add NAT-bypass safeguards/policy hooks for demoting-forwarding state (platform/firewall
   integration): `apply.demote_nat_bypass_mark` marks steered ingress (prerouting) and fabric
   egress (postrouting) at raw priority so the platform firewall can `return` on the mark;
   `apply.demote_notrack` (default on) NOTRACKs steered traffic at prerouting so conntrack/NAT
   never run on the demoting node (NOTRACK on the outgoing interface alone would not bypass
   anything). Cooperation snippets: `SEAMLESS_FIREWALL_HOWTO.md`. (done)
6. Integration tests: controlled handoff under load, rp_filter modes, conntrack sync,
   WAN-ingress-during-hold cases. Implemented as a netns two-node handoff test (unit tests +
   16 netns checks incl. nft); load/WAN-ingress scenarios remain manual. (done)
