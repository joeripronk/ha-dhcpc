# SEAMLESS_TAKEOVER.md progress

Plan file: `SEAMLESS_TAKEOVER.md`. Integration test: `tests/seamless-takeover-netns.sh`
(netns, needs root; 21 checks, all passing). Firewall cooperation: `SEAMLESS_FIREWALL_HOWTO.md`.
Unit tests: `make test`.

## Steps

- [x] 1. Base opt-in `apply.demote_route_via_new_master`: config, startup/reload validation
      (slave_sync_wan + non-VIP OSPF fabric), `ctl status` exposure. (done)
- [x] 2. `apply.disable_rp_filter` (default on): sysctl reconcile on managed interfaces
      (all/default/DHCP/VIP/OSPF ifaces, idempotent like IPv6 handling). (done)
- [x] 3. Split /1 steering during demoting hold: additive `0.0.0.0/1` + `128.0.0.0/1`
      routes via the new master's fabric nexthop, explicit cleanup, drift-verified.
      Replaces the default_via override as the steering mechanism (the default route
      stays on the lease gateway; LPM does the steering). (done)
- [x] 4. VIP hold behavior: VIP addresses stay assigned throughout the demoting hold
      (removed only at hold completion); ARP *replies* for VIP addresses suppressed via
      per-VIP-interface netdev egress chains; locally-originated VIP-source traffic
      dropped via an ip-family output chain; active only while demoting-steering,
      reconciled on transitions. (done)
- [x] 5. NAT-bypass policy hook: `apply.demote_nat_bypass_mark` (default 0 = off) marks
      steered packets in an own ip-family table at prerouting (-300, before conntrack/nat)
      and postrouting (-300); `apply.demote_notrack` (default on) additionally NOTRACKs
      steered traffic at prerouting so conntrack/NAT never run on this node. NOTRACK must
      live at prerouting (state is created before the forward hook, SNAT after it), so a
      NOTRACK rule on the outgoing interface alone would bypass nothing; zone-based
      firewalls need the forward-accept cooperation from `SEAMLESS_FIREWALL_HOWTO.md`. (done)
- [x] 6. Tests: unit tests for desired-state computation (steering/suppression/mark)
      and config parsing; netns integration test (two-node handoff incl. nft checks).
      Load/WAN-ingress-under-load scenarios remain manual. (done)
- [x] 7. Code review + docs touch-up in SEAMLESS_TAKEOVER.md status lines. (done)

## Notes / decisions

- Steering mechanism: additive split /1s (longest-prefix match beats the kept default
  route); the default route itself stays on the lease gateway/WAN.
- VIP ARP suppression scope: only ARP replies whose sender IP is a configured VIP, only
  on VIP interfaces, only while the demoting hold with steering is active; the new
  master's GARPs (requests) must pass untouched. nft canonical syntax used
  (`arp operation reply arp saddr ip <vip> drop`, `meta mark set`).
- VIP-source block: ip-family output-hook drop for VIP sources (kills local services on
  VIP during hold, as planned).
- VIP-subnet splits implemented: per cluster address with a CIDR prefix (<= /31), the
  two sub-prefixes at prefixlen+1 via the steering nexthop, added on the steering
  transition and drift-verified; host prefixes and subnets containing the nexthop are
  skipped; packets to the VIP address itself still hit the kernel /32 local route and
  rely on the nft scoping chains (ARP suppression/output drop) plus the new master's
  GARPs.
- nft rule reconciliation runs only on state transitions (enter/leave steering hold);
  nft chains are not drift-verified (consistent with the slave egress block).
- NOTRACK: mark rule first, then the NOTRACK verdict (the mark survives untracking and
  gives zone-based firewalls their match). With NOTRACK on, plain-accept forward policies
  need no cooperation at all; fw4-style zone firewalls need the forward-accept drop-in
  from `SEAMLESS_FIREWALL_HOWTO.md`, otherwise steered packets fall to the default
  forward policy. `demote_notrack` defaults to on (only ever active while the opt-in
  feature steers), matching the plan's "forward as-is, no NAT state" principle.
- Bug found via the integration test and fixed: the ctl server writes the response in
  two write() calls; a ctl client that reads its reply and exits could close the socket
  before the second write, and the default SIGPIPE disposition killed the daemon.
  The daemon now ignores SIGPIPE.
- Integration test requires root (netns); nft checks run only when an nft CLI is
  available on the test host. Daemon log files are block-buffered; the test reads live
  kernel state (routes/addresses/sysctl/nft) instead of logs.
