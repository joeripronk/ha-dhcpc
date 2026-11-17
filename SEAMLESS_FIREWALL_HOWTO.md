# Seamless takeover: firewall cooperation howto

Companion to `SEAMLESS_TAKEOVER.md`.

During a steered demoting hold the old master keeps VIPs assigned (ARP replies
suppressed), installs split /1 steering routes via the new master's fabric
nexthop, relaxes rp_filter, and forwards everything as-is: **conntrack and NAT
must not run on the demoting node** for steered traffic. With
`apply.demote_notrack` (default on) the daemon manages this itself in its own
nftables table `ha_dhcpc_tk` (ip family), chain `pre` at prerouting priority
-300 (raw, **before** the firewall's conntrack/nat hooks):

- `fib daddr . iif oifname "<fabric>" notrack` — untracks exactly the steered
  transit (FIB lookup with `iif` in the key so policy routing is respected);
- `iifname "<fabric>" notrack` — the return direction entering the fabric.

## Why NOTRACK on the outgoing interface alone is not enough

Conntrack state for forwarded packets is created at **prerouting** (before the
forward hook) and SNAT/masquerade runs at **postrouting** (after it). A NOTRACK
rule placed only on the outgoing interface (or in the forward chain) sees
packets that were already tracked — and already NAT-rewritten — so it bypasses
nothing. NOTRACK must sit in prerouting at raw priority, which is why the
daemon's chain lives there and why the fib lookup (routing already decided by
the time prerouting finishes for the *return* direction; for the forward
direction the fib expression performs the lookup itself) is the precise match.

## What the firewall must do

Untracked packets bypass conntrack, so any conntrack/state-based forward policy
will not match them and they fall to the forward chain's default policy. The
forward path must explicitly accept untracked traffic (optionally scoped to the
fabric interfaces). Example (plain nftables; on fw4 put the equivalent rule in a
`custom_forward` include):

```nft
chain raw_prerouting {
    type filter hook prerouting priority raw; policy accept;

    # Perform a FIB lookup to check if the packet will exit via "eth1"
    # Include "iif" in the tuple so policy-based routing (ip rules) is respected
    fib daddr . iif oifname "eth1" notrack

    # Also disable tracking for the return traffic entering "eth1"
    iifname "eth1" notrack
}

chain forward {
    type filter hook forward priority filter; policy drop;

    # Allow established/related stateful traffic
    ct state established,related accept

    # Explicitly accept untracked packets (since notrack bypasses conntrack)
    ct state untracked accept

    # Optional: scope untracked acceptance strictly to the interfaces
    # ct state untracked oifname "eth1" accept
    # ct state untracked iifname "eth1" accept
}
```

If your forward policy already accepts the steered paths unconditionally, no
firewall cooperation is needed at all — the daemon's prerouting NOTRACK alone
suffices.

## Notes

- The mark (`apply.demote_nat_bypass_mark`, default 0 = off) is optional with
  NOTRACK on: use it only to scope the firewall's accept/NAT-return rules per
  mark. When configured, the daemon sets it in its prerouting chain **before**
  the NOTRACK verdicts (packet marks survive untracking) and at postrouting.
- With `demote_notrack: false` (pure mark cooperation), the firewall must
  instead `return` on the mark before its NAT hooks (prerouting DNAT and
  postrouting SNAT/masquerade) and accept marked packets in forward.
- NOTRACK means the demoting node has no conntrack state for steered flows;
  the new master applies all NAT once traffic arrives there. Conntrack sync
  health (helpers/expectations, replication lag) still limits how many existing
  flows survive the handoff.
- Verified end-to-end by `tests/seamless-takeover-netns.sh` (netns, root;
  checks split /1s, VIP hold, ARP suppression, output drop, the prerouting
  fib/NOTRACK rules and cleanup at hold completion).
