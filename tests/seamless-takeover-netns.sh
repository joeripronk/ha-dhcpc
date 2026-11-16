#!/usr/bin/env bash
set -euo pipefail

# Seamless-takeover integration test (SEAMLESS_TAKEOVER.md) in network namespaces.
# Two-node cluster on a dedicated non-VIP fabric; node1 is master (higher priority),
# node2 slave. Demoting node1 must, during the handoff hold:
#   - install additive split /1 steering routes via node2's fabric address,
#     keeping the default route untouched (no lease here: no default at all),
#     plus per-VIP-subnet splits at prefixlen+1 covering the VIP subnet,
#   - keep its VIP assigned through the hold (removed only at completion),
#   - run scoped nft scoping: VIP ARP-reply suppression, VIP-source output drop,
#     NAT-bypass mark chains (checked only when an nft CLI is available),
# and after the hold: node2 promotes (owns the VIP), node1 is a clean slave
# (no split routes, no VIP, no takeover chains). Also verifies the
# apply.disable_rp_filter reconcile (default on).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT_DIR/ha-dhcpc}"
STATE_BASE="${STATE_BASE:-/tmp/ha-dhcpc-seamless-ns-test-$$}"
NS1="${NS1:-hadc-s1}"
NS2="${NS2:-hadc-s2}"
V1="${V1:-fab1}"
V2="${V2:-fab2}"
FAB1_IP="${FAB1_IP:-10.0.0.1}"
FAB2_IP="${FAB2_IP:-10.0.0.2}"
FAB_IF="${FAB_IF:-fab0}"
FABV_IF="${FABV_IF:-fab0.11}"   # dotted VLAN name: must work in nft args (production uses br-lan.N)
DHCP_IF="${DHCP_IF:-dhcp0}"
VIP_IF="${VIP_IF:-vip0}"
VIP_CIDR="${VIP_CIDR:-192.168.101.1/24}"
VIP_IP="${VIP_IP:-192.168.101.1}"
NAT_MARK="${NAT_MARK:-0x2e05}"
NAT_MARK_DEC=11781
WAIT_SEC="${WAIT_SEC:-45}"
NFT="${NFT:-}"
PASS=0
FAIL=0
SKIP=0
PIDS=()

log() { printf '[seamless-test] %s\n' "$*"; }
pass() { PASS=$((PASS+1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL: %s\n' "$*" >&2; }
skip() { SKIP=$((SKIP+1)); printf 'SKIP: %s\n' "$*"; }

cleanup() {
    set +e
    log "cleanup"
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 0.3
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    ip link del "$V1" 2>/dev/null || true
    ip netns del "$NS1" 2>/dev/null || true
    ip netns del "$NS2" 2>/dev/null || true
    [[ "${KEEP_STATE:-0}" == 1 ]] || rm -rf "$STATE_BASE"
}
trap cleanup EXIT

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "[seamless-test] re-executing with sudo..." >&2
    exec sudo "$0" "$@"
fi

if [[ ! -x "$BIN" ]]; then
    echo "binary not found/executable: $BIN" >&2
    exit 2
fi
NFT="$(command -v nft || true)"

mkdir -p "$STATE_BASE/$NS1" "$STATE_BASE/$NS2"

write_shared_conf() {
    local dir="$1"
    cat >"$dir/ha-dhcpc.conf" <<EOF
designated_master: node1
master_mac: "02:00:00:00:00:01"
members:
  - { id: node1, sync_address: $FAB1_IP, priority: 200 }
  - { id: node2, sync_address: $FAB2_IP, priority: 100 }
interface: $DHCP_IF
cluster:
  port: 4231
  heartbeat_ms: 1000
  election_deadline_ms: 3000
  quorum: none
  cluster_timeout_ms: 0
  addresses:
    $VIP_IF: ["$VIP_CIDR"]
default_role: master
dhcp:
  retention: off
  rediscover_in_retention: false
  request_options: [1, 3, 6, 15, 28]
apply:
  routes: true
  handoff_hold_ms: 3000
  slave_isolation: nft
  slave_sync_wan: true
  demote_route_via_new_master: true
  demote_nat_bypass_mark: $NAT_MARK_DEC
  demote_notrack: true
  announce_gratuitous: true
  disable_ipv6: true
routing:
  enabled: true
  advertise:
    public_ip32: false
    vip_subnets: false
    default_route: false
  accept:
    default_route: false
ospf:
  interfaces:
    - $FAB_IF
    - $FABV_IF
lease_file: none
loglevel: debug
EOF
}

log "setup namespaces and links"
ip netns add "$NS1"
ip netns add "$NS2"
ip link add "$V1" type veth peer name "$V2"
ip link set "$V1" netns "$NS1"
ip link set "$V2" netns "$NS2"

for ns in "$NS1" "$NS2"; do
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link add "$VIP_IF" type dummy 2>/dev/null || true
    ip netns exec "$ns" ip link add "$DHCP_IF" type dummy 2>/dev/null || true
    ip netns exec "$ns" ip link add "$FABV_IF" type dummy 2>/dev/null || true
    ip netns exec "$ns" ip link set "$VIP_IF" up
    ip netns exec "$ns" ip link set "$DHCP_IF" up
    ip netns exec "$ns" ip link set "$FABV_IF" up
    # rp_filter presets the daemon must bring down (apply.disable_rp_filter default on)
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1 2>/dev/null || true
    for i in "$FAB_IF" "$FABV_IF" "$VIP_IF" "$DHCP_IF"; do
        ip netns exec "$ns" sysctl -qw "net.ipv4.conf.$i.rp_filter=1" 2>/dev/null || true
    done
done
ip netns exec "$NS1" ip addr add "$FAB1_IP/24" dev "$V1"
ip netns exec "$NS2" ip addr add "$FAB2_IP/24" dev "$V2"
ip netns exec "$NS1" ip link set "$V1" up multicast on
ip netns exec "$NS2" ip link set "$V2" up multicast on
# name the fabric links fab0 inside the namespaces (config refers to fab0)
ip netns exec "$NS1" ip link set "$V1" name "$FAB_IF"
ip netns exec "$NS2" ip link set "$V2" name "$FAB_IF"

# The shared document must be byte-identical cluster-wide (peer trust is
# digest-based); per-node paths belong in the local overlay.
write_shared_conf "$STATE_BASE/$NS1"
cp "$STATE_BASE/$NS1/ha-dhcpc.conf" "$STATE_BASE/$NS2/ha-dhcpc.conf"
printf 'self: node1\nctl_socket: %s\n' "$STATE_BASE/$NS1/ctl.sock" \
    >"$STATE_BASE/$NS1/ha-dhcpc-local.conf"
# node2 must not bootstrap-adopt master at startup (that would settle dual-master);
# it follows the seeded designated_master instead.
printf 'self: node2\ndefault_role: slave\nctl_socket: %s\n' "$STATE_BASE/$NS2/ctl.sock" \
    >"$STATE_BASE/$NS2/ha-dhcpc-local.conf"

start_node() {
    local ns="$1" dir="$2" logf="$3"
    ip netns exec "$ns" sh -c "\"$BIN\" --conf '$dir/ha-dhcpc.conf' --local-conf '$dir/ha-dhcpc-local.conf' --persist '$dir/state.json' >> '$logf' 2>&1; echo \"[test] daemon exited rc=\$?\" >> '$logf'" &
    PIDS+=("$!")
}

log "start ha-dhcpc instances"
start_node "$NS1" "$STATE_BASE/$NS1" "$STATE_BASE/node1.log"
start_node "$NS2" "$STATE_BASE/$NS2" "$STATE_BASE/node2.log"

ctl_json() {
    local ns="$1" conf="$2" local="$3"
    ip netns exec "$ns" "$BIN" --conf "$conf" --local-conf "$local" ctl status 2>&1 || true
}

role_of() {
    local ns="$1" dir="$2"
    ctl_json "$ns" "$dir/ha-dhcpc.conf" "$dir/ha-dhcpc-local.conf" | \
        sed -n 's/^{"role":"\([a-z]*\)".*/\1/p' | head -1
}

poll_role() {
    local ns="$1" dir="$2" want="$3" secs="$4" i
    for ((i = 0; i < secs * 2; i++)); do
        [[ "$(role_of "$ns" "$dir")" == "$want" ]] && return 0
        sleep 0.5
    done
    return 1
}

log "waiting for election: node1 master, node2 slave"
if poll_role "$NS1" "$STATE_BASE/$NS1" master "$WAIT_SEC" && \
   poll_role "$NS2" "$STATE_BASE/$NS2" slave "$WAIT_SEC"; then
    pass "election converged (node1 master, node2 slave)"
else
    fail "election did not converge in ${WAIT_SEC}s"
    log "--- node1 log tail ---"; tail -n 30 "$STATE_BASE/node1.log" 2>/dev/null || true
    log "--- node2 log tail ---"; tail -n 30 "$STATE_BASE/node2.log" 2>/dev/null || true
fi

if [[ "$(role_of "$NS1" "$STATE_BASE/$NS1")" == master ]]; then
    if ip netns exec "$NS1" ip -4 addr show dev "$VIP_IF" | grep -q "$VIP_IP"; then
        pass "node1 (master) holds the VIP before demotion"
    else
        fail "node1 master does not hold the VIP before demotion"
    fi
fi

rp_ok=1
for ns in "$NS1" "$NS2"; do
    for scope in all default "$FAB_IF" "$VIP_IF" "$DHCP_IF"; do
        v="$(ip netns exec "$ns" sysctl -n "net.ipv4.conf.$scope.rp_filter" 2>/dev/null || echo x)"
        [[ "$v" == "0" ]] || { rp_ok=0; log "rp_filter $ns/$scope = $v (want 0)"; }
    done
done
if [[ $rp_ok == 1 ]]; then
    pass "apply.disable_rp_filter reconciled all/default/managed interfaces to 0"
else
    fail "rp_filter reconcile incomplete"
fi

log "waiting until node1 sees node2 alive (peer liveness must be established before demote)"
alive_seen=0
for ((i = 0; i < 60; i++)); do
    s="$(ctl_json "$NS1" "$STATE_BASE/$NS1/ha-dhcpc.conf" "$STATE_BASE/$NS1/ha-dhcpc-local.conf")"
    printf '%s' "$s" | grep -q '"id":"node2"[^}]*"alive":true' && { alive_seen=1; break; }
    sleep 0.5
done
if [[ $alive_seen == 1 ]]; then
    pass "node1 sees node2 as a live peer before demote"
else
    fail "node1 never marked node2 alive in ${WAIT_SEC}s"
fi

log "demoting node1 (steered handoff hold to node2)"
ip netns exec "$NS1" "$BIN" --conf "$STATE_BASE/$NS1/ha-dhcpc.conf" \
    --local-conf "$STATE_BASE/$NS1/ha-dhcpc-local.conf" ctl demote 2>&1 | head -2 || true

hold_seen=0
for ((i = 0; i < 60; i++)); do
    r="$(ip netns exec "$NS1" ip -4 route show table main 2>/dev/null || true)"
    if printf '%s' "$r" | grep -q "^0\.0\.0\.0/1 via $FAB2_IP" && \
       printf '%s' "$r" | grep -q "^128\.0\.0\.0/1 via $FAB2_IP"; then
        hold_seen=1
        break
    fi
    sleep 0.2
done
if [[ $hold_seen == 1 ]]; then
    pass "split /1 steering routes via the new master fabric nexthop during the hold"
else
    fail "split /1 steering routes never appeared during the hold"
fi

if [[ $hold_seen == 1 ]]; then
    sleep 1
    r="$(ip netns exec "$NS1" ip -4 route show table main 2>/dev/null || true)"
    printf '%s' "$r" | grep -q "^192\.168\.101\.0/25 via $FAB2_IP" &&
        pass "VIP-subnet split route (lower half) steered during the hold" ||
        fail "VIP-subnet lower-half split route missing during the hold"
    printf '%s' "$r" | grep -q "^192\.168\.101\.128/25 via $FAB2_IP" &&
        pass "VIP-subnet split route (upper half) steered during the hold" ||
        fail "VIP-subnet upper-half split route missing during the hold"
    if ip netns exec "$NS1" ip -4 addr show dev "$VIP_IF" | grep -q "$VIP_IP"; then
        pass "node1 keeps the VIP assigned during the hold"
    else
        fail "node1 dropped the VIP during the hold (must persist until completion)"
    fi
    if [[ -n "$NFT" ]]; then
        netdev_rules="$(ip netns exec "$NS1" "$NFT" list table netdev ha_dhcpc 2>/dev/null || true)"
        ip_rules="$(ip netns exec "$NS1" "$NFT" list table ip ha_dhcpc_tk 2>/dev/null || true)"
        printf '%s' "$netdev_rules" | grep -q "arp operation reply arp saddr ip $VIP_IP drop" &&
            pass "ARP-reply suppression rule for the VIP active on node1" ||
            fail "ARP-reply suppression rule missing on node1"
        printf '%s' "$ip_rules" | grep -q "ip saddr $VIP_IP drop" &&
            pass "locally-originated VIP-source traffic dropped on node1" ||
            fail "VIP-source output drop rule missing on node1"
        printf '%s' "$ip_rules" | grep -q "meta mark set 0x00002e05" &&
            pass "NAT-bypass mark chains active on node1" ||
            fail "NAT-bypass mark rules missing on node1"
        printf '%s' "$ip_rules" | grep -q 'fib daddr . iif oifname "fab0" notrack' &&
            pass "FIB-based NOTRACK rule active for the fabric egress" ||
            fail "FIB-based NOTRACK rule missing for the fabric egress"
        printf '%s' "$ip_rules" | grep -q 'iifname "fab0" notrack' &&
            pass "NOTRACK rule active for the fabric return direction" ||
            fail "NOTRACK rule missing for the fabric return direction"
        printf '%s' "$ip_rules" | grep -q 'iif oifname "fab0.11" notrack' &&
            pass "NOTRACK rules installed for the dotted VLAN fabric name" ||
            fail "NOTRACK rules missing for the dotted VLAN fabric name"
    else
        skip "nft CLI unavailable on this host: ARP-suppression/mark chain checks skipped"
    fi
fi

log "waiting for node2 promotion and node1 hold completion (within the 60s handoff cooldown)"
ok_node2="" ok_node1=""
for ((i = 0; i < 50; i++)); do
    [[ "$(role_of "$NS2" "$STATE_BASE/$NS2")" == master ]] && ok_node2=1
    [[ "$(role_of "$NS1" "$STATE_BASE/$NS1")" == slave ]] && ok_node1=1
    [[ -n "$ok_node2" && -n "$ok_node1" ]] && break
    sleep 0.5
done
[[ -n "$ok_node2" ]] && pass "node2 promoted to master" || fail "node2 never became master"
[[ -n "$ok_node1" ]] && pass "node1 completed the hold as slave" || fail "node1 never became slave"

if [[ -n "$ok_node2" && -n "$ok_node1" ]]; then
    r1="$(ip netns exec "$NS1" ip -4 route show table main 2>/dev/null || true)"
    if ! printf '%s' "$r1" | grep -q "via $FAB2_IP"; then
        pass "all steering routes (split /1s and VIP splits) removed after the hold"
    else
        fail "steering routes lingered after the hold"
    fi
    if ip netns exec "$NS1" ip -4 addr show dev "$VIP_IF" | grep -q "$VIP_IP"; then
        fail "node1 still holds the VIP after the hold"
    else
        pass "VIP removed from node1 at hold completion"
    fi
    if ip netns exec "$NS2" ip -4 addr show dev "$VIP_IF" | grep -q "$VIP_IP"; then
        pass "node2 (new master) owns the VIP"
    else
        fail "node2 did not take over the VIP"
    fi
    if [[ -n "$NFT" ]]; then
        netdev_chains="$(ip netns exec "$NS1" "$NFT" -n list table netdev ha_dhcpc 2>/dev/null || true)"
        ip_chains="$(ip netns exec "$NS1" "$NFT" -n list table ip ha_dhcpc_tk 2>/dev/null || true)"
        printf '%s' "$netdev_chains" | grep -q "ar_${VIP_IF}" &&
            fail "ARP-suppression chain lingered on node1" ||
            pass "ARP-suppression chain cleaned up on node1"
        printf '%s' "$ip_chains" | grep -q . &&
            fail "takeover ip-family table lingered on node1" ||
            pass "takeover ip-family scoping cleaned up on node1"
    fi
fi

log "result: $PASS passed, $FAIL failed, $SKIP skipped"
[[ $FAIL -eq 0 ]] || exit 1
exit 0
