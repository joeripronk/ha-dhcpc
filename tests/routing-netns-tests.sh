#!/usr/bin/env bash
set -euo pipefail

# End-to-end two-node routing test in network namespaces.
# Sets up env, starts both ha-dhcpc instances, runs checks, reports, cleans up.
# Requires root/CAP_NET_ADMIN+CAP_NET_RAW (for netns, veth, routes, raw OSPF).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT_DIR/ha-dhcpc}"
STATE_BASE="${STATE_BASE:-/tmp/ha-dhcpc-routing-ns-test-$$}"
NS1="${NS1:-hadc-r1}"
NS2="${NS2:-hadc-r2}"
V1="${V1:-r1fab}"
V2="${V2:-r2fab}"
FAB1_IP="${FAB1_IP:-10.0.0.1}"
FAB2_IP="${FAB2_IP:-10.0.0.2}"
FAB1_CIDR="${FAB1_IP}/24"
FAB2_CIDR="${FAB2_IP}/24"
VIP1_IF="${VIP1_IF:-vip1}"
VIP2_IF="${VIP2_IF:-vip2}"
DHCP1_IF="${DHCP1_IF:-dhcp1}"
DHCP2_IF="${DHCP2_IF:-dhcp2}"
VIP1_CIDR="${VIP1_CIDR:-192.168.101.1/24}"
VIP2_CIDR="${VIP2_CIDR:-192.168.102.1/24}"
VIP1_NET="${VIP1_NET:-192.168.101.0/24}"
VIP2_NET="${VIP2_NET:-192.168.102.0/24}"
WAIT_SEC="${WAIT_SEC:-45}"
PASS=0
FAIL=0
PIDS=()

log() { printf '[routing-test] %s\n' "$*"; }
pass() { PASS=$((PASS+1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL: %s\n' "$*" >&2; }

cleanup() {
    set +e
    log "cleanup"
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 0.3
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    ip link del "$V1" 2>/dev/null || true
    ip netns del "$NS1" 2>/dev/null || true
    ip netns del "$NS2" 2>/dev/null || true
    rm -rf "$STATE_BASE"
}
trap cleanup EXIT

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "[routing-test] re-executing with sudo..." >&2
    exec sudo "$0" "$@"
fi

if [[ ! -x "$BIN" ]]; then
    echo "binary not found/executable: $BIN" >&2
    exit 2
fi

mkdir -p "$STATE_BASE/$NS1" "$STATE_BASE/$NS2"

write_conf() {
    local dir="$1" self="$2" sync="$3" fab_if="$4" dhcp_if="$5" vip_if="$6" vip_cidr="$7"
    cat >"$dir/ha-dhcpc.conf" <<EOF
designated_master: $self
master_mac: "02:00:00:00:00:01"
members:
  - { id: $self, sync_address: $sync }
interface: $dhcp_if
cluster:
  port: 4227
  heartbeat_ms: 1000
  election_deadline_ms: 3000
  quorum: none
  cluster_timeout_ms: 0
  addresses:
    $vip_if: [$vip_cidr]
default_role: master
dhcp:
  retention: off
  rediscover_in_retention: false
  request_options: [1, 3, 6, 15, 28]
apply:
  routes: true
  suppress_member_dad: true
  arp_responder: false
  announce_gratuitous: false
  disable_ipv6: true
routing:
  enabled: true
  advertise:
    public_ip32: false
    vip_subnets: true
    default_route: false
  accept:
    default_route: false
ospf:
  interfaces:
    - $fab_if
ctl_socket: $dir/ctl.sock
lease_file: none
loglevel: debug
EOF
    cat >"$dir/ha-dhcpc-local.conf" <<EOF
self: $self
priority: 100
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
done
ip netns exec "$NS1" ip link add "$VIP1_IF" type dummy 2>/dev/null || true
ip netns exec "$NS2" ip link add "$VIP2_IF" type dummy 2>/dev/null || true
ip netns exec "$NS1" ip link add "$DHCP1_IF" type dummy 2>/dev/null || true
ip netns exec "$NS2" ip link add "$DHCP2_IF" type dummy 2>/dev/null || true
ip netns exec "$NS1" ip link set "$VIP1_IF" up
ip netns exec "$NS2" ip link set "$VIP2_IF" up
ip netns exec "$NS1" ip link set "$DHCP1_IF" up
ip netns exec "$NS2" ip link set "$DHCP2_IF" up
ip netns exec "$NS1" ip addr add "$FAB1_CIDR" dev "$V1"
ip netns exec "$NS2" ip addr add "$FAB2_CIDR" dev "$V2"
ip netns exec "$NS1" ip link set "$V1" up multicast on
ip netns exec "$NS2" ip link set "$V2" up multicast on

write_conf "$STATE_BASE/$NS1" node1 "$FAB1_IP" "$V1" "$DHCP1_IF" "$VIP1_IF" "$VIP1_CIDR"
write_conf "$STATE_BASE/$NS2" node2 "$FAB2_IP" "$V2" "$DHCP2_IF" "$VIP2_IF" "$VIP2_CIDR"

start_node() {
    local ns="$1" dir="$2" logf="$3"
    ip netns exec "$ns" "$BIN" \
        --conf "$dir/ha-dhcpc.conf" \
        --local-conf "$dir/ha-dhcpc-local.conf" \
        --persist "$dir/state.json" \
        >"$logf" 2>&1 &
    PIDS+=("$!")
}

log "start ha-dhcpc instances"
start_node "$NS1" "$STATE_BASE/$NS1" "$STATE_BASE/node1.log"
start_node "$NS2" "$STATE_BASE/$NS2" "$STATE_BASE/node2.log"

# wait for ctl sockets
for i in $(seq 1 "$WAIT_SEC"); do
    [[ -S "$STATE_BASE/$NS1/ctl.sock" && -S "$STATE_BASE/$NS2/ctl.sock" ]] && break
    sleep 1
done
log "waiting ${WAIT_SEC}s for OSPF convergence"
sleep "$WAIT_SEC"

ctl_json() {
    local ns="$1" conf="$2" local="$3"
    ip netns exec "$ns" "$BIN" --conf "$conf" --local-conf "$local" ctl status 2>&1 || true
}

STATUS1="$(ctl_json "$NS1" "$STATE_BASE/$NS1/ha-dhcpc.conf" "$STATE_BASE/$NS1/ha-dhcpc-local.conf")"
STATUS2="$(ctl_json "$NS2" "$STATE_BASE/$NS2/ha-dhcpc.conf" "$STATE_BASE/$NS2/ha-dhcpc-local.conf")"
ROUTE1="$(ip netns exec "$NS1" ip route 2>&1 || true)"
ROUTE2="$(ip netns exec "$NS2" ip route 2>&1 || true)"

log "--- node1 status ---"
printf '%s\n' "$STATUS1"
log "--- node2 status ---"
printf '%s\n' "$STATUS2"
log "--- node1 routes ---"
printf '%s\n' "$ROUTE1"
log "--- node2 routes ---"
printf '%s\n' "$ROUTE2"

if [[ -S "$STATE_BASE/$NS1/ctl.sock" && -S "$STATE_BASE/$NS2/ctl.sock" ]]; then
    pass "both ctl sockets present"
else
    fail "ctl sockets missing (node1=$(test -S "$STATE_BASE/$NS1/ctl.sock" && echo yes || echo no), node2=$(test -S "$STATE_BASE/$NS2/ctl.sock" && echo yes || echo no))"
fi

if printf '%s' "$STATUS1" | grep -q '"routing"'; then pass "node1 reports routing status"; else fail "node1 missing routing status"; fi
if printf '%s' "$STATUS2" | grep -q '"routing"'; then pass "node2 reports routing status"; else fail "node2 missing routing status"; fi

if printf '%s' "$STATUS1" | grep -Eq '"neighbors_2way"[[:space:]]*:[[:space:]]*[1-9]|"state"[[:space:]]*:[[:space:]]*"full"'; then
    pass "node1 sees OSPF adjacency (2way/full)"
else
    fail "node1 no OSPF adjacency observed"
fi
if printf '%s' "$STATUS2" | grep -Eq '"neighbors_2way"[[:space:]]*:[[:space:]]*[1-9]|"state"[[:space:]]*:[[:space:]]*"full"'; then
    pass "node2 sees OSPF adjacency (2way/full)"
else
    fail "node2 no OSPF adjacency observed"
fi

if printf '%s' "$ROUTE1" | grep -Fq "192.168.102.0/24"; then
    pass "node1 installed route to node2 VIP subnet"
else
    fail "node1 missing route to node2 VIP subnet ($VIP2_NET)"
fi
if printf '%s' "$ROUTE2" | grep -Fq "192.168.101.0/24"; then
    pass "node2 installed route to node1 VIP subnet"
else
    fail "node2 missing route to node1 VIP subnet ($VIP1_NET)"
fi

if printf '%s' "$STATUS1" | grep -Fq "$FAB2_IP"; then pass "node1 learned peer/fabric info for node2"; else fail "node1 missing learned peer info"; fi
if printf '%s' "$STATUS2" | grep -Fq "$FAB1_IP"; then pass "node2 learned peer/fabric info for node1"; else fail "node2 missing learned peer info"; fi

log "--- node1 log tail ---"
tail -n 80 "$STATE_BASE/node1.log" 2>&1 || true
log "--- node2 log tail ---"
tail -n 80 "$STATE_BASE/node2.log" 2>&1 || true

log "result: $PASS passed, $FAIL failed"
log "state/logs (cleaned after run): $STATE_BASE"
if [[ "$FAIL" -ne 0 ]]; then
    exit 1
fi
exit 0
