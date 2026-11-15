#!/usr/bin/env bash
set -euo pipefail

# Dedicated netns repro for TCP port-3724 stall after master promote.
# Derived from captures/handover-20261115-085955 (flow 172.16.202.40:58513
# <-> 37.244.61.208:3724, public/NAT 143.177.173.8:58513).
#
# Shows:
#   - migrate_ok:   conntrack+NAT tuple present on promoted router -> flow continues
#   - migrate_fail: tuple missing on promoted router -> client replies forwarded
#                   without SNAT (private src leaks on WAN), server retransmits to
#                   public IP, flow stalls (matches captured failure)
#
# Requires root/CAP_NET_ADMIN, and: ip, iptables, conntrack, python3, tcpdump.
# Run: sudo ./tests/conntrack-handover-3724-netns.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAP_DIR="${CAP_DIR:-$ROOT_DIR/captures/handover-20261115-085955}"
NS_C="ho3724c"
NS_W="ho3724w"
NS_RA="ho3724ra"
NS_RB="ho3724rb"
OUT="${OUT:-/tmp/ha-dhcpc-3724-handover-$$}"
PASS=0
FAIL=0

log(){ printf '[3724-netns] %s\n' "$*"; }
ok(){ PASS=$((PASS+1)); printf 'PASS: %s\n' "$*"; }
bad(){ FAIL=$((FAIL+1)); printf 'FAIL: %s\n' "$*" >&2; }

need(){ command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 2; }; }

cleanup(){
  set +e
  for p in ${PIDS:-}; do kill "$p" 2>/dev/null || true; done
  sleep 0.2
  for p in ${PIDS:-}; do kill -9 "$p" 2>/dev/null || true; done
  for ns in "$NS_C" "$NS_W" "$NS_RA" "$NS_RB"; do ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  exec sudo CAP_DIR="$CAP_DIR" OUT="$OUT" "$0" "$@"
fi
for c in ip iptables conntrack python3 tcpdump; do need "$c"; done

mkdir -p "$OUT"
PIDS=""
cleanup >/dev/null 2>&1 || true

log "setup namespaces/links"
for ns in "$NS_C" "$NS_W" "$NS_RA" "$NS_RB"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done

# client LAN links to RA and RB (handover target)
ip link add veth-c-a type veth peer name veth-a-lan
ip link add veth-c-b type veth peer name veth-b-lan
ip link add veth-a-wan type veth peer name veth-w-a
ip link add veth-b-wan type veth peer name veth-w-b
ip link set veth-c-a netns "$NS_C"; ip link set veth-c-b netns "$NS_C"
ip link set veth-a-lan netns "$NS_RA"; ip link set veth-a-wan netns "$NS_RA"
ip link set veth-b-lan netns "$NS_RB"; ip link set veth-b-wan netns "$NS_RB"
ip link set veth-w-a netns "$NS_W"; ip link set veth-w-b netns "$NS_W"

# addresses mirror captured flow (public on router WAN; WAN enforces no private leak)
ip -n "$NS_C" addr add 172.16.202.40/24 dev veth-c-a
ip -n "$NS_C" link set veth-c-a up; ip -n "$NS_C" link set veth-c-b up
ip -n "$NS_RA" addr add 172.16.202.1/24 dev veth-a-lan
ip -n "$NS_RA" addr add 143.177.173.8/24 dev veth-a-wan
ip -n "$NS_RB" addr add 172.16.202.1/24 dev veth-b-lan
ip -n "$NS_RB" addr add 143.177.173.8/24 dev veth-b-wan
for ns_if in "$NS_RA:veth-a-lan" "$NS_RA:veth-a-wan" "$NS_RB:veth-b-lan" "$NS_RB:veth-b-wan"; do
  ns=${ns_if%%:*}; ifc=${ns_if##*:}; ip -n "$ns" link set "$ifc" up
done
ip -n "$NS_W" addr add 143.177.173.1/24 dev veth-w-a
ip -n "$NS_W" addr add 143.177.173.1/24 dev veth-w-b
ip -n "$NS_W" addr add 37.244.61.208/32 dev lo
ip -n "$NS_W" link set veth-w-a up; ip -n "$NS_W" link set veth-w-b up
ip -n "$NS_C" route replace default via 172.16.202.1 dev veth-c-a
ip -n "$NS_RA" route replace default via 143.177.173.1 dev veth-a-wan
ip -n "$NS_RB" route replace default via 143.177.173.1 dev veth-b-wan
ip -n "$NS_W" route replace 143.177.173.8/32 dev veth-w-a
# emulate internet: private source must not be delivered on WAN side
ip netns exec "$NS_W" iptables -F FORWARD 2>/dev/null || true
ip netns exec "$NS_W" iptables -A FORWARD -s 172.16.202.0/24 -j DROP
ip netns exec "$NS_W" iptables -A FORWARD -d 172.16.202.0/24 -j DROP
ip netns exec "$NS_W" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$NS_W" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null || true
for i in $(ip -n "$NS_W" -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do ip netns exec "$NS_W" sysctl -qw net.ipv4.conf.$i.rp_filter=0 2>/dev/null || true; done

for r in "$NS_RA" "$NS_RB"; do
  ip netns exec "$r" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$r" iptables -t nat -F; ip netns exec "$r" iptables -F FORWARD
  wan_if=$(ip -n "$r" -o link show | awk -F': ' '/veth-.*-wan/{print $2; exit}' | cut -d@ -f1)
  lan_if=$(ip -n "$r" -o link show | awk -F': ' '/veth-.*-lan/{print $2; exit}' | cut -d@ -f1)
  ip netns exec "$r" iptables -t nat -A POSTROUTING -s 172.16.202.0/24 -o "$wan_if" -j SNAT --to-source 143.177.173.8
  ip netns exec "$r" iptables -A FORWARD -i "$lan_if" -o "$wan_if" -j ACCEPT
  ip netns exec "$r" iptables -A FORWARD -i "$wan_if" -o "$lan_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  echo "$r wan=$wan_if lan=$lan_if" >>"$OUT/info.txt"
done

# start 3724 server on WAN
ip netns exec "$NS_W" python3 -u - <<'PY' >"$OUT/server.log" 2>&1 &
import socket, time, sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('37.244.61.208',3724)); s.listen(5)
print('listening', flush=True)
while True:
    c,a=s.accept(); c.settimeout(1.0)
    print('accept',a, flush=True)
    try:
        while True:
            d=c.recv(4096)
            if not d: break
            if b'PING' in d:
                c.sendall(b'PONG')
            if b'AFTER' in d:
                c.sendall(b'AFTER-OK')
                print('after-ok', flush=True)
    except Exception as e:
        print('err',e, flush=True)
    c.close()
PY
PIDS="$PIDS $!"

sleep 0.5

# capture WAN on RB and RA WAN-facing links to see NAT correctness
ip netns exec "$NS_RB" tcpdump -ni veth-b-wan -U -w "$OUT/rb-wan.pcap" tcp port 3724 >/dev/null 2>&1 & PIDS="$PIDS $!"
ip netns exec "$NS_RA" tcpdump -ni veth-a-wan -U -w "$OUT/ra-wan.pcap" tcp port 3724 >/dev/null 2>&1 & PIDS="$PIDS $!"
ip netns exec "$NS_RB" tcpdump -ni veth-b-lan -U -w "$OUT/rb-lan.pcap" tcp port 3724 >/dev/null 2>&1 & PIDS="$PIDS $!"

# long-lived client flow via RA (bind fixed source port like capture)
ip netns exec "$NS_C" python3 -u - <<'PY' >"$OUT/client.log" 2>&1 &
import socket,time,sys
s=socket.socket(); s.bind(('172.16.202.40',58513))
s.settimeout(8)
s.connect(('37.244.61.208',3724))
print('connected', flush=True)
for i in range(3):
    s.sendall(b'PING'); s.recv(16); time.sleep(0.2)
print('pre-handover-ok', flush=True)
# wait for handover orchestration
for _ in range(40):
    time.sleep(0.25)
    try:
        s.sendall(b'AFTER')
        d=s.recv(16)
        if b'AFTER' in d or b'PONG' in d:
            print('post-handover-ok', flush=True)
            break
    except Exception as e:
        last=e
else:
    print('post-handover-fail', last, flush=True)
time.sleep(0.5)
s.close()
PY
PIDS="$PIDS $!"

sleep 1.2
ip netns exec "$NS_RA" conntrack -L -o extended 2>/dev/null | grep 3724 | tee "$OUT/ct-ra-pre.txt" || true

promote_with_ct(){
  log "handover: export ct from RA, insert into RB, switch WAN route+client to RB"
  ip netns exec "$NS_RA" conntrack -L -p tcp --dport 3724 -o save 2>/dev/null | tee "$OUT/ct-save.txt" > /dev/null || true
  if [ -s "$OUT/ct-save.txt" ]; then
    ip netns exec "$NS_RB" conntrack -R < "$OUT/ct-save.txt" 2>/dev/null || \
      while read -r line; do [ -n "$line" ] && ip netns exec "$NS_RB" conntrack -I $line 2>/dev/null || true; done < "$OUT/ct-save.txt"
  fi
  ip netns exec "$NS_RB" conntrack -L -o extended 2>/dev/null | grep 3724 | tee "$OUT/ct-rb-post.txt" || true
  ip -n "$NS_W" neigh replace 143.177.173.8 lladdr 02:00:00:00:00:bb nud permanent dev veth-w-b 2>/dev/null || true
  ip -n "$NS_W" route replace 143.177.173.8/32 dev veth-w-b
  ip -n "$NS_C" addr replace 172.16.202.40/24 dev veth-c-b
  ip -n "$NS_C" route replace default via 172.16.202.1 dev veth-c-b
}

promote_without_ct(){
  log "handover: switch WAN route+client to RB WITHOUT ct migration (captured failure mode)"
  ip netns exec "$NS_RB" conntrack -F >/dev/null 2>&1 || true
  ip -n "$NS_W" neigh replace 143.177.173.8 lladdr 02:00:00:00:00:bb nud permanent dev veth-w-b 2>/dev/null || true
  ip -n "$NS_W" route replace 143.177.173.8/32 dev veth-w-b
  ip -n "$NS_C" addr replace 172.16.202.40/24 dev veth-c-b
  ip -n "$NS_C" route replace default via 172.16.202.1 dev veth-c-b
}

MODE="${1:-both}"
case "$MODE" in
  with-ct) promote_with_ct ;;
  without-ct|fail) promote_without_ct ;;
  both)
    # run without-ct scenario in this process; for a clean with-ct comparison rerun with arg with-ct
    promote_without_ct
    ;;
  *) echo "usage: $0 [with-ct|without-ct|both]" >&2; exit 2;;
esac

sleep 5
# stop captures
for p in $PIDS; do kill "$p" 2>/dev/null || true; done
sleep 0.5

echo "--- client ---"; cat "$OUT/client.log" || true
echo "--- server ---"; cat "$OUT/server.log" || true

# analyze RB WAN capture for leaked private source (bug signature)
if tcpdump -nn -r "$OUT/rb-wan.pcap" 2>/dev/null | grep -q '172\.16\.202\.40\.58513 > 37\.244\.61\.208\.3724'; then
  echo "DETECTED: private/un-NATed client source on RB WAN after handover (matches stall bug)" | tee "$OUT/verdict.txt"
  if [[ "$MODE" == "with-ct" ]]; then bad "private source leaked despite ct migration"; else ok "reproduced stall signature without ct migration"; fi
else
  echo "NO private-source leak on RB WAN" | tee "$OUT/verdict.txt"
fi

if grep -q 'post-handover-ok' "$OUT/client.log" 2>/dev/null; then
  ok "flow continued after handover ($MODE)"
elif grep -q 'post-handover-fail' "$OUT/client.log" 2>/dev/null; then
  if [[ "$MODE" == "with-ct" ]]; then bad "flow stalled with ct migration ($MODE)"; else ok "flow stalled without ct migration ($MODE, expected)"; fi
fi

log "artifacts: $OUT"
log "compare with captures: $CAP_DIR (see debug-summary.md)"
printf 'RESULT: %d pass, %d fail\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
