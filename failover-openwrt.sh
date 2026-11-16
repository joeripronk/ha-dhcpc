#!/bin/sh
# Fail over master role between meterkast and woonkamer on the OpenWrt ha-dhcpc
# cluster and validate that established TCP connections on a given port keep
# working (conntrack flows remain present across the promotion).
#
# Usage: ./failover-openwrt.sh <port> [--from meterkast|woonkamer] [--to meterkast|woonkamer] [--timeout N]
#   port      TCP port number to monitor/validate (e.g. 3724)
#   --from    require this node to be master before failover
#   --to      target node to promote (defaults to the other of the pair)
#   --timeout seconds to wait for role convergence and validation (default 30)
#
# Uses ssh root@<host> and `ha-dhcpc ctl promote/status` (no daemon restarts).
# Matches conntrack flows by original or reply sport/dport (NAT-aware).
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/openwrt-cluster-lib.sh"

PAIR_A="meterkast"
PAIR_B="woonkamer"
ALL_HOSTS="meterkast woonkamer studeerkamer"
PORT=""
FROM=""
TO=""
TIMEOUT=30

usage() {
	echo "usage: $0 <port> [--from meterkast|woonkamer] [--to meterkast|woonkamer] [--timeout N]" >&2
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--from) [ $# -ge 2 ] || usage; FROM=$2; shift 2 ;;
	--to) [ $# -ge 2 ] || usage; TO=$2; shift 2 ;;
	--timeout) [ $# -ge 2 ] || usage; TIMEOUT=$2; shift 2 ;;
	--help|-h) usage ;;
	-*) echo "unknown option: $1" >&2; usage ;;
	*)
		if [ -z "$PORT" ]; then PORT=$1; else echo "unexpected argument: $1" >&2; usage; fi
		shift ;;
	esac
done

[ -n "$PORT" ] || usage
case "$PORT" in *[!0-9]*|"") echo "port must be a number: $PORT" >&2; exit 2 ;; esac
case "$FROM" in ""|"$PAIR_A"|"$PAIR_B") ;; *) echo "--from must be $PAIR_A or $PAIR_B" >&2; exit 2 ;; esac
case "$TO" in ""|"$PAIR_A"|"$PAIR_B") ;; *) echo "--to must be $PAIR_A or $PAIR_B" >&2; exit 2 ;; esac
if [ -n "$FROM" ] && [ -n "$TO" ] && [ "$FROM" = "$TO" ]; then echo "--from and --to must differ" >&2; exit 2; fi

json_str() { cluster_json_field "$1"; }
host_status() { cluster_host_status "$1"; }

role_of() { host_status "$1" | json_str role; }
master_of_view() { host_status "$1" | json_str master; }

require_host() {
	r=$(role_of "$1")
	[ -n "$r" ] || { echo "error: cannot read ha-dhcpc status from $1" >&2; exit 1; }
}

for h in $PAIR_A $PAIR_B; do require_host "$h"; done

ROLE_A=$(role_of "$PAIR_A"); ROLE_B=$(role_of "$PAIR_B")
MASTER_A=$(master_of_view "$PAIR_A"); MASTER_B=$(master_of_view "$PAIR_B")

CURRENT_MASTER=""
if [ "$ROLE_A" = "master" ]; then CURRENT_MASTER="$PAIR_A"; fi
if [ "$ROLE_B" = "master" ]; then
	if [ -n "$CURRENT_MASTER" ] && [ "$CURRENT_MASTER" != "$PAIR_B" ]; then
		echo "error: both $PAIR_A and $PAIR_B report master role" >&2; exit 1
	fi
	CURRENT_MASTER="$PAIR_B"
fi
[ -n "$CURRENT_MASTER" ] || { echo "error: neither $PAIR_A nor $PAIR_B is master (roles: $PAIR_A=$ROLE_A/$MASTER_A, $PAIR_B=$ROLE_B/$MASTER_B)" >&2; exit 1; }
if [ -n "$FROM" ] && [ "$FROM" != "$CURRENT_MASTER" ]; then echo "error: --from $FROM is not current master ($CURRENT_MASTER)" >&2; exit 1; fi
if [ -n "$TO" ]; then TARGET="$TO"; else if [ "$CURRENT_MASTER" = "$PAIR_A" ]; then TARGET="$PAIR_B"; else TARGET="$PAIR_A"; fi; fi
[ "$TARGET" != "$CURRENT_MASTER" ] || { echo "error: target equals current master ($TARGET)" >&2; exit 1; }

echo "cluster: current master=$CURRENT_MASTER target=$TARGET port=$PORT timeout=${TIMEOUT}s"
echo "views: $PAIR_A role=$ROLE_A master=$MASTER_A; $PAIR_B role=$ROLE_B master=$MASTER_B"

# Match original/reply sport/dport so NATed forwarded flows are included.
ct_flows() {
	host=$1
	ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$host" \
		"conntrack -L -p tcp 2>/dev/null | grep -E '(^|[[:space:]])(sport=${PORT}|dport=${PORT})([[:space:]]|$)' || true" \
		2>/dev/null | sed '/^$/d' | sort
}
ct_established() {
	host=$1
	ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$host" \
		"conntrack -L -p tcp 2>/dev/null | grep ESTABLISHED | grep -E '(^|[[:space:]])(sport=${PORT}|dport=${PORT})([[:space:]]|$)' || true" \
		2>/dev/null | sed '/^$/d' | sort
}
ct_tuples() {
	sed -n 's/.*src=\([^ ]*\) dst=\([^ ]*\) sport=\([^ ]*\) dport=\([^ ]*\).*src=\([^ ]*\) dst=\([^ ]*\) sport=\([^ ]*\) dport=\([^ ]*\).*/orig \1:\3->\2:\4 reply \5:\7->\6:\8/p' | sort -u
}

tmpdir=${TMPDIR:-/tmp}/failover-openwrt.$$.$PORT
mkdir -p "$tmpdir"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT INT TERM

echo "== pre-failover =="
for h in $ALL_HOSTS; do
	ct_established "$h" >"$tmpdir/pre.$h.raw"
	ct_flows "$h" >"$tmpdir/pre.all.$h.raw"
	ct_tuples <"$tmpdir/pre.$h.raw" >"$tmpdir/pre.$h.tuples"
	est=$(wc -l <"$tmpdir/pre.$h.tuples" | tr -d ' ')
	all=$(wc -l <"$tmpdir/pre.all.$h.raw" | tr -d ' ')
	echo "  $h: established=$est total_tcp_port=$all"
done

BASELINE_TUPLES="$tmpdir/pre.$CURRENT_MASTER.tuples"
BASELINE_COUNT=$(wc -l <"$BASELINE_TUPLES" | tr -d ' ')
echo "baseline: $BASELINE_COUNT established conntrack tuple(s) for port $PORT on current master $CURRENT_MASTER"
if [ "$BASELINE_COUNT" -eq 0 ]; then
	echo "note: no established port-$PORT conntrack flows found on master; validating role convergence only"
fi

echo "== failover =="
echo "promoting $TARGET (request sent to $CURRENT_MASTER)..."
PROM_OUT=$(ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$CURRENT_MASTER" "ha-dhcpc ctl promote $TARGET" 2>/dev/null || true)
echo "promote response: ${PROM_OUT:-<none>}"
case "$PROM_OUT" in
	*'"ok":true'*|*'"ok": true'*) ;;
	*) echo "warning: promote command did not return explicit ok; checking convergence..." >&2 ;;
esac

echo "waiting for convergence (target master, old master demoted)..."
deadline=$(( $(date +%s) + TIMEOUT ))
converged=0
while [ "$(date +%s)" -le "$deadline" ]; do
	r_t=$(role_of "$TARGET" 2>/dev/null || true)
	r_s=$(role_of "$CURRENT_MASTER" 2>/dev/null || true)
	m_t=$(master_of_view "$TARGET" 2>/dev/null || true)
	m_s=$(master_of_view "$CURRENT_MASTER" 2>/dev/null || true)
	if [ "$r_t" = "master" ] && [ "$r_s" = "slave" ] && [ "$m_t" = "$TARGET" ] && [ "$m_s" = "$TARGET" ]; then
		converged=1
		echo "converged: $TARGET role=master, $CURRENT_MASTER role=slave, master_view=$TARGET"
		break
	fi
	sleep 1
done

if [ "$converged" -ne 1 ]; then
	echo "error: failover did not converge within ${TIMEOUT}s" >&2
	for h in $PAIR_A $PAIR_B; do
		echo "  $h: role=$(role_of "$h" 2>/dev/null || echo '?') master=$(master_of_view "$h" 2>/dev/null || echo '?')" >&2
	done
	exit 1
fi

sleep 2

echo "== post-failover =="
for h in $ALL_HOSTS; do
	ct_established "$h" >"$tmpdir/post.$h.raw"
	ct_flows "$h" >"$tmpdir/post.all.$h.raw"
	ct_tuples <"$tmpdir/post.$h.raw" >"$tmpdir/post.$h.tuples"
	est=$(wc -l <"$tmpdir/post.$h.tuples" | tr -d ' ')
	all=$(wc -l <"$tmpdir/post.all.$h.raw" | tr -d ' ')
	echo "  $h: established=$est total_tcp_port=$all"
done

ok=1
if [ "$BASELINE_COUNT" -gt 0 ]; then
	missing="$tmpdir/missing.tuples"
	comm -23 "$BASELINE_TUPLES" "$tmpdir/post.$TARGET.tuples" >"$missing" || true
	still_missing="$tmpdir/still_missing.tuples"; : >"$still_missing"
	while IFS= read -r t; do
		[ -n "$t" ] || continue
		found=0
		for h in $ALL_HOSTS; do
			if grep -Fqx "$t" "$tmpdir/post.$h.tuples" 2>/dev/null; then found=1; break; fi
		done
		[ "$found" -eq 1 ] || printf '%s\n' "$t" >>"$still_missing"
	done <"$missing"
	miss_count=$(wc -l <"$still_missing" | tr -d ' ')
	if [ "$miss_count" -eq 0 ]; then
		echo "validation: all $BASELINE_COUNT baseline established port-$PORT tuple(s) still present after failover"
	else
		echo "validation: FAIL - $miss_count baseline established port-$PORT tuple(s) missing after failover:" >&2
		sed 's/^/  missing: /' "$still_missing" >&2
		ok=0
	fi
else
	echo "validation: no baseline established port-$PORT flows to compare; role failover convergence succeeded"
fi

NEW_MASTER_TUPLES=$(wc -l <"$tmpdir/post.$TARGET.tuples" | tr -d ' ')
echo "new master $TARGET has $NEW_MASTER_TUPLES established port-$PORT tuple(s)"

if [ "$ok" -eq 1 ]; then
	echo "RESULT: PASS (failover $CURRENT_MASTER -> $TARGET, port $PORT)"
	exit 0
else
	echo "RESULT: FAIL (failover $CURRENT_MASTER -> $TARGET, port $PORT)" >&2
	exit 1
fi
