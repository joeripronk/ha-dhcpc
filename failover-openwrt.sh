#!/bin/sh
# Fail over master role between OpenWrt ha-dhcpc cluster nodes and validate
# that established TCP connections on a given port keep working (conntrack
# flows remain present across the promotion).
#
# Usage: ./failover-openwrt.sh <port> [--from <host>] [--to <host>] [--timeout N] [--recheck N]
#   port      TCP port number to monitor/validate (e.g. 3724)
#   --from    require this node to be master before failover (optional)
#   --to      target node to promote (defaults to preferred slave)
#   --timeout seconds to wait for role convergence and validation (default 30)
#   --recheck seconds to keep re-checking every baseline tuple once per second
#             after the post-failover snapshot; a tuple that drops out of
#             ESTABLISHED during the window fails the run (default 10)
#
# Uses ssh root@<host> and `ha-dhcpc ctl promote/status` (no daemon restarts).
# Matches conntrack flows by original or reply sport/dport (NAT-aware).
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/openwrt-cluster-lib.sh"

: "${CLUSTER_HOSTS:=studeerkamer woonkamer meterkast}"
ALL_HOSTS="$CLUSTER_HOSTS"
# Capture every cluster node so old/new master (and any other participant) are covered.
# br-lan.11 is the cluster/OSPF fabric (heartbeats, OSPF, conntrack sync); br-lan.5/.300 are the data paths.
CAP_IFACES="br-lan.5 br-lan.11 br-lan.300"
PORT=""
FROM=""
TO=""
TIMEOUT=30
RECHECK=${RECHECK:-10}

usage() {
	echo "usage: $0 <port> [--from <host>] [--to <host>] [--timeout N] [--recheck N]" >&2
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--from) [ $# -ge 2 ] || usage; FROM=$2; shift 2 ;;
	--to) [ $# -ge 2 ] || usage; TO=$2; shift 2 ;;
	--timeout) [ $# -ge 2 ] || usage; TIMEOUT=$2; shift 2 ;;
	--recheck) [ $# -ge 2 ] || usage; RECHECK=$2; shift 2 ;;
	--help|-h) usage ;;
	-*) echo "unknown option: $1" >&2; usage ;;
	*)
		if [ -z "$PORT" ]; then PORT=$1; else echo "unexpected argument: $1" >&2; usage; fi
		shift ;;
	esac
done

[ -n "$PORT" ] || usage
case "$PORT" in *[!0-9]*|"") echo "port must be a number: $PORT" >&2; exit 2 ;; esac

host_in_list() {
	h=$1
	for x in $ALL_HOSTS; do
		[ "$x" = "$h" ] && return 0
	done
	return 1
}

case "$FROM" in "") ;; *) host_in_list "$FROM" || { echo "--from must be one of: $ALL_HOSTS" >&2; exit 2; } ;; esac
case "$TO" in "") ;; *) host_in_list "$TO" || { echo "--to must be one of: $ALL_HOSTS" >&2; exit 2; } ;; esac
if [ -n "$FROM" ] && [ -n "$TO" ] && [ "$FROM" = "$TO" ]; then echo "--from and --to must differ" >&2; exit 2; fi

json_str() { cluster_json_field "$1"; }
host_status() { cluster_host_status "$1"; }

role_of() { host_status "$1" | json_str role; }
master_of_view() { host_status "$1" | json_str master; }

# Auto-discover current master
echo "discovering master from hosts: $ALL_HOSTS"
CURRENT_MASTER=$(cluster_find_master $ALL_HOSTS 2>/dev/null || true)
if [ -z "$CURRENT_MASTER" ]; then
	echo "error: could not auto-discover a single master (check cluster status/reachability)" >&2
	exit 1
fi

if [ -n "$FROM" ] && [ "$FROM" != "$CURRENT_MASTER" ]; then
	echo "error: --from $FROM is not current master ($CURRENT_MASTER)" >&2
	exit 1
fi

if [ -n "$TO" ]; then
	TARGET="$TO"
else
	# Prefer the other of the original pair when applicable
	if [ "$CURRENT_MASTER" = "meterkast" ]; then
		TARGET="woonkamer"
	elif [ "$CURRENT_MASTER" = "woonkamer" ]; then
		TARGET="meterkast"
	else
		# pick first non-master host
		for h in $ALL_HOSTS; do
			if [ "$h" != "$CURRENT_MASTER" ]; then
				TARGET="$h"
				break
			fi
		done
	fi
fi

[ -n "$TARGET" ] || { echo "error: could not determine failover target" >&2; exit 1; }
[ "$TARGET" != "$CURRENT_MASTER" ] || { echo "error: target equals current master ($TARGET)" >&2; exit 1; }
host_in_list "$TARGET" || { echo "error: target $TARGET not in cluster hosts ($ALL_HOSTS)" >&2; exit 1; }

echo "cluster: current master=$CURRENT_MASTER target=$TARGET port=$PORT timeout=${TIMEOUT}s recheck=${RECHECK}s"
for h in $ALL_HOSTS; do
	echo "  $h: role=$(role_of "$h" 2>/dev/null || echo '?') master=$(master_of_view "$h" 2>/dev/null || echo '?')"
done
CAP_HOSTS="$ALL_HOSTS"

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
ts=$(date +%Y%m%d-%H%M%S 2>/dev/null || echo now)
CAP_DIR="$PWD/failover-captures/${ts}-port${PORT}-${CURRENT_MASTER}-to-${TARGET}"
mkdir -p "$tmpdir" "$CAP_DIR/analysis"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT INT TERM

FETCH_OK=1

fetch_remote_file() {
	_rh=$1 _rf=$2 _lf=$3 _label=$4 _optional=${5:-0}
	_err="$tmpdir/scp.err.$$"
	if scp -o BatchMode=yes -o ConnectTimeout=5 "root@${_rh}:${_rf}" "$_lf" </dev/null >"$_err" 2>&1; then
		echo "  saved: $_lf"
		return 0
	fi
	echo "  warning: could not fetch ${_label}: $(tr '\n' ' ' <"$_err" 2>/dev/null)" >&2
	if [ "$_optional" -ne 1 ]; then
		FETCH_OK=0
	fi
	return 1
}

capture_start() {
	echo "== tcpdump captures =="
	echo "capture dir: $CAP_DIR (full capture, snaplen ${CAP_SNAPLEN:-100}B, ${CAP_SIZE_MB:-100}MB/file limit)"
	for h in $CAP_HOSTS; do
		for iface in $CAP_IFACES; do
			rfile="/tmp/ha-failover-${ts}-${PORT}-${h}-${iface}.pcap"
			pfile="/tmp/ha-failover-${ts}-${PORT}-${h}-${iface}.pid"
			logfile="/tmp/ha-failover-${ts}-${PORT}-${h}-${iface}.log"
			printf '%s\n' "$h $iface $rfile $pfile $logfile" >>"$tmpdir/captures.list"
			if ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$h" \
				"rm -f '$rfile' '$pfile' '$logfile'; tcpdump -i '$iface' -nn -s ${CAP_SNAPLEN:-100} -C ${CAP_SIZE_MB:-100} -W 1 -U -w '$rfile' >'$logfile' 2>&1 & echo \$! >'$pfile'" \
				>"$tmpdir/start.err" 2>&1; then
				echo "  started: $h $iface -> $CAP_DIR/$(basename "$rfile")"
			else
				echo "  warning: failed to start tcpdump on $h $iface: $(tr '\n' ' ' <"$tmpdir/start.err" 2>/dev/null)" >&2
				FETCH_OK=0
			fi
		done
	done
	sleep 1
}
capture_stop() {
	echo "== stopping tcpdump captures (and killing any remaining tcpdump/conntrack on capture hosts) =="
	if [ -f "$tmpdir/captures.list" ]; then
		while IFS=' ' read -r h iface rfile pfile logfile; do
			[ -n "$h" ] || continue
			ssh -n -o BatchMode=yes -o ConnectTimeout=5 "root@$h" \
				"if [ -f '$pfile' ]; then kill \"\$(cat '$pfile')\" 2>/dev/null || true; sleep 1; kill -9 \"\$(cat '$pfile')\" 2>/dev/null || true; fi" \
				</dev/null >/dev/null 2>&1 || true
			ssh -n -o BatchMode=yes -o ConnectTimeout=5 "root@$h" "ls ${rfile}* 2>/dev/null" </dev/null >"$tmpdir/rfiles" 2>/dev/null || true
			if [ ! -s "$tmpdir/rfiles" ]; then
				echo "  warning: no pcap files found on $h $iface (${rfile}*)" >&2
				FETCH_OK=0
			else
				while IFS= read -r rf; do
					[ -n "$rf" ] || continue
					base=$(basename "$rf")
					fetch_remote_file "$h" "$rf" "$CAP_DIR/$base" "$h:$rf" || true
				done <"$tmpdir/rfiles"
			fi
			if ! fetch_remote_file "$h" "$logfile" "$CAP_DIR/${h}-${iface}.tcpdump.log" "$h:$logfile"; then
				: # already warned
			fi
		done <"$tmpdir/captures.list"
	fi
	# Always try to kill any leftover tcpdump/conntrack processes on capture hosts (and analysis hosts too, for safety)
	for h in $CAP_HOSTS $ALL_HOSTS; do
		ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$h" "killall tcpdump 2>/dev/null || true; killall conntrack 2>/dev/null || true" >/dev/null 2>&1 || true
	done
}
ct_dump_remote() {
	host=$1 label=$2
	rbase="/tmp/ha-failover-${ts}-${PORT}-${host}-${label}"
	ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$host" "
		conntrack -L -p tcp -o extended 2>/dev/null | grep -E '(^|[[:space:]])(sport=${PORT}|dport=${PORT})([[:space:]]|$)' >'${rbase}.extended' || true
		conntrack -L -p tcp -o save 2>/dev/null | grep -E '(^|[[:space:]])(sport[[:space:]]+${PORT}|dport[[:space:]]+${PORT})([[:space:]]|$)' >'${rbase}.save' || true
		conntrack -L -p tcp 2>/dev/null | grep -E '(^|[[:space:]])(sport=${PORT}|dport=${PORT})([[:space:]]|$)' >'${rbase}.plain' || true
		cat /proc/net/nf_conntrack 2>/dev/null | grep -E '(^|[[:space:]])(sport=${PORT}|dport=${PORT})([[:space:]]|$)' >'${rbase}.nf_conntrack' || true
		ip route show default >'${rbase}.ip_default' 2>&1 || true
		ip -4 route >'${rbase}.ip_r4' 2>&1 || true
		ha-dhcpc ctl status 2>'${rbase}.status.err' >'${rbase}.status.json' || true
	" >"$tmpdir/ctdump.err" 2>&1 || { echo "  warning: ct dump ($label) failed on $host: $(tr '\n' ' ' <"$tmpdir/ctdump.err" 2>/dev/null)" >&2; FETCH_OK=0; }
	printf '%s\n' "$host $label $rbase" >>"$tmpdir/analysis.files"
}

analysis_start() {
	echo "== analysis capture =="
	echo "analysis dir: $CAP_DIR/analysis (conntrack dumps/events, ha-dhcpc status/logs)"
	for h in $ALL_HOSTS; do
		ct_dump_remote "$h" pre
	done
	# events+samples run on every node: a disconnect on any node counts, and
	# the recheck window needs the monitors alive until analysis_stop_fetch.
	for h in $ALL_HOSTS; do
		emon="/tmp/ha-failover-${ts}-${PORT}-${h}-events.log"
		epid="/tmp/ha-failover-${ts}-${PORT}-${h}-events.pid"
		smon="/tmp/ha-failover-${ts}-${PORT}-${h}-samples.log"
		spid="/tmp/ha-failover-${ts}-${PORT}-${h}-samples.pid"
		printf '%s\n' "$h bg $emon $epid" >>"$tmpdir/analysis.files"
		printf '%s\n' "$h bg $smon $spid" >>"$tmpdir/analysis.files"
		if ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$h" "
			rm -f '$emon' '$epid' '$smon' '$spid'
			(conntrack -E -o extended -p tcp 2>/dev/null | grep --line-buffered -E '(^|[[:space:]])(sport=${PORT}|dport=${PORT})([[:space:]]|$)' >'$emon') & echo \$! >'$epid'
			(i=0; while [ \$i -lt 120 ]; do echo \"--- sample \$i \$(date +%s 2>/dev/null || echo now) ---\"; conntrack -L -p tcp -o save 2>/dev/null | grep -E '(^|[[:space:]])(sport[[:space:]]+${PORT}|dport[[:space:]]+${PORT})([[:space:]]|$)' || conntrack -L -p tcp -o extended 2>/dev/null | grep -E '(^|[[:space:]])(sport=${PORT}|dport=${PORT})([[:space:]]|$)' || true; i=\$((i+1)); sleep 1; done >'$smon') & echo \$! >'$spid'
		" >"$tmpdir/amon.err" 2>&1; then
			echo "  started: $h conntrack events+samples"
		else
			echo "  warning: failed to start analysis monitors on $h: $(tr '\n' ' ' <"$tmpdir/amon.err" 2>/dev/null)" >&2
			FETCH_OK=0
		fi
	done
}

analysis_stop_fetch() {
	echo "== collecting analysis =="
	for h in $ALL_HOSTS; do
		ct_dump_remote "$h" post
		ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$h" "
			logread 2>/dev/null | grep ha-dhcpc | tail -n 300 >/tmp/ha-failover-${ts}-${PORT}-${h}-logread.log || true
			dmesg 2>/dev/null | tail -n 120 >/tmp/ha-failover-${ts}-${PORT}-${h}-dmesg-tail.log || true
		" >"$tmpdir/logdump.err" 2>&1 || { echo "  warning: log collection failed on $h: $(tr '\n' ' ' <"$tmpdir/logdump.err" 2>/dev/null)" >&2; FETCH_OK=0; }
		printf '%s\n' "$h log /tmp/ha-failover-${ts}-${PORT}-${h}-logread.log" >>"$tmpdir/analysis.files"
		printf '%s\n' "$h log /tmp/ha-failover-${ts}-${PORT}-${h}-dmesg-tail.log" >>"$tmpdir/analysis.files"
	done
	for h in $ALL_HOSTS; do
		for kind in events samples; do
			pfile="/tmp/ha-failover-${ts}-${PORT}-${h}-${kind}.pid"
			ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$h" \
				"if [ -f '$pfile' ]; then kill \"\$(cat '$pfile')\" 2>/dev/null || true; sleep 1; kill -9 \"\$(cat '$pfile')\" 2>/dev/null || true; fi" \
				>/dev/null 2>&1 || true
		done
	done
	if [ -f "$tmpdir/analysis.files" ]; then
		while IFS=' ' read -r h kind a b; do
			[ -n "$h" ] || continue
			case "$kind" in
			pre|post)
				for ext in extended save plain nf_conntrack ip_default ip_r4 status.json status.err; do
					opt=0
					[ "$ext" = status.err ] && opt=1
					fetch_remote_file "$h" "${a}.${ext}" "$CAP_DIR/analysis/${h}-${kind}.${ext}" "$h:${a}.${ext}" "$opt" || true
				done
				;;
			bg)
				base=$(basename "$a")
				fetch_remote_file "$h" "$a" "$CAP_DIR/analysis/$base" "$h:$a" || true
				;;
			log)
				base=$(basename "$a")
				fetch_remote_file "$h" "$a" "$CAP_DIR/analysis/${h}-${base}" "$h:$a" || true
				;;
			esac
		done <"$tmpdir/analysis.files"
	fi
	if [ "$FETCH_OK" -eq 1 ]; then
		for h in $ALL_HOSTS; do
			ssh -n -o BatchMode=yes -o ConnectTimeout=5 "root@$h" "rm -f /tmp/ha-failover-${ts}-${PORT}-${h}-pre.* /tmp/ha-failover-${ts}-${PORT}-${h}-post.* /tmp/ha-failover-${ts}-${PORT}-${h}-events.* /tmp/ha-failover-${ts}-${PORT}-${h}-samples.* /tmp/ha-failover-${ts}-${PORT}-${h}-logread.log /tmp/ha-failover-${ts}-${PORT}-${h}-dmesg-tail.log" </dev/null >/dev/null 2>&1 || true
		done
		if [ -f "$tmpdir/captures.list" ]; then
			while IFS=' ' read -r h iface rfile pfile logfile; do
				[ -n "$h" ] || continue
				ssh -n -o BatchMode=yes -o ConnectTimeout=5 "root@$h" "rm -f '${rfile}'* '$pfile' '$logfile'" </dev/null >/dev/null 2>&1 || true
			done <"$tmpdir/captures.list"
		fi
		echo "  saved: $CAP_DIR/analysis/ (remote artifacts cleaned)"
	else
		echo "  saved: $CAP_DIR/analysis/ (remote /tmp/ha-failover-${ts}-${PORT}-* preserved for diagnosis due to fetch warnings)" >&2
	fi
	# Always kill leftovers on all hosts
	for h in $CAP_HOSTS $ALL_HOSTS; do
		ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$h" "killall tcpdump 2>/dev/null || true; killall conntrack 2>/dev/null || true" >/dev/null 2>&1 || true
	done
}
capture_start
analysis_start

echo "== pre-failover =="
for h in $ALL_HOSTS; do
	ct_established "$h" >"$tmpdir/pre.$h.raw"
	ct_flows "$h" >"$tmpdir/pre.all.$h.raw"
	ct_tuples <"$tmpdir/pre.$h.raw" >"$tmpdir/pre.$h.tuples"
	est=$(wc -l <"$tmpdir/pre.$h.tuples" | tr -d ' ')
	all=$(wc -l <"$tmpdir/pre.all.$h.raw" | tr -d ' ')
	echo "  $h: established=$est total_tcp_port=$all"
done

BASELINE_TUPLES="$tmpdir/baseline.tuples"
: >"$BASELINE_TUPLES"
for h in $ALL_HOSTS; do
	if [ -s "$tmpdir/pre.$h.tuples" ]; then
		cat "$tmpdir/pre.$h.tuples" >>"$BASELINE_TUPLES"
	fi
done
sort -u -o "$BASELINE_TUPLES" "$BASELINE_TUPLES"
BASELINE_COUNT=$(wc -l <"$BASELINE_TUPLES" | tr -d ' ')
echo "baseline: $BASELINE_COUNT established conntrack tuple(s) for port $PORT across the cluster"
if [ "$BASELINE_COUNT" -eq 0 ]; then
	echo "note: no established port-$PORT conntrack flows found; validating role convergence only"
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
	for h in $ALL_HOSTS; do
		echo "  $h: role=$(role_of "$h" 2>/dev/null || echo '?') master=$(master_of_view "$h" 2>/dev/null || echo '?')" >&2
	done
	capture_stop
	analysis_stop_fetch
	exit 1
fi

sleep 15

echo "== post-failover =="
for h in $ALL_HOSTS; do
	ct_established "$h" >"$tmpdir/post.$h.raw"
	ct_flows "$h" >"$tmpdir/post.all.$h.raw"
	ct_tuples <"$tmpdir/post.$h.raw" >"$tmpdir/post.$h.tuples"
	est=$(wc -l <"$tmpdir/post.$h.tuples" | tr -d ' ')
	all=$(wc -l <"$tmpdir/post.all.$h.raw" | tr -d ' ')
	echo "  $h: established=$est total_tcp_port=$all"
done

# Recheck window: a single snapshot cannot tell a migrated-and-alive connection
# from one that disconnects moments later (or a same-tuple reconnect).  Re-poll
# every baseline tuple once per second; it must stay ESTABLISHED on some host in
# every check.  Runs before analysis_stop_fetch so the event/sample monitors
# stay alive through the window.
RECHECK_DROPS="$tmpdir/recheck.dropped"
: >"$RECHECK_DROPS"
if [ "$BASELINE_COUNT" -gt 0 ] && [ "$RECHECK" -gt 0 ]; then
	echo "== recheck window (${RECHECK} checks, ~1/s; every baseline tuple must stay established in every check) =="
	i=0
	while [ "$i" -lt "$RECHECK" ]; do
		i=$((i+1))
		wnow=$(date '+%H:%M:%S' 2>/dev/null || echo now)
		all_tuples="$tmpdir/recheck.$i.tuples"
		: >"$all_tuples"
		for h in $ALL_HOSTS; do
			ct_established "$h" | sed '/^$/d' | ct_tuples >>"$all_tuples"
		done
		sort -u -o "$all_tuples" "$all_tuples"
		while IFS= read -r t; do
			[ -n "$t" ] || continue
			if ! grep -Fqx "$t" "$all_tuples"; then
				printf '%s\tcheck=%s at=%s\n' "$t" "$i" "$wnow" >>"$RECHECK_DROPS"
			fi
		done <"$BASELINE_TUPLES"
		if [ "$i" -lt "$RECHECK" ]; then
			sleep 1
		fi
	done
fi

capture_stop
analysis_stop_fetch

# Scan the captured conntrack event logs for close/delete transitions of
# baseline tuples: those are disconnects even when samples still show the
# tuple (same-tuple reconnects look "present" in a state snapshot).
EVENT_HITS="$tmpdir/event.disconnects"
: >"$EVENT_HITS"
if [ "$BASELINE_COUNT" -gt 0 ]; then
	while IFS=' ' read -r _tag1 opair _tag2 rpair; do
		[ -n "$opair" ] || continue
		o_sp=${opair#*:}; o_sp=${o_sp%%->*}; o_dp=${opair#*->}; o_dp=${o_dp#*:}
		r_sp=${rpair#*:}; r_sp=${r_sp%%->*}; r_dp=${rpair#*->}; r_dp=${r_dp#*:}
		pat="sport=${o_sp}[[:space:]]+dport=${o_dp}|sport=${r_sp}[[:space:]]+dport=${r_dp}"
		for ef in "$CAP_DIR"/analysis/*-events.log; do
			[ -f "$ef" ] || continue
			# The demoting node destroys its own conntrack entries during the
			# handoff; that is local teardown, not a flow disconnect. The new
			# master's log still catches real FIN/close events.
			case "$(basename "$ef")" in
				*"-${CURRENT_MASTER}-events.log") continue ;;
			esac
			line=$(grep -E "$pat" "$ef" 2>/dev/null | grep -E 'CLOSE_WAIT|LAST_ACK|TIME_WAIT|CLOSE|FIN_WAIT|DELETE|DESTROY|REPLACED' |
				awk '!/packets=0 bytes=0/ || /packets=[1-9]/' | head -n 1 || true)
			[ -n "$line" ] || continue
			printf '%s\t%s\t%s\n' "$opair $rpair" "$(basename "$ef")" "$line" >>"$EVENT_HITS"
		done
	done <"$BASELINE_TUPLES"
fi

echo "captures: $CAP_DIR"
if [ "$FETCH_OK" -ne 1 ]; then
	echo "warning: some captures/analysis artifacts could not be fetched; see warnings above and preserved remote files" >&2
fi
ok=1
if [ -f "$CAP_DIR/analysis/${TARGET}-post.status.json" ]; then
	origin_state=$(cluster_json_field originating <"$CAP_DIR/analysis/${TARGET}-post.status.json" 2>/dev/null || true)
	replica_state=$(cluster_json_field replica <"$CAP_DIR/analysis/${TARGET}-post.status.json" 2>/dev/null || true)
	echo "post status (from $TARGET-post.status.json, may be truncated): conntrack_sync originating=${origin_state:-unknown} replica=${replica_state:-unknown}"
	case "$origin_state" in
		false)
			echo "error: new master $TARGET reports conntrack_sync originating=false (expected true after failover)" >&2
			ok=0
			;;
	esac
fi

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

if [ -s "$RECHECK_DROPS" ]; then
	echo "validation: FAIL - baseline tuple(s) left established state during the ${RECHECK}s recheck window (migrated but disconnected):" >&2
	sed 's/^/  dropped: /' "$RECHECK_DROPS" >&2
	ok=0
fi
if [ -s "$EVENT_HITS" ]; then
	echo "validation: FAIL - close/delete conntrack event(s) seen for baseline tuple(s) during the monitoring window:" >&2
	sed 's/^/  event: /' "$EVENT_HITS" >&2
	echo "  (presence in the final snapshot is not survival: a same-tuple reconnect looks identical)" >&2
	ok=0
fi

if [ "$ok" -eq 1 ]; then
	echo "RESULT: PASS (failover $CURRENT_MASTER -> $TARGET, port $PORT)"
	exit 0
else
	echo "RESULT: FAIL (failover $CURRENT_MASTER -> $TARGET, port $PORT)" >&2
	exit 1
fi
