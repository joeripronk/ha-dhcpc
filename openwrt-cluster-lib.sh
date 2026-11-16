#!/bin/sh
# Shared helpers for OpenWrt ha-dhcpc cluster scripts.

: "${CLUSTER_HOSTS:=studeerkamer woonkamer meterkast}"

cluster_json_field() {
	python3 -c 'import json,sys,re
key=sys.argv[1]
data=sys.stdin.read()
try:
 d=json.loads(data)
 v=d.get(key,"")
 if isinstance(v,bool): print("true" if v else "false")
 elif v is None: print("")
 else: print(v)
except Exception:
 m=re.search(r"\"" + re.escape(key) + r"\"\s*:\s*\"([^\"]*)\"", data)
 if m: print(m.group(1))
 else:
  m=re.search(r"\"" + re.escape(key) + r"\"\s*:\s*(true|false|null|-?[0-9]+)", data)
  print(m.group(1) if m and m.group(1)!="null" else "")' "$1"
}

cluster_host_status() {
	ssh -o BatchMode=yes -o ConnectTimeout=5 -q "root@$1" 'ha-dhcpc ctl status 2>/dev/null' 2>/dev/null || true
}

# Prints: role \n self \n master (empty on parse/unreachable failure)
cluster_status_triplet() {
	python3 -c 'import json,sys,re
data=sys.stdin.read()
def emit(role,selfv,master):
 for v in (role,selfv,master):
  if v is None: v=""
  sys.stdout.write(str(v)+"\n")
try:
 d=json.loads(data)
 emit(d.get("role",""), d.get("self",""), d.get("master",""))
except Exception:
 def gf(k):
  m=re.search(r"\"" + re.escape(k) + r"\"\s*:\s*\"([^\"]*)\"", data)
  return m.group(1) if m else ""
 emit(gf("role"), gf("self"), gf("master"))'
}

cluster_find_master() {
	masters=
	unreachable=
	for h in "$@"; do
		status=$(cluster_host_status "$h")
		if [ -z "$status" ]; then
			unreachable="${unreachable}${unreachable:+ }$h"
			continue
		fi
		triplet=$(printf '%s\n' "$status" | cluster_status_triplet)
		role=$(printf '%s\n' "$triplet" | sed -n '1p')
		self=$(printf '%s\n' "$triplet" | sed -n '2p')
		master_view=$(printf '%s\n' "$triplet" | sed -n '3p')
		echo "status: host=$h self=${self:-?} role=${role:-?} master_view=${master_view:-?}" >&2
		if [ "$role" = "master" ]; then
			masters="${masters}${masters:+ }$h"
		fi
	done
	if [ -n "$unreachable" ]; then
		echo "status: unreachable/no-status: $unreachable" >&2
	fi
	case "$masters" in
	"")
		echo "graceful-restart: master not found" >&2
		return 1
		;;
	*" "*)
		echo "graceful-restart: multiple masters found: $masters" >&2
		return 1
		;;
	*)
		printf '%s\n' "$masters"
		return 0
		;;
	esac
}

cluster_graceful_ctl() {
	host=$1 action=$2 dry_run=${3:-0}
	if [ "$dry_run" -eq 1 ]; then
		echo "dry-run: would run graceful-restart $action on $host"
		return 0
	fi
	i=1
	while [ "$i" -le 10 ]; do
		out=$(ssh -o BatchMode=yes -o ConnectTimeout=5 -q "root@$host" "ha-dhcpc ctl graceful-restart $action" 2>/dev/null || true)
		case "$out" in
		*'"ok":true'*|*'"ok": true'*)
			echo "graceful-restart: $action on $host"
			return 0
			;;
		*not\ master*)
			echo "graceful-restart: $host is not master; refusing to retry $action" >&2
			return 1
			;;
		*"unknown command"*|*'"ok":false'*|*"error"*)
			echo "graceful-restart: $action rejected on $host ($out) - daemon may lack support" >&2
			return 1
			;;
		"") ;;
		esac
		sleep 1
		i=$((i + 1))
	done
	echo "graceful-restart: failed to $action on $host (no response/timeout); daemon may lack graceful-restart support" >&2
	return 1
}

cluster_graceful_disable_any() {
	dry_run=${1:-0}
	shift || true
	if [ "$dry_run" -eq 1 ]; then
		echo "dry-run: would try graceful-restart disable on any host"
		return 0
	fi
	for h in "$@"; do
		out=$(ssh -o BatchMode=yes -o ConnectTimeout=5 -q "root@$h" "ha-dhcpc ctl graceful-restart disable" 2>/dev/null || true)
		case "$out" in
		*'"ok":true'*|*'"ok": true'*)
			echo "graceful-restart: disable on $h"
			return 0
			;;
		esac
	done
	echo "graceful-restart: disable failed on all hosts; window will expire automatically" >&2
	return 1
}
