#!/bin/sh
# Build (from current source) and deploy the ha-dhcpc OpenWrt package to the cluster nodes.
# Usage: ./deploy-openwrt.sh [--dry-run] [--no-build] [--with-valgrind] [apk-path]
#   --no-build       deploy newest existing SDK apk instead of building
#   --with-valgrind  run ha-dhcpc under valgrind (memcheck) logging to /tmp/ha-dhcpc-valgrind.log
#   apk-path         deploy this specific apk (implies --no-build)
set -eu

HOSTS="studeerkamer woonkamer meterkast"   # slaves first, master last
DRY_RUN=0
BUILD=1
WITH_VALGRIND=0
APK=
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SDK_DEFAULT="$HOME/src/openwrt-sdk-25.12.6-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64"

while [ $# -gt 0 ]; do
	case "$1" in
	--dry-run) DRY_RUN=1 ;;
	--no-build) BUILD=0 ;;
	--with-valgrind) WITH_VALGRIND=1 ;;
	-*)
		echo "unknown option: $1" >&2
		exit 1
		;;
	*)
		APK=$1
		BUILD=0
		;;
	esac
	shift
done

if [ "$BUILD" -eq 1 ]; then
	echo "building OpenWrt package..."
	"$SCRIPT_DIR/build-openwrt.sh"
fi

if [ -z "$APK" ]; then
	APK=$(ls -t "$SDK_DEFAULT/bin/packages/aarch64_cortex-a53/base"/ha-dhcpc-*.apk 2>/dev/null | head -1)
fi

[ -n "$APK" ] && [ -f "$APK" ] || { echo "apk not found: ${APK:-none}" >&2; exit 1; }
echo "deploying $(basename "$APK")${DRY_RUN:+ (dry-run)}${WITH_VALGRIND:+ (with-valgrind)}"

json_field() {
	python3 -c 'import json,sys
try:
 d=json.load(sys.stdin); print(d.get(sys.argv[1],""))
except Exception:
 print("")' "$1"
}

host_status() {
	ssh -q "root@$1" 'ha-dhcpc ctl status 2>/dev/null' 2>/dev/null || true
}

find_master() {
	masters=
	unreachable=
	for h in $HOSTS; do
		status=$(host_status "$h")
		if [ -z "$status" ]; then
			unreachable="${unreachable}${unreachable:+ }$h"
			continue
		fi
		role=$(printf '%s' "$status" | json_field role)
		self=$(printf '%s' "$status" | json_field self)
		master_view=$(printf '%s' "$status" | json_field master)
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
		echo "$masters"
		return 0
		;;
	esac
}

graceful_ctl() {
	host=$1 action=$2
	if [ "$DRY_RUN" -eq 1 ]; then
		echo "dry-run: would run graceful-restart $action on $host"
		return 0
	fi
	for i in 1 2 3 4 5 6 7 8 9 10; do
		out=$(ssh -q "root@$host" "ha-dhcpc ctl graceful-restart $action" 2>/dev/null || true)
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
		"")
			;;
		esac
		sleep 1
	done
	echo "graceful-restart: failed to $action on $host (no response/timeout); daemon may lack graceful-restart support" >&2
	return 1
}

graceful_disable_any() {
	if [ "$DRY_RUN" -eq 1 ]; then
		echo "dry-run: would try graceful-restart disable on any host"
		return 0
	fi
	for h in $HOSTS; do
		out=$(ssh -q "root@$h" "ha-dhcpc ctl graceful-restart disable" 2>/dev/null || true)
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

MASTER=$(find_master || true)
GRACEFUL=0
if [ -n "$MASTER" ]; then
	echo "master: $MASTER"
	if [ "$DRY_RUN" -eq 1 ]; then
		echo "dry-run: would enable graceful-restart on $MASTER, wait, deploy to: $HOSTS, then disable graceful-restart"
		for h in $HOSTS; do
			if [ "$WITH_VALGRIND" -eq 1 ]; then
				echo "dry-run: would scp $APK to root@$h:/tmp/ and run 'apk add --allow-untrusted --force /tmp/$(basename "$APK") valgrind && mkdir -p /etc/ha-dhcpc && touch /etc/ha-dhcpc/valgrind.enabled && /etc/init.d/ha-dhcpc restart' (valgrind log: /tmp/ha-dhcpc-valgrind.log)"
			else
				echo "dry-run: would scp $APK to root@$h:/tmp/ and run 'apk add --allow-untrusted --force /tmp/$(basename "$APK") && rm -f /etc/ha-dhcpc/valgrind.enabled && /etc/init.d/ha-dhcpc restart'"
			fi
		done
		exit 0
	fi
	if graceful_ctl "$MASTER" enable; then
		GRACEFUL=1
		# allow broadcasts/heartbeats to reach and persist on all peers before restarts
		sleep 3
	else
		echo "graceful-restart: enable failed; aborting to avoid downtime. Upgrade master daemon to a version with graceful-restart support, or deploy nodes manually." >&2
		exit 1
	fi
else
	echo "graceful-restart: cannot identify a single master; aborting deploy (cannot guarantee no VIP loss). Fix cluster state or deploy manually." >&2
	exit 1
fi

for h in $HOSTS; do
	scp -q "$APK" "root@$h:/tmp/" || { echo "$h: scp failed" >&2; continue; }
	# --force is required: apk skips same-version installs, so a rebuild of
	# the same PKG_VERSION would otherwise leave the old binary in place.
	# The install does not restart the running service, so restart right after.
	if [ "$WITH_VALGRIND" -eq 1 ]; then
		ssh -q "root@$h" "apk add --allow-untrusted --force '/tmp/$(basename "$APK")' valgrind && mkdir -p /etc/ha-dhcpc && touch /etc/ha-dhcpc/valgrind.enabled && /etc/init.d/ha-dhcpc restart" \
			&& echo "$h: ok (valgrind)" || echo "$h: FAILED" >&2
	else
		ssh -q "root@$h" "apk add --allow-untrusted --force '/tmp/$(basename "$APK")' && rm -f /etc/ha-dhcpc/valgrind.enabled && /etc/init.d/ha-dhcpc restart" \
			&& echo "$h: ok" || echo "$h: FAILED" >&2
	fi
done

# Disable on the master (identity preserved during graceful window); rediscover after restarts.
if [ "$GRACEFUL" -eq 1 ]; then
	MASTER2=""
	tries=0
	max_tries=60
	while [ -z "${MASTER2:-}" ]; do
		if [ "$tries" -ge "$max_tries" ]; then
			echo
			echo "graceful-restart: timed out waiting for a single master after deploy; attempting disable on any host (window will expire automatically if that fails)" >&2
			graceful_disable_any || true
			exit 1
		fi
		sleep 3
		tries=$((tries + 1))
		MASTER2=$(find_master 2>&1 | tail -n 1 || true)
		case "$MASTER2" in
		""|*" "*|*"graceful-restart:"*|*"status:"*)
			MASTER2=""
			echo -n "."
			;;
		esac
	done
	echo
	graceful_ctl "$MASTER2" disable || graceful_disable_any || true
fi
