#!/bin/sh
# Build (from current source) and deploy the ha-dhcpc OpenWrt package to the cluster nodes.
# Usage: ./deploy-openwrt.sh [--dry-run] [--no-build] [apk-path]
#   --no-build       deploy newest existing SDK apk instead of building
#   apk-path         deploy this specific apk (implies --no-build)
set -eu

HOSTS="studeerkamer woonkamer meterkast"   # slaves first, master last
DRY_RUN=0
BUILD=1
APK=
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SDK_DEFAULT="$HOME/src/openwrt-sdk-25.12.6-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/openwrt-cluster-lib.sh"

while [ $# -gt 0 ]; do
	case "$1" in
	--dry-run) DRY_RUN=1 ;;
	--no-build) BUILD=0 ;;
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
[ "$DRY_RUN" -eq 1 ] && dlabel=" (dry-run)" || dlabel=
echo "deploying $(basename "$APK")$dlabel"

MASTER=$(cluster_find_master $HOSTS || true)
GRACEFUL=0
if [ -n "$MASTER" ]; then
	echo "master: $MASTER"
		if [ "$DRY_RUN" -eq 1 ]; then
			echo "dry-run: would enable graceful-restart on $MASTER, wait, deploy to: $HOSTS, then disable graceful-restart"
			for h in $HOSTS; do
				echo "dry-run: would scp $APK to root@$h:/tmp/ and run 'apk add --allow-untrusted --force /tmp/$(basename "$APK") && rm -f /etc/ha-dhcpc/valgrind.enabled && /etc/init.d/ha-dhcpc restart'"
			done
			exit 0
		fi
	if cluster_graceful_ctl "$MASTER" enable "$DRY_RUN"; then
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
	ssh -q "root@$h" "apk add --allow-untrusted --force '/tmp/$(basename "$APK")' && rm -f /etc/ha-dhcpc/valgrind.enabled && /etc/init.d/ha-dhcpc restart" \
		&& echo "$h: ok" || echo "$h: FAILED" >&2
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
			cluster_graceful_disable_any "$DRY_RUN" $HOSTS || true
			exit 1
		fi
		sleep 3
		tries=$((tries + 1))
		MASTER2=$(cluster_find_master $HOSTS 2>&1 | tail -n 1 || true)
		case "$MASTER2" in
		""|*" "*|*"graceful-restart:"*|*"status:"*)
			MASTER2=""
			echo -n "."
			;;
		esac
	done
	echo
	cluster_graceful_ctl "$MASTER2" disable "$DRY_RUN" || cluster_graceful_disable_any "$DRY_RUN" $HOSTS || true
fi

