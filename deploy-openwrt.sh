#!/bin/sh
# Deploy the ha-dhcpc OpenWrt package to the cluster nodes.
# Usage: ./deploy-openwrt.sh [apk-path]   (default: newest apk from the SDK)
set -eu

HOSTS="studeerkamer woonkamer meterkast"   # slaves first, master last

APK=${1:-$(ls -t "$HOME/src/openwrt-sdk-25.12.6-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/bin/packages/aarch64_cortex-a53/base"/ha-dhcpc-*.apk 2>/dev/null | head -1)}

[ -n "$APK" ] && [ -f "$APK" ] || { echo "apk not found: ${APK:-none}" >&2; exit 1; }
echo "deploying $(basename "$APK")"

for h in $HOSTS; do
	scp -q "$APK" "root@$h:/tmp/" || { echo "$h: scp failed" >&2; continue; }
	# --force is required: apk skips same-version installs, so a rebuild of
	# the same PKG_VERSION would otherwise leave the old binary in place.
	# The install does not restart the running service, so restart right after.
	ssh -q "root@$h" "apk add --allow-untrusted --force '/tmp/$(basename "$APK")' && /etc/init.d/ha-dhcpc restart" \
		&& echo "$h: ok" || echo "$h: FAILED" >&2
done
