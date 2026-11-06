#!/bin/sh
# Deploy the ha-dhcpc OpenWrt package to the cluster nodes.
# Usage: ./deploy-openwrt.sh [apk-path]   (default: newest apk from the SDK)
set -eu

HOSTS="meterkast studeerkamer woonkamer"

APK=${1:-$(ls -t "$HOME/src/openwrt-sdk-25.12.6-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/bin/packages/aarch64_cortex-a53/base"/ha-dhcpc-*.apk 2>/dev/null | head -1)}

[ -n "$APK" ] && [ -f "$APK" ] || { echo "apk not found: ${APK:-none}" >&2; exit 1; }
echo "deploying $(basename "$APK")"

for h in $HOSTS; do
	scp -q "$APK" "root@$h:/tmp/" || { echo "$h: scp failed" >&2; continue; }
	ssh -q "root@$h" "apk add --allow-untrusted '/tmp/$(basename "$APK")'" || echo "$h: install failed" >&2
done
