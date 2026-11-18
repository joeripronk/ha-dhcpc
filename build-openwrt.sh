#!/bin/sh
# Build the ha-dhcpc OpenWrt package with the SDK.
# Usage: ./build-openwrt.sh [sdk-dir]   (or OPENWRT_SDK=/path/sdk ./build-openwrt.sh)
set -eu

SDK=${1:-${OPENWRT_SDK:-$HOME/src/openwrt-sdk-25.12.6-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64}}

[ -d "$SDK" ] || { echo "SDK not found: $SDK" >&2; exit 1; }
[ -f "$SDK/package/ha-dhcpc/Makefile" ] || { echo "package/ha-dhcpc missing in $SDK" >&2; exit 1; }

# u-boot is only needed to build firmware images, not packages, but the SDK
# probes it for every mediatek board (~90 prereq checks, minutes per build).
# Hide the feed dir while this package-only build runs; restore afterwards.
UBOOT=feeds/base_root/package/boot/uboot-mediatek
UBOOT_OFF=.uboot-mediatek.off

# recover from an interrupted earlier run
if [ -d "$SDK/$UBOOT_OFF" ] && [ ! -d "$SDK/$UBOOT" ]; then
	mv "$SDK/$UBOOT_OFF" "$SDK/$UBOOT"
fi

restore() {
	if [ -d "$SDK/$UBOOT_OFF" ]; then
		mv "$SDK/$UBOOT_OFF" "$SDK/$UBOOT"
	fi
}
trap restore EXIT

if [ -d "$SDK/$UBOOT" ]; then
	mv "$SDK/$UBOOT" "$SDK/$UBOOT_OFF"
fi

if ! grep -q '^CONFIG_PACKAGE_ha-dhcpc=' "$SDK/.config"; then
	echo "CONFIG_PACKAGE_ha-dhcpc=m" >> "$SDK/.config"
	(cd "$SDK" && umask 022 && make defconfig > /dev/null)
fi
find "$SDK/bin/packages" \( -name 'ha-dhcpc*.apk' -o -name 'ha-dhcpc*.ipk' \) -delete -print

# Force re-prepare so the current source tree is always what gets built.
rm -rf "$SDK"/build_dir/target-*/ha-dhcpc-* \
       "$SDK"/staging_dir/target-*/stamp/.ha-dhcpc_installed

( cd "$SDK" && umask 022 && make -j"$(nproc)" package/ha-dhcpc/compile V=${V:-s} )

find "$SDK/bin/packages" -name 'ha-dhcpc*.apk' -o -name 'ha-dhcpc*.ipk' | sort | tail -1
