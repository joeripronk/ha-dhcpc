#!/bin/sh
# Deploy ha-dhcpc to this host (the router): native build + tests, install
# binary, production config and systemd unit when they differ from what is
# installed, then restart the service. Dry-run by default; run with --apply.
#
# Rollback: install the previous binary/config and restart, or
# systemctl stop ha-dhcpc.service && systemctl start dhclient-internet
set -eu

CONF_DIR=/etc/ha-dhcpc
UNIT=ha-dhcpc.service
SRC_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SRC_DIR/../.." && pwd)
APPLY=0

[ "${1:-}" = "--apply" ] && APPLY=1

run() {
	if [ "$APPLY" = 1 ]; then sh -c "$1"; else echo "DRY-RUN: $1"; fi
}

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
for f in ha-dhcpc.conf ha-dhcpc-local.conf "$UNIT"; do
	[ -f "$SRC_DIR/$f" ] || { echo "missing $SRC_DIR/$f" >&2; exit 1; }
done

make -C "$REPO_DIR" -s
make -C "$REPO_DIR" -s test

changed=0
for f in ha-dhcpc.conf ha-dhcpc-local.conf; do
	if [ ! -f "$CONF_DIR/$f" ] || ! cmp -s "$SRC_DIR/$f" "$CONF_DIR/$f"; then
		changed=1
		run "install -m 640 $SRC_DIR/$f $CONF_DIR/$f"
	fi
done
# old three-file layout (plan §6): the daemon no longer reads these, so they
# are removed to keep one source of truth on the node.
retired=0
for f in ha-dhcpc.yaml master.conf slave.conf; do
	[ -f "$CONF_DIR/$f" ] || continue
	retired=1
	run "rm -f $CONF_DIR/$f"
done
[ "$retired" = 1 ] && changed=1
# state file: the default moved next to the config (plan §3/§6); move a legacy
# one over when the node has not written its new one yet.
if [ ! -f "$CONF_DIR/state.json" ] && [ -f /var/lib/ha-dhcpc/state.json ]; then
	run "mv /var/lib/ha-dhcpc/state.json $CONF_DIR/state.json"
fi
if ! cmp -s "$SRC_DIR/$UNIT" "/etc/systemd/system/$UNIT"; then
	changed=1
	run "install -m 644 $SRC_DIR/$UNIT /etc/systemd/system/$UNIT"
	run "systemctl daemon-reload"
fi
if ! cmp -s "$REPO_DIR/ha-dhcpc" /usr/local/bin/ha-dhcpc; then
	changed=1
	run "install -m 755 $REPO_DIR/ha-dhcpc /usr/local/bin/ha-dhcpc"
fi

if [ "$changed" = 0 ]; then
	echo "up to date; nothing to deploy"
	exit 0
fi

run "systemctl restart $UNIT"

if [ "$APPLY" = 1 ]; then
	sleep 5
	if /usr/local/bin/ha-dhcpc ctl status; then
		echo "deploy complete"
	else
		echo "ha-dhcpc did not answer; last journal lines:" >&2
		journalctl -u "$UNIT" -n 20 --no-pager >&2 || true
		exit 1
	fi
else
	echo "dry-run complete; rerun with --apply"
fi
