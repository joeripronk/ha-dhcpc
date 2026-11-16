#!/bin/sh
# Migrate this host's DHCP on the internet VLAN from dhclient-internet.service
# to ha-dhcpc. Dry-run by default; run with --apply to perform the migration.
#
# The current lease is carried over through state.json (which lives next to the
# config), so the daemon comes up on the same lease and the executor applies
# nothing to the interface yet (netlink reconcile pending): the running config
# from dhclient-script simply stays in place. This host opts out of the
# dhclient-format lease DB (lease_file: none), so the engine starts with no
# stored lease and re-acquires via DISCOVER once the server confirms: the
# address may change there, and the executor moves it idempotently.
#
# Rollback: systemctl stop ha-dhcpc.service && systemctl start dhclient-internet
set -eu

IFACE=internet
DHCLIENT_LEASES=/var/lib/dhcp/dhclient.leases
CONF_DIR=/etc/ha-dhcpc
STATE_DIR=/etc/ha-dhcpc   # state file lives next to the config
UNIT=ha-dhcpc.service
SRC_DIR=$(dirname "$0")
BINARY=${BINARY:-/usr/local/bin/ha-dhcpc}
APPLY=0

[ "${1:-}" = "--apply" ] && APPLY=1

run() {
	if [ "$APPLY" = 1 ]; then sh -c "$1"; else echo "DRY-RUN: $1"; fi
}

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
ip link show "$IFACE" >/dev/null || { echo "interface $IFACE missing" >&2; exit 1; }
[ -x "$BINARY" ] || { echo "binary $BINARY missing (set BINARY=...)" >&2; exit 1; }
for f in ha-dhcpc.conf "$UNIT"; do
	[ -f "$SRC_DIR/$f" ] || { echo "missing $SRC_DIR/$f" >&2; exit 1; }
done
[ -f "$DHCLIENT_LEASES" ] || { echo "no $DHCLIENT_LEASES to migrate from" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

# latest lease block; the block is copied verbatim as the engine lease DB
# (same format) and distilled into the daemon's state.json boot cache.
LEASE_BLOCK=$(awk '/^lease \{/{block=$0 "\n"; inblock=1; next}
	inblock{block=block $0 "\n"}
	/^}$/{inblock=0; last=block}
	END{printf "%s", last}' "$DHCLIENT_LEASES")
[ -n "$LEASE_BLOCK" ] || { echo "no lease block found" >&2; exit 1; }
STATE_JSON=$(LEASE_BLOCK="$LEASE_BLOCK" python3 - <<'EOF'
import datetime, json, os, re

block = os.environ["LEASE_BLOCK"]

def field(name):
    m = re.search(rf"^\s*{name}\s+([0-9.]+);", block, re.M)
    return m.group(1) if m else None

def when(name):
    m = re.search(rf"{name} \d+ (\d+)[/-](\d+)[/-](\d+) (\d+):(\d+):(\d+);", block)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups())
    return datetime.datetime(y, mo, d, h, mi, s, tzinfo=datetime.timezone.utc)

now = datetime.datetime.now(datetime.timezone.utc)

def rem(name):
    t = when(name)
    return max(0, int((t - now).total_seconds())) if t else 0

dns = field("option domain-name-servers")
state = {
    "role": "master",
    "lease_version": 1,
    "acked_version": 1,
    "interface": "internet",
    "lease": {
        "state": "BOUND",
        "retention_active": False,
        "address": field("fixed-address") or "0.0.0.0",
        "netmask": field("option subnet-mask") or "0.0.0.0",
        "gateway": field("option routers") or "0.0.0.0",
        "server_id": field("option dhcp-server-identifier") or "0.0.0.0",
        "dns": [d.strip() for d in dns.split(",")] if dns else [],
        "t1_remaining_s": rem("renew"),
        "t2_remaining_s": rem("rebind"),
        "t3_remaining_s": rem("expire"),
        "config_hash": "0" * 40,
    },
}
print(json.dumps(state, separators=(",", ":"), sort_keys=True))
EOF
)

echo "# would write $STATE_DIR/state.json:"
echo "$STATE_JSON" | sed 's/^/# /'
run "mkdir -p $STATE_DIR && chmod 700 $STATE_DIR"
run "mkdir -p $CONF_DIR"
run "install -m 640 $SRC_DIR/ha-dhcpc.conf $CONF_DIR/ha-dhcpc.conf"

[ "$BINARY" = /usr/local/bin/ha-dhcpc ] || run "install -m 755 $BINARY /usr/local/bin/ha-dhcpc"
run "install -m 644 $SRC_DIR/$UNIT /etc/systemd/system/$UNIT"

if [ "$APPLY" = 1 ]; then
	printf '%s\n' "$STATE_JSON" > "$STATE_DIR/state.json"
fi

run "systemctl daemon-reload"
run "systemctl stop dhclient-internet.service"
run "systemctl disable dhclient-internet.service"
run "systemctl enable $UNIT"
run "systemctl start $UNIT"

if [ "$APPLY" = 1 ]; then
	sleep 5
	if "$BINARY" ctl status; then
		echo "migration complete"
	else
		echo "ha-dhcpc did not answer; rolling dhclient-internet back in" >&2
		systemctl start dhclient-internet.service
		systemctl stop "$UNIT"
		exit 1
	fi
	echo "rollback: systemctl stop $UNIT && systemctl start dhclient-internet"
else
	echo "dry-run complete; rerun with --apply"
fi
