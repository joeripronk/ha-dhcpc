#!/bin/sh
# Optional external-supervisor notify script for ha-dhcpc.
# ha-dhcpc has built-in failover and VIP ownership; this is only for setups
# that still want an external supervisor (e.g. keepalived) to drive roles:
#   notify_master -> ha-dhcpc ctl promote
#   notify_backup / notify_fault -> ha-dhcpc ctl demote
# Called as: notify.sh <type> <instance> <state> [old_state]
set -eu

DHCPC=ha-dhcpc

case "$1" in
MASTER)
	"$DHCPC" ctl promote
	;;
BACKUP|FAULT|STOP)
	"$DHCPC" ctl demote
	;;
*)
	echo "notify.sh: unknown type '$1'" >&2
	exit 1
	;;
esac
