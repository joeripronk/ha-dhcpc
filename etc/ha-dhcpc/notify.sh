#!/bin/sh
# keepalived notify script for ha-dhcpc (plan §4):
#   notify_master -> ha-dhcpc ctl promote
#   notify_backup / notify_fault -> ha-dhcpc ctl demote
# keepalived calls this as: notify.sh <type> <instance> <state> [old_state]
# v1: only MASTER triggers a promote; anything else demotes.
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
