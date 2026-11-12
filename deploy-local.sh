#!/bin/sh
# Deploy ha-dhcpc locally: build, install binary/config/unit, restart systemd.
# Wrapper for production/host-router/deploy-local.sh. Dry-run by default; pass --apply.
set -eu
exec "$(dirname "$0")/production/host-router/deploy-local.sh" "$@"
