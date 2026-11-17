# ha-dhcpc agent notes

## Project setup

- `ha-dhcpc` is a C daemon for HA DHCP client/cluster behavior (routing, conntrack sync, OSPF integration, etc.) targeting Linux routers/hosts and OpenWrt.
- Native build/test: `make` and `make test` from repo root (see `Makefile`). Build artifacts and test binaries live in the tree.
- Key areas: `src/` (daemon, `src/dhcp/` embedded DHCP client), `include/ha-dhcpc/`, `tests/`, `production/` (node configs/units), design/docs in `HA-DHCPC*.md`.
- `production/host-router/` contains the local router deployment (systemd unit + shared/local config). `production/routers/` contains OpenWrt router config.

## Deployment (use local scripts)

Passwordless sudo is available on this machine. Use the provided deploy scripts instead of ad-hoc install/restart commands.

### Local router (this host, systemd)

- Script: `./deploy-local.sh` (wrapper for `production/host-router/deploy-local.sh`).
- Builds and runs tests, installs binary/config/unit only when changed, and restarts `ha-dhcpc.service`.
- Deploys by default. Preview with:
  - `./deploy-local.sh --dry-run`
- Re-execs with sudo as needed. After apply it checks status via `ha-dhcpc ctl status` and prints journal hints on failure.

### OpenWrt router cluster

- Script: `./deploy-openwrt.sh` (builds package with `./build-openwrt.sh`/OpenWrt SDK and deploys via `ssh`/`scp` to cluster nodes as `root@<host>`, installs apk, restarts service).
- **Graceful deploy flow**: identifies master, enables graceful-restart window, deploys to hosts (slaves then master), then disables; aborts if a single master cannot be identified/enabled to avoid VIP loss.
- Dry-run (no build/install/restart side effects): `./deploy-openwrt.sh --dry-run`
- Useful options: `--no-build` (deploy newest existing SDK apk) or pass an explicit `apk-path` (implies `--no-build`). Valgrind is toggled per node via `/etc/ha-dhcpc/valgrind.enabled` (the init script honors it).
- Requires OpenWrt SDK/toolchain access as configured by `build-openwrt.sh`/`OPENWRT_SDK` and SSH reachability to the configured hosts.

## Guidelines

- Prefer `make test` after code changes; for local deployment use `./deploy-local.sh` (`--dry-run` to preview); for OpenWrt routers use `./deploy-openwrt.sh` (`--dry-run` to preview).
- Do not commit secrets or environment-specific credentials; configs in `production/` are deployment-specific.
- Be cautious with cluster deploys: they affect live routers and failover behavior. Review status/output and avoid manual partial deploys when the script aborts for safety.

## Finding memory leaks

- **Symptoms/rate:** watch `grep -E 'VmRSS|RssAnon|VmData' /proc/<pid>/status` and map/fd counts (`wc -l /proc/<pid>/maps`, `ls /proc/<pid>/fd | wc -l`). Steady `RssAnon`/`VmData` growth with stable maps/fds is heap retention. Master-only growth is often tied to periodic work (`periodic_ready`/`hadc_executor_audit_tick`, `hadc_gwping_tick`, `hadc_routing_reconcile`, OSPF tick) or heartbeat-rate work (`hadc_cluster_heartbeat`) — e.g. fast `cluster.heartbeat_ms` (100ms vs 2000ms) multiplies per-tick leaks.
- **Attribute quickly:** compare master vs slave, single-master with `conntrack_sync`/routing/OSPF/gateway-probe toggled, and idle vs renew/event periods to isolate the path before profiling.
- **Heap profile (preferred):** build/run with debug symbols and profile the exact reproducing config.
  - From start: `heaptrack -o /tmp/ha-ht ./ha-dhcpc --conf ... --local-conf ... --persist ...` (or profile the service binary/args), reproduce growth, stop with Ctrl-C, then `heaptrack_print --print-leaks 1 /tmp/ha-ht*.zst | head -200`.
  - Attach (if `kernel.yama.ptrace_scope` allows): `sudo heaptrack -p <pid>` for a few minutes, stop with `pkill -INT -f 'heaptrack -p <pid>'`, then `heaptrack_print --print-leaks 1 <trace>.zst`. Attach can fail to capture on some setups; prefer profiling from start if the trace is empty.
  - Alternatives: `valgrind --tool=massif --massif-out-file=/tmp/ha.massif ./ha-dhcpc ...` + `ms_print`, or ASan/LSan builds for definitive leak stacks.
- **Common leak patterns here:** libnl `rtnl_*_get_by_name` / `rtnl_neigh_get` return refs that must be released (`rtnl_link_put`/`rtnl_neigh_put`) — objects from `nl_cache_foreach` callbacks are cache-owned; jansson `json_*`/`json_dumps` results must be decref’d/freed on all paths; per-tick netlink cache dumps/allocations in executor/cluster must all be freed. Re-profile after fixes to confirm `print-leaks` and RssAnon slope are flat.
