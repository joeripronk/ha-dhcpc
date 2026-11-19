/* Config reload (plan §6): re-read the shared document plus this node's local
 * overlay, and when the effective config changed, apply it live — heartbeat
 * timer, cluster transport, ctl socket, DHCP knobs, executor re-apply. An
 * interface change restarts the DHCP engine on the new interface.
 * Returns 0 on success; -1 when a file no longer parses (the previous
 * effective config is kept, so a bad edit never takes a live node down).
 */
#ifndef HA_DHCPC_RELOAD_H
#define HA_DHCPC_RELOAD_H

#include "types.h"

int hadc_conf_reload(hadc_ctx_t *ctx, const char *why);

#endif /* HA_DHCPC_RELOAD_H */
