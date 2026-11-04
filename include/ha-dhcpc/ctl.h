/* HA-DHCPC control interface (M0, frozen). Mirrors plan §3/§4.
 * Local unix socket (ctl_socket). Used by keepalived notify scripts and
 * operators. Idempotent, logged, auditable.
 *
 * Wire protocol (frozen): plaintext line commands, one per line; single-line
 * JSON replies. Commands:
 *   promote [node-id]   -> this node (or given node) becomes master
 *   demote              -> step down; settles dual-master cluster-wide
 *   status              -> JSON status (below)
 *   update              -> master-only: re-read the shared config file from
 *                          disk, apply it here and push it cluster-wide
 * Status JSON keys (frozen): role, self, master, lease{...}, members[],
 * retention, timers{heartbeat_ms,election_deadline_ms}, apply_acks.
 */
#ifndef HA_DHCPC_CTL_H
#define HA_DHCPC_CTL_H

#include "types.h"

typedef struct hadc_ctx hadc_ctx_t;

typedef enum {
    HADC_CTL_PROMOTE = 0,  /* optional target node id (NULL = self) */
    HADC_CTL_DEMOTE,
    HADC_CTL_STATUS,
    HADC_CTL_UPDATE,       /* re-read + publish the shared config (master only) */
} hadc_ctl_cmd_t;

int hadc_ctl_init(hadc_ctx_t *ctx);  /* bind + register with event loop */
int hadc_ctl_step(hadc_ctx_t *ctx);  /* pump socket; nonblocking */

/* Move the control socket after a reload changed ctl_socket; 0 when unchanged
 * (then nothing is touched). */
int hadc_ctl_rebind(hadc_ctx_t *ctx);

/* JSON status snapshot as canonical text (caller frees with free()). */
char *hadc_ctl_status_json(hadc_ctx_t *ctx);

#endif /* HA_DHCPC_CTL_H */
