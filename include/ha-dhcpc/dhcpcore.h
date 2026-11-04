/* HA-DHCPC DHCP engine interface (M0, frozen). Mirrors plan §3.
 * The engine is the vendored FreeBSD fork of dhclient (ISC DHCP 4.x
 * derivative): wire codec, RFC 2131 state machine/timeouts, socket layer,
 * lease-file handling. It runs ONLY on the master (plan §2.3: slaves are
 * passive to DHCP). ha-dhcpc drives it through this boundary; the engine
 * never decides roles.
 *
 * M1 scaffold: stub. Vendoring + Linux build of the fork is the M1 work.
 */
#ifndef HA_DHCPC_DHCPCORE_H
#define HA_DHCPC_DHCPCORE_H

#include "lease.h"
#include "types.h"

typedef struct hadc_ctx hadc_ctx_t;

/* Engine -> cluster callbacks (invoked on the event loop thread). */
typedef struct {
    /* New/updated lease state (ACK received): bump version, executor, push. */
    void (*on_lease_update)(void *arg, const hadc_lease_t *lease);
    /* Retention entry/exit (plan §5): propagates to slaves. */
    void (*on_retention)(void *arg, bool entered);
    /* Carrier loss returns: re-enter INIT-SELECT (master-only). */
    void (*on_carrier_return)(void *arg);
} hadc_dhcp_callbacks_t;

int hadc_dhcpcore_init(hadc_ctx_t *ctx, const hadc_dhcp_callbacks_t *cb, void *arg);
int hadc_dhcpcore_start(hadc_ctx_t *ctx);  /* master-only; no-op on slaves */
int hadc_dhcpcore_stop(hadc_ctx_t *ctx);   /* only the master may RELEASE */
int hadc_dhcpcore_step(hadc_ctx_t *ctx);   /* pump engine + timers */

/* Daemon-side: keep the engine's lease file current on slaves so a promoted
 * node resumes renew-only on the synced lease (plan §4/§5). */
int hadc_dhcpcore_write_lease_file(hadc_ctx_t *ctx, const hadc_lease_t *lease);

/* Config reload (plan §6): push the live-settable knobs (retention, rate
 * limit, renew retry) to a running engine; requested options and the hook
 * script are read at engine start, so a change there needs the restart below. */
int hadc_dhcpcore_reload(hadc_ctx_t *ctx);

/* The engine re-enters on the new interface: old interface registrations are
 * dropped, sockets reopened, and the state machine re-enters (INIT-REBOOT on
 * the existing lease, INIT-SELECT when there is none). Master-only. */
int hadc_dhcpcore_restart(hadc_ctx_t *ctx);

#endif /* HA_DHCPC_DHCPCORE_H */
