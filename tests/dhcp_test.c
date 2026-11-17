/* DHCP core control-path tests. These run the vendored state machine without
 * sockets; send failures are expected and ignored by the core. */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dhcpd.h"

static int fail(const char *what)
{
    printf("dhcp_test: FAIL (%s)\n", what);
    return 1;
}

int main(void)
{
    struct interface_info *ip;
    struct client_state *client;
    struct client_config *config;
    struct client_lease *lease;
    static uint8_t server_id[4];

    ip = calloc(1, sizeof(*ip));
    client = calloc(1, sizeof(*client));
    config = calloc(1, sizeof(*config));
    lease = calloc(1, sizeof(*lease));
    if (!ip || !client || !config || !lease)
        return fail("alloc");

    snprintf(ip->name, sizeof(ip->name), "dhcp_test0");
    ip->wfdesc = -1;
    ip->ufdesc = -1;
    ip->client = client;
    ifi = ip;

    client->config = config;
    client->active = lease;
    client->state = S_BOUND;

    lease->address.len = 4;
    inet_pton(AF_INET, "10.0.0.2", lease->address.iabuf);
    lease->is_bootp = 0;
    lease->expiry = time(NULL) + 10000;
    lease->renewal = time(NULL) + 100;
    lease->rebind = time(NULL) + 200;

    inet_pton(AF_INET, "10.0.0.1", server_id);
    lease->options[DHO_DHCP_SERVER_IDENTIFIER].data = server_id;
    lease->options[DHO_DHCP_SERVER_IDENTIFIER].len = 4;

    if (dhcp_core_force_renew("dhcp_test_missing") != -1)
        return fail("missing interface");
    if (dhcp_core_force_renew("dhcp_test0") != 0)
        return fail("force renew");
    if (client->state != S_RENEWING)
        return fail("state");

    /* A server that cannot honour our renewal answers the REQUEST with an
     * OFFER for a new lease (xid echoes our transaction). With retention
     * on, the core must take it instead of dropping it as "not SELECTING". */
    static uint8_t mt[1] = { 1 };
    static uint8_t hw[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    static struct dhcp_packet raw;
    struct packet pkt;
    uint32_t xid = 0x12345678;

    ip->hw_address.hlen = 6;
    memcpy(ip->hw_address.haddr, hw, 6);
    client->xid = xid;

    memset(&raw, 0, sizeof(raw));
    raw.xid = xid;
    raw.hlen = 6;
    memcpy(raw.chaddr, hw, 6);
    inet_pton(AF_INET, "10.0.0.9", &raw.yiaddr);

    memset(&pkt, 0, sizeof(pkt));
    pkt.raw = &raw;
    pkt.interface = ip;
    pkt.client_addr.len = 4;
    inet_pton(AF_INET, "10.0.0.1", pkt.client_addr.iabuf);
    pkt.options[DHO_DHCP_MESSAGE_TYPE].data = mt;
    pkt.options[DHO_DHCP_MESSAGE_TYPE].len = 1;

    dhcp_core_set_retention(1, 0, 0, 0);

    /* RENEWING, xid matches: accepted, no selection window, straight to
     * the confirming REQUEST. */
    client->state = S_RENEWING;
    dhcpoffer(&pkt);
    if (client->state != S_REQUESTING)
        return fail("offer accepted in RENEWING");
    if (client->offered_leases != NULL)
        return fail("offered lease not consumed");

    /* The reported case: the offer answers us after the client fell back
     * to the last-known-good lease (BOUND) during a failed renew. */
    client->state = S_BOUND;
    dhcpoffer(&pkt);
    if (client->state != S_REQUESTING)
        return fail("offer accepted in BOUND (retention on)");

    /* Retention off: a healthy bound lease is not renegotiated. */
    dhcp_core_set_retention(0, 0, 0, 0);
    client->state = S_BOUND;
    dhcpoffer(&pkt);
    if (client->state != S_BOUND)
        return fail("offer dropped in BOUND (retention off)");
    dhcp_core_set_retention(1, 0, 0, 0);

    /* An offer that does not answer our transaction stays dropped. */
    client->state = S_RENEWING;
    raw.xid = 0x87654321;
    dhcpoffer(&pkt);
    if (client->state != S_RENEWING)
        return fail("xid-mismatched offer dropped");
    if (client->offered_leases != NULL)
        return fail("xid-mismatched offer recorded");
    raw.xid = xid;

    /* The reported case: the core resumed on the daemon's persisted lease, so
     * the transaction ids the servers keep answering are not ours. A NAK from
     * the server the lease is pinned to is still about us and must
     * relinquish the lease (NAK -> reselect), not be dropped as an
     * unrecognizable xid. */
    static uint8_t mt_nak[1] = { 3 };
    static uint8_t sid_pinned[4];
    static uint8_t sid_other[4];
    struct dhcp_core_lease preset;
    struct client_lease *pleased;

    inet_pton(AF_INET, "10.0.0.1", sid_pinned);
    inet_pton(AF_INET, "10.0.0.8", sid_other);
    memset(&preset, 0, sizeof(preset));
    memcpy(preset.address, sid_pinned, 4); /* lease addr, any */
    memcpy(preset.server_id, sid_pinned, 4);
    preset.t1_remaining_s = 100;
    preset.t2_remaining_s = 200;
    preset.t3_remaining_s = 300;
    dhcp_core_preset_lease(&preset);

    pleased = calloc(1, sizeof(*pleased));
    if (!pleased)
        return fail("alloc");
    pleased->address.len = 4;
    memcpy(pleased->address.iabuf, sid_pinned, 4);
    pleased->expiry = time(NULL) + 10000;
    pleased->renewal = time(NULL) + 100;
    pleased->rebind = time(NULL) + 200;
    pleased->options[DHO_DHCP_SERVER_IDENTIFIER].len = 4;
    pleased->options[DHO_DHCP_SERVER_IDENTIFIER].data = malloc(4);
    if (!pleased->options[DHO_DHCP_SERVER_IDENTIFIER].data)
        return fail("alloc");
    memcpy(pleased->options[DHO_DHCP_SERVER_IDENTIFIER].data, sid_pinned, 4);
    client->active = pleased;
    client->state = S_BOUND;
    client->xid = 0; /* nothing we sent in this lifetime */

    pkt.options[DHO_DHCP_MESSAGE_TYPE].data = mt_nak;
    pkt.options[DHO_DHCP_MESSAGE_TYPE].len = 1;
    pkt.options[DHO_DHCP_SERVER_IDENTIFIER].len = 4;
    pkt.options[DHO_DHCP_SERVER_IDENTIFIER].len = 4;
    pkt.options[DHO_DHCP_SERVER_IDENTIFIER].data = sid_pinned;
    raw.xid = 0x008c5556; /* a transaction from before the restart */

    /* It answers the lease we resumed on: relinquish and re-select. */
    dhcpnak(&pkt);
    if (client->state != S_SELECTING)
        return fail("nak answering the persisted lease relinquished");
    if (client->active != NULL)
        return fail("nak relinquished the lease");

    /* A relayed NAK carries no server identifier: the packet source stands in
     * for it, so a NAK from the server the lease is pinned to is still ours. */
    dhcp_core_preset_lease(&preset); /* running on the persisted lease again */
    client->xid = 0;
    client->state = S_BOUND;
    client->active = calloc(1, sizeof(*client->active));
    if (!client->active)
        return fail("alloc");
    client->active->address.len = 4;
    memcpy(client->active->address.iabuf, sid_pinned, 4);
    client->active->options[DHO_DHCP_SERVER_IDENTIFIER].len = 4;
    client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data = malloc(4);
    if (!client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data)
        return fail("alloc");
    memcpy(client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data, sid_pinned, 4);
    pkt.options[DHO_DHCP_SERVER_IDENTIFIER].len = 0; /* relayed: no option 54 */
    dhcpnak(&pkt); /* source is 10.0.0.1 */
    if (client->state != S_SELECTING)
        return fail("relayed nak from our server relinquished");
    if (client->active != NULL)
        return fail("relayed nak relinquished the lease");

    /* A NAK from a server that does not own the lease is not ours to act on. */
    dhcp_core_preset_lease(&preset);
    client->xid = 0;
    client->state = S_BOUND;
    client->active = calloc(1, sizeof(*client->active));
    if (!client->active)
        return fail("alloc");
    client->active->address.len = 4;
    memcpy(client->active->address.iabuf, sid_pinned, 4);
    client->active->options[DHO_DHCP_SERVER_IDENTIFIER].len = 4;
    client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data = malloc(4);
    if (!client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data)
        return fail("alloc");
    memcpy(client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data, sid_pinned, 4);
    pkt.options[DHO_DHCP_SERVER_IDENTIFIER].len = 4;
    pkt.options[DHO_DHCP_SERVER_IDENTIFIER].data = sid_other;
    dhcpnak(&pkt);
    if (client->state != S_BOUND)
        return fail("nak from another server dropped");
    if (client->active == NULL)
        return fail("nak from another server relinquished the lease");

    /* Retention off: the xid check rules again (upstream behaviour). */
    dhcp_core_preset_lease(&preset);
    pkt.options[DHO_DHCP_SERVER_IDENTIFIER].len = 4;
    pkt.options[DHO_DHCP_SERVER_IDENTIFIER].data = sid_pinned;
    dhcp_core_set_retention(0, 0, 0, 0);
    dhcpnak(&pkt);
    if (client->state != S_BOUND)
        return fail("nak dropped with retention off");
    dhcp_core_set_retention(1, 0, 0, 0);
    dhcp_core_preset_lease(NULL);

    /* A known transaction id still rules: a NAK that does not match it is
     * dropped even in the states where a NAK is actionable. */
    client->xid = xid;
    client->state = S_RENEWING;
    dhcpnak(&pkt);
    if (client->state != S_RENEWING)
        return fail("xid-mismatched nak dropped");
    raw.xid = xid;
    dhcpnak(&pkt);
    if (client->state != S_SELECTING)
        return fail("nak answering our transaction relinquished");

    /* Role flip back to master (plan §4): the core is re-entered with its clock
     * advanced to now and stale timeouts cancelled, so the next action on the
     * held lease is the renewal that is due (unicast to the pinned server-id),
     * not a DISCOVER driven by a stale reboot timer. */
    if (dhcp_core_resume("dhcp_test_missing", -1, -1, -1) != -1)
        return fail("resume missing interface");

    client->state = S_BOUND;
    client->xid = 0;
    client->first_sending = 1; /* frozen long before the demotion */
    client->active = calloc(1, sizeof(*client->active));
    if (!client->active)
        return fail("alloc");
    client->active->address.len = 4;
    memcpy(client->active->address.iabuf, sid_pinned, 4);
    client->active->is_bootp = 0;
    client->active->expiry = time(NULL) + 10000;
    client->active->renewal = time(NULL) + 100;
    client->active->rebind = time(NULL) + 200;
    client->active->options[DHO_DHCP_SERVER_IDENTIFIER].len = 4;
    client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data = malloc(4);
    if (!client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data)
        return fail("alloc");
    memcpy(client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data, sid_pinned, 4);

    if (dhcp_core_resume("dhcp_test0", 100, 200, 300) != 0)
        return fail("resume on held lease");
    if (client->state != S_RENEWING)
        return fail("resume on held lease must renew, not DISCOVER");
    if (client->active == NULL)
        return fail("resume dropped the held lease");
    if (!(client->active->renewal < client->active->rebind &&
          client->active->rebind < client->active->expiry))
        return fail("resume did not re-arm the held lease timers in order");

    /* Nothing to renew when no lease is held: reboot into a fresh select. */
    free(client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data);
    free(client->active);
    client->active = NULL;
    client->state = S_INIT;
    if (dhcp_core_resume("dhcp_test0", -1, -1, -1) != 0)
        return fail("resume with no lease");
    if (client->state != S_SELECTING)
        return fail("resume with no lease must reboot to select");

    printf("dhcp_test: OK\n");
    return 0;
}
