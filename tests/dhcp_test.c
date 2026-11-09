/* DHCP core control-path tests. These run the vendored state machine without
 * sockets; send failures are expected and ignored by the core. */
#define _GNU_SOURCE

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

    printf("dhcp_test: OK\n");
    return 0;
}
