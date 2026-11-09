#define _GNU_SOURCE

#include "dhcpd.h"

void dhcp_core_fd_closed(int fd)
{
    (void)fd;
}
