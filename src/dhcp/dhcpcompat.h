/* Linux compatibility shims for the vendored FreeBSD dhclient fork.
 *
 * The fork derives from ISC DHCP 4.x via the FreeBSD base tree (see the
 * per-file copyright headers; upstream reference checkout lives in
 * vendor/freebsd-src, sbin/dhclient). This header replaces the BSD-only
 * pieces the fork pulled from <sys/sockio.h>, <net/if_dl.h>, <net/route.h>,
 * <libutil.h>, <sys/endian.h> and the capsicum/casper machinery.
 */
#ifndef DHCP_LINUX_COMPAT_H
#define DHCP_LINUX_COMPAT_H

#include <asm/ioctls.h>		/* SIOCGIFFLAGS, SIOCSIFMTU, SIOCGIFMTU */
#include <arpa/inet.h>
#include <linux/if_link.h>	/* rtnetlink link messages */
#include <linux/netlink.h>	/* rtnetlink (replaces BSD PF_ROUTE) */
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>		/* ARPHRD_ETHER */
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>

#ifndef nitems
#define nitems(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef RTA_TYPE
#define RTA_TYPE(rta) ((rta)->rta_type)
#endif

/* Kernel IFF_LOWER_UP (carrier); older glibc headers lack it. */
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

/* BSD <sys/endian.h> accessors used by the fork. */
#ifndef be16dec
static inline uint16_t be16dec(const void *pp);
static inline uint16_t
be16dec(const void *pp)
{
	uint16_t t;

	memcpy(&t, pp, sizeof(t));
	return (ntohs(t));
}
#endif
#ifndef be32dec
static inline uint32_t be32dec(const void *pp);
static inline uint32_t
be32dec(const void *pp)
{
	uint32_t t;

	memcpy(&t, pp, sizeof(t));
	return (ntohl(t));
}
#endif

#ifndef __arraycount
#define __arraycount(a) nitems(a)
#endif

#ifndef __DECONST
#define __DECONST(type, var) ((type)(uintptr_t)(const void)(var))
#endif

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#ifndef __dead2
#define __dead2 __attribute__((__noreturn__))
#endif

#ifndef timespeccmp
#define timespeccmp(tvp, uvp, cmp) (((tvp)->tv_sec == (uvp)->tv_sec) ? \
    ((tvp)->tv_nsec cmp (uvp)->tv_nsec) : ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

/* BSD <sys/time.h> macros; glibc hides these from -std=gnu11. */
#ifndef timespecadd
#define timespecadd(tvp, uvp, vvp) do { \
    (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec; \
    (vvp)->tv_nsec = (tvp)->tv_nsec + (uvp)->tv_nsec; \
    if ((vvp)->tv_nsec >= 1000000000) { \
        (vvp)->tv_sec++; \
        (vvp)->tv_nsec -= 1000000000; \
    } \
} while (0)
#endif
#ifndef timespecsub
#define timespecsub(tvp, uvp, vvp) do { \
    (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec; \
    (vvp)->tv_nsec = (tvp)->tv_nsec - (uvp)->tv_nsec; \
    if ((vvp)->tv_nsec < 0) { \
        (vvp)->tv_sec--; \
        (vvp)->tv_nsec += 1000000000; \
    } \
} while (0)
#endif

/* glibc exposes getprogname() only under _GNU_SOURCE. */
#ifndef getprogname
const char *getprogname(void);
#endif

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#ifndef ETHER_VLAN_ENCAP_LEN
#define ETHER_VLAN_ENCAP_LEN 4
#endif

/* BSD libc has these; glibc does not provide them here. */
size_t	 dhcp_strlcpy(char *dst, const char *src, size_t dsize);
size_t	 dhcp_strlcat(char *dst, const char *src, size_t dsize);
void	 dhcp_setproctitle(const char *fmt, ...)
		     __attribute__((__format__(__printf__, 1, 2)));

#ifndef strlcpy
#define strlcpy dhcp_strlcpy
#endif
#ifndef strlcat
#define strlcat dhcp_strlcat
#endif
#ifndef setproctitle
#define setproctitle dhcp_setproctitle
#endif

/* OpenWrt's musl does not expose arc4random(3). */
#ifndef __GLIBC__
uint32_t arc4random(void);
#endif

#endif /* DHCP_LINUX_COMPAT_H */
