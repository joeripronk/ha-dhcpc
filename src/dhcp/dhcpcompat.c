/* Linux compat shims for the vendored FreeBSD dhclient fork (see dhcpcompat.h). */
#define _GNU_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "dhcpcompat.h"

#ifndef __GLIBC__

uint32_t
arc4random(void)
{
	uint32_t v;
	static uint64_t state;

	if (getrandom(&v, sizeof(v), 0) == sizeof(v))
		return v;
	/* Best effort if getrandom(2) is unavailable. */
	if (state == 0)
		state = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
	state = state * 6364136223846793005ULL + 1442695040888963407ULL;
	return (uint32_t)(state >> 32);
}

#endif

size_t
dhcp_strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';
		while (*src++)
			;
	}
	return (src - osrc - 1);	/* count does not include NUL */
}

void
dhcp_setproctitle(__attribute__((__unused__)) const char *fmt, ...)
{
	/* No process title on Linux; accepted no-op. */
}

const char *
getprogname(void)
{
	if (program_invocation_short_name != NULL)
		return (program_invocation_short_name);
	return (program_invocation_name);
}
