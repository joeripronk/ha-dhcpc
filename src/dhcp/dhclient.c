/*	$OpenBSD: dhclient.c,v 1.63 2005/02/06 17:10:13 krw Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 1995, 1996, 1997, 1998, 1999
 * The Internet Software Consortium.    All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 *
 * This client was substantially modified and enhanced by Elliot Poger
 * for use on Linux while he was working on the MosquitoNet project at
 * Stanford.
 *
 * The current version owes much to Elliot's Linux enhancements, but
 * was substantially reorganized and partially rewritten by Ted Lemon
 * so as to use the same networking framework that the Internet Software
 * Consortium DHCP server uses.   Much system-specific configuration code
 * was moved into a shell script so that as support for more operating
 * systems is added, it will not be necessary to port and maintain
 * system-specific configuration code to these operating systems - instead,
 * the shell script can invoke the native tools to accomplish the same
 * purpose.
 */

#if !defined(__has_include) || __has_include(<sys/cdefs.h>)
#include <sys/cdefs.h>
#endif
#include "dhcpd.h"

#include <libgen.h>

#ifndef _PATH_VAREMPTY
#define	_PATH_VAREMPTY	"/var/empty"
#endif

#define	PERIOD 0x2e
#define	hyphenchar(c) ((c) == 0x2d)
#define	bslashchar(c) ((c) == 0x5c)
#define	periodchar(c) ((c) == PERIOD)
#define	asterchar(c) ((c) == 0x2a)
#define	alphachar(c) (((c) >= 0x41 && (c) <= 0x5a) || \
	    ((c) >= 0x61 && (c) <= 0x7a))
#define	digitchar(c) ((c) >= 0x30 && (c) <= 0x39)
#define	whitechar(c) ((c) == ' ' || (c) == '\t')

#define	borderchar(c) (alphachar(c) || digitchar(c))
#define	middlechar(c) (borderchar(c) || hyphenchar(c))
#define	domainchar(c) ((c) > 0x20 && (c) < 0x7f)

#define	CLIENT_PATH "PATH=/usr/bin:/usr/sbin:/bin:/sbin"

time_t cur_time;
struct timespec time_now;
static time_t default_lease_time = 43200; /* 12 hours... */

const char *path_dhclient_conf = _PATH_DHCLIENT_CONF;
char *path_dhclient_db = NULL;

int log_perror = 1;
static int privfd = -1;		/* BSD privsep pipe; unused on Linux */

static char hostname[_POSIX_HOST_NAME_MAX + 1];

static struct iaddr iaddr_broadcast = { 4, { 255, 255, 255, 255 } };
static struct in_addr inaddr_any, inaddr_broadcast;

/*
 * ASSERT_STATE() does nothing now; it used to be
 * assert (state_is == state_shouldbe).
 */
#define ASSERT_STATE(state_is, state_shouldbe) {}

/*
 * We need to check that the expiry, renewal and rebind times are not beyond
 * the end of time (~2038 when a 32-bit time_t is being used).
 */
#define TIME_MAX        ((((time_t) 1 << (sizeof(time_t) * CHAR_BIT - 2)) - 1) * 2 + 1)

static struct timespec arp_timeout = { .tv_sec = 0, .tv_nsec = 250 * 1000 * 1000 };
static const struct timespec zero_timespec = { .tv_sec = 0, .tv_nsec = 0 };
int		log_priority;
static int		no_daemon;
static int		unknown_ok = 1;
static int		routefd;

struct interface_info	*ifi;

/* ha-dhcpc integration state (see dhcpd.h integration API). */
static void (*core_on_reason)(void *arg, const char *reason,
    struct client_lease *new_lease);
static void *core_on_arg;
static int core_retention;
static int core_retention_rediscover;
static long core_retention_backoff_min = 30;
static long core_retention_backoff_max = 600;
/* 0 while we are running on the daemon's persisted lease: the transaction id
   the servers answer is not one we generated in this lifetime. */
static int core_xid_known = 1;

/* State names for "answer ignored" logging (indexes match enum dhcp_state). */
static const char *const state_names[] = {
	"REBOOTING", "INIT", "SELECTING", "REQUESTING",
	"BOUND", "RENEWING", "REBINDING"
};

void		 usage(void);
int		 check_option(struct client_lease *l, int option);
int		 check_classless_option(unsigned char *data, int len);
int		 ipv4addrs(const char * buf);
int		 res_hnok(const char *dn);
int		 check_search(const char *srch);
const char	*option_as_string(unsigned int code, unsigned char *data, int len);

/* Minimum MTU is 68 as per RFC791, p. 24 */
#define MIN_MTU 68

static time_t	scripttime;

static struct iaddr defaddr = { .len = 4 };

static void
parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (size_t)(max + 1));
	while (RTA_OK(rta, len)) {
		if (RTA_TYPE(rta) <= max)
			tb[RTA_TYPE(rta)] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

static void
disassoc(void *arg)
{
	struct interface_info *_ifi = arg;

	/*
	 * Clear existing state.
	 */
	if (_ifi->client->active != NULL) {
		script_init("EXPIRE", NULL);
		script_write_params("old_",
		    _ifi->client->active);
		if (_ifi->client->alias)
			script_write_params("alias_",
				_ifi->client->alias);
		script_go();
		if (core_on_reason != NULL)
			core_on_reason(core_on_arg, "EXPIRE",
			    _ifi->client->active);
	}
	_ifi->client->state = S_INIT;
}

/*
 * rtnetlink handler (replaces the BSD PF_ROUTE socket). Carrier and address
 * changes on our interface drive the same reactions as on BSD, except that
 * the daemon does not exit: the cluster decides retention, and the core
 * reports pseudo-reasons through the integration hooks.
 */
void
routehandler(struct protocol *p __unused)
{
	struct rtattr *tb[IFA_MAX + 1];
	char msg[4096];
	struct client_lease *l;
	struct ifaddrmsg *ifa;
	struct ifinfomsg *ifim;
	struct nlmsghdr *n;
	time_t t = time(NULL);
	struct iaddr a;
	ssize_t n_read;
	unsigned flags = 0;
	int linkstat;

	n_read = recv(routefd, msg, sizeof(msg), 0);
	if (n_read < 0)
		return;
	for (n = (struct nlmsghdr *)msg; NLMSG_OK(n, n_read);
	    n = NLMSG_NEXT(n, n_read)) {
		switch (n->nlmsg_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
			ifa = (struct ifaddrmsg *)NLMSG_DATA(n);
			if ((int)ifa->ifa_index != (int)ifi->index)
				break;
			if (ifa->ifa_family != AF_INET)
				break;
			if (scripttime == 0 || t < scripttime + 10)
				break;
			parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa),
			    (int)NLMSG_PAYLOAD(n, sizeof(*ifa)));
			if (!tb[IFA_LOCAL])
				break;
			a.len = sizeof(struct in_addr);
			memcpy(a.iabuf, RTA_DATA(tb[IFA_LOCAL]), a.len);
			if (addr_eq(a, defaddr))
				break;

			for (l = ifi->client->active; l != NULL; l = l->next)
				if (addr_eq(a, l->address))
					break;

			if (l == NULL)	/* added/deleted addr is not ours */
				break;

			if (n->nlmsg_type == RTM_NEWADDR) {
				warning("My address (%s) was re-added",
				    piaddr(a));
			} else {
				warning("My address (%s) was deleted",
				    piaddr(a));
				if (core_on_reason != NULL)
					core_on_reason(core_on_arg,
					    "ADDRESS-DELETED", NULL);
			}
			break;
		case RTM_NEWLINK:
			ifim = (struct ifinfomsg *)NLMSG_DATA(n);
			if ((int)ifim->ifi_index != (int)ifi->index)
				break;
			flags = ifim->ifi_flags;
			if ((flags & IFF_UP) == 0) {
				warning("Interface %s is down", ifi->name);
				disassoc(ifi);
				if (core_on_reason != NULL)
					core_on_reason(core_on_arg,
					    "CARRIER-LOSS", NULL);
				break;
			}
			linkstat = (flags & IFF_LOWER_UP) != 0;
			if (linkstat != ifi->linkstat) {
				debug("%s link state %s -> %s", ifi->name,
				    ifi->linkstat ? "up" : "down",
				    linkstat ? "up" : "down");
				ifi->linkstat = linkstat;
				if (linkstat) {
					if (core_on_reason != NULL)
						core_on_reason(core_on_arg,
						    "CARRIER-RETURN", NULL);
					state_reboot(ifi);
				} else {
					disassoc(ifi);
					if (core_on_reason != NULL)
						core_on_reason(core_on_arg,
						    "CARRIER-LOSS", NULL);
				}
			}
			break;
		default:
			break;
		}
	}
	return;
}

void
dhcp_core_set_hooks(void (*on_reason)(void *arg, const char *reason,
    struct client_lease *new_lease), void *arg)
{
	core_on_reason = on_reason;
	core_on_arg = arg;
}

void
dhcp_core_set_retention(int enabled, int rediscover, long backoff_min_s,
    long backoff_max_s)
{
	core_retention = enabled;
	core_retention_rediscover = rediscover;
	if (backoff_min_s > 0)
		core_retention_backoff_min = backoff_min_s;
	if (backoff_max_s > 0)
		core_retention_backoff_max = backoff_max_s;
}

static long core_rate_limit_ms;		/* 0 = no pacing */
static long core_renew_retry_interval_s;	/* 0 = exponential backoff */
static time_t rate_last_send;		/* scheduled time of last send; 0 = none */

#define PACED_SLOTS 8
struct paced_packet {
	struct interface_info *ip;
	struct in_addr from, to;
};
static struct paced_packet paced_slots[PACED_SLOTS];

void
dhcp_core_set_rate_limit_ms(long ms)
{
	core_rate_limit_ms = ms > 0 ? ms : 0;
}

void
dhcp_core_set_renew_retry_interval_s(long s)
{
	core_renew_retry_interval_s = s > 0 ? s : 0;
}

/* Daemon integration (config reload): point the lease DB at a new path. The
 * file itself is not moved; the core simply reads and writes this path from
 * now on (plan §6 lease_file). An empty path opts out of the file entirely. */
void
dhcp_core_set_lease_db(const char *lease_db)
{
	char *dup;

	if (lease_db == NULL)
		return;
	dup = strdup(lease_db);
	if (dup == NULL)
		return;
	free(path_dhclient_db);
	path_dhclient_db = dup;
}

/* Daemon integration (plan §3/§5/§8): the persisted lease the core should
 * resume on when there is no lease DB. Set before dhcp_core_start(). */
static struct dhcp_core_lease core_preset;
static int core_preset_set;

void
dhcp_core_preset_lease(const struct dhcp_core_lease *preset)
{
	if (preset == NULL) {
		core_preset_set = 0;
		core_xid_known = 1;
		return;
	}
	core_preset = *preset;
	core_preset_set = 1;
	core_xid_known = 0; /* we will run on a transaction id we did not pick */
}

/* Enter S_BOUND on the daemon's persisted lease: identity, pinned server-id
 * and the timers are all we need, and nothing is sent until a timer is due
 * (the renewal goes unicast to the server that owns the lease). */
static void
resume_on_preset(struct interface_info *ip)
{
	struct client_lease *lease;
	struct option_data *opt;
	struct {
		int number;
		const uint8_t *src;
	} opts[4];
	int i;

	lease = malloc(sizeof(*lease));
	if (lease == NULL) {
		warning("resume: no memory for the persisted lease; re-selecting");
		state_reboot(ip);
		return;
	}
	memset(lease, 0, sizeof(*lease));

	lease->address.len = 4;
	memcpy(lease->address.iabuf, core_preset.address, 4);

	opts[0].number = DHO_SUBNET_MASK;
	opts[0].src = core_preset.netmask;
	opts[1].number = DHO_ROUTERS;
	opts[1].src = core_preset.gateway;
	opts[2].number = DHO_DHCP_SERVER_IDENTIFIER;
	opts[2].src = core_preset.server_id;
	opts[3].number = -1;

	for (i = 0; i < 3; i++) {
		if (memcmp(opts[i].src, "\0\0\0\0", 4) == 0)
			continue;
		opt = &lease->options[opts[i].number];
		opt->data = malloc(4);
		if (opt->data == NULL)
			continue;
		memcpy(opt->data, opts[i].src, 4);
		opt->len = 4;
	}
	if (core_preset.n_dns > 0) {
		opt = &lease->options[DHO_DOMAIN_NAME_SERVERS];
		opt->data = malloc(4 * core_preset.n_dns);
		if (opt->data != NULL) {
			memcpy(opt->data, core_preset.dns, 4 * core_preset.n_dns);
			opt->len = 4 * core_preset.n_dns;
		}
	}

	lease->renewal = cur_time + core_preset.t1_remaining_s;
	lease->rebind = cur_time + core_preset.t2_remaining_s;
	lease->expiry = cur_time + core_preset.t3_remaining_s;
	lease->medium = ip->client->medium;

	ip->client->active = lease;
	ip->client->state = S_BOUND;
	core_xid_known = 0;
	add_timeout(lease->renewal, state_bound, ip);

	note("resumed on the daemon's persisted lease (no lease DB): %s, renewal in %d s",
	    piaddr(lease->address), (int)(lease->renewal - cur_time));
}

/* Minimum retry interval implied by the send pacing window, in seconds. */
static long
paced_min_interval(void)
{
	return core_rate_limit_ms > 0 ? (core_rate_limit_ms + 999) / 1000 : 0;
}

static void paced_flush(void *x);

static void
paced_cancel(struct interface_info *ip)
{
	int i;

	for (i = 0; i < PACED_SLOTS; i++) {
		if (paced_slots[i].ip == ip) {
			cancel_timeout(paced_flush, &paced_slots[i]);
			paced_slots[i].ip = NULL;
		}
	}
}

static void
paced_flush(void *x)
{
	struct paced_packet *p = x;
	struct interface_info *ip = p->ip;
	long remaining_ms;

	if (ip == NULL)
		return;
	if (core_rate_limit_ms > 0 && rate_last_send != 0) {
		remaining_ms = core_rate_limit_ms -
		    (long)(cur_time - rate_last_send) * 1000;
		if (remaining_ms > 0) {
			/* Another slot took this window; re-arm. */
			add_timeout(cur_time + (remaining_ms + 999) / 1000,
			    paced_flush, p);
			return;
		}
	}
	p->ip = NULL;
	rate_last_send = cur_time;
	send_packet_unpriv(privfd, &ip->client->packet,
	    ip->client->packet_length, p->from, p->to);
}

/*
 * Minimum interval between DHCP packets we send (ISP-side rate limits,
 * e.g. Odido NL fiber requires >= 10 s between DHCP packets). Sends due
 * too soon are delayed with add_timeout(); delays are whole seconds.
 * Returns the delay in seconds (0 if sent immediately).
 */
static int
paced_send_packet(struct interface_info *ip, struct in_addr from,
    struct in_addr to)
{
	long remaining_ms;
	int i, delay_s;

	if (core_rate_limit_ms <= 0) {
		send_packet_unpriv(privfd, &ip->client->packet,
		    ip->client->packet_length, from, to);
		return (0);
	}
	if (rate_last_send != 0) {
		remaining_ms = core_rate_limit_ms -
		    (long)(cur_time - rate_last_send) * 1000;
		if (remaining_ms > 0) {
			delay_s = (int)((remaining_ms + 999) / 1000);
			/* A delayed REQUEST/REBOOT during acquisition can
			   exceed the reboot timeout and loop forever; prefer
			   correctness over spacing for these states. */
			if ((ip->client->state == S_REQUESTING ||
			    ip->client->state == S_REBOOTING) &&
			    (cur_time - ip->client->first_sending + delay_s) >
			    ip->client->config->reboot_timeout) {
				note("rate limit: bypassing %d s delay for %s to meet reboot timeout",
				    delay_s, ip->name);
				rate_last_send = cur_time;
				send_packet_unpriv(privfd, &ip->client->packet,
				    ip->client->packet_length, from, to);
				return (0);
			}
			for (i = 0; i < PACED_SLOTS; i++) {
				if (paced_slots[i].ip != NULL)
					continue;
				paced_slots[i].ip = ip;
				paced_slots[i].from = from;
				paced_slots[i].to = to;
				add_timeout(cur_time + delay_s,
				    paced_flush, &paced_slots[i]);
				/* Reserve the window so queued sends stay
				   sequential instead of firing together. */
				rate_last_send = cur_time + delay_s;
				debug("rate limit: send delayed %d s", delay_s);
				return (delay_s);
			}
			/* No free slot: send now rather than drop. */
		}
	}
	rate_last_send = cur_time;
	send_packet_unpriv(privfd, &ip->client->packet,
	    ip->client->packet_length, from, to);
	return (0);
}

static int retention_active;

static void
retention_enter(struct interface_info *ip)
{
	if (retention_active)
		return;
	retention_active = 1;
	note("entering RETAINED for %s: keeping last-known-good configuration "
	    "(plan §5, no teardown)", ip->name);
	if (core_on_reason != NULL)
		core_on_reason(core_on_arg, "RETAINED-ENTER", ip->client->active);
}

/*
 * Daemon entry point (replaces main): the daemon calls this once, then
 * drives the core through dhcp_core_run_timeouts()/dispatch_step().
 */
int
dhcp_core_start(const char *interface, const char *lease_db,
    const char *hook_script)
{
	int fd;

	tzset();
	clock_gettime(CLOCK_MONOTONIC, &time_now);
	cur_time = time_now.tv_sec;

	inaddr_broadcast.s_addr = INADDR_BROADCAST;
	inaddr_any.s_addr = INADDR_ANY;

	openlog(getprogname(), LOG_PID | LOG_NDELAY, DHCPD_LOG_FACILITY);
	setlogmask(LOG_UPTO(LOG_DEBUG));

	/* Single log sink: the daemon's own logger writes to stderr (captured
	   by journald); the core must not ALSO write stderr, or journald shows
	   every core note twice (syslog + stderr). Log only via syslog. */
	log_perror = 0;

	if ((ifi = calloc(1, sizeof(struct interface_info))) == NULL)
		error("calloc");
	if (strlcpy(ifi->name, interface, IFNAMSIZ) >= IFNAMSIZ)
		error("Interface name too long");
	if (path_dhclient_db == NULL) {
		if (lease_db != NULL)
			path_dhclient_db = strdup(lease_db);
		else if (asprintf(&path_dhclient_db, "%s.%s", _PATH_DHCLIENT_DB,
		    ifi->name) == -1)
			error("asprintf");
	}

	read_client_conf();

	if (hook_script != NULL)
		top_level_config.script_name = strdup(hook_script);

	if (!interface_link_status(ifi->name))
		warning("%s: no link yet; continuing, carrier watch active",
		    ifi->name);
	ifi->linkstat = 1;

	if (gethostname(hostname, sizeof(hostname)) < 0)
		hostname[0] = '\0';

	/* set up the interface */
	discover_interfaces(ifi);

	/* Read persisted leases (BSD used O_EXLOCK; lease-file locking is
	   the daemon's concern on Linux). */
	/* An empty lease DB means the daemon opted out of the file entirely: the
	   core then starts with no stored lease (plan §6 lease_file: none). */
	if (path_dhclient_db != NULL && *path_dhclient_db != '\0') {
		if ((fd = open(path_dhclient_db, O_RDONLY | O_CREAT, 0644)) == -1)
			error("can't open %s: %m", path_dhclient_db);
		read_client_leases();
		rewrite_client_leases();
		close(fd);
	}

	/* rtnetlink link/address watch (replaces BSD PF_ROUTE). */
	if ((routefd = linux_route_socket()) != -1)
		add_protocol("AF_NETLINK", routefd, routehandler, ifi);

	ifi->client->state = S_INIT;
	bootp_packet_handler = do_packet;
	if (core_preset_set)
		resume_on_preset(ifi);
	else
		state_reboot(ifi);

	return (0);
}

/*
 * Daemon integration: re-enter the engine on a different interface (config
 * reload, plan §6). The old interface's protocol registrations are dropped and
 * their fds closed — the daemon drops them from its own epoll set first — the
 * interface identity is re-discovered (which reopens the packet and raw-UDP
 * sockets and re-registers it), the lease-db path follows the new interface
 * name, and the state machine re-enters on the lease we already hold
 * (INIT-SELECT when there is none). The rtnetlink watch is untouched.
 *
 * Refuses without touching anything when the interface is absent. An interface
 * that is present but has no carrier is accepted, exactly as at startup: the
 * core keeps a carrier watch on it (SIOCGIFFLAGS cannot report IFF_LOWER_UP, so
 * a carrier check here would refuse every live interface).
 */
int
dhcp_core_restart(const char *interface, const char *lease_db)
{
	char *db = NULL;

	if (ifi == NULL || ifi->client == NULL)
		return (-1);
	if (strlen(interface) >= IFNAMSIZ)
		return (-1);
	if (if_nametoindex(interface) == 0) {
		warning("dhcp_core_restart: %s: not found", interface);
		return (-1);
	}
	if (lease_db != NULL) {
		db = strdup(lease_db); /* may be empty: lease DB opted out */
	} else {
		if (asprintf(&db, "%s.%s", _PATH_DHCLIENT_DB, interface) == -1)
			db = NULL;
	}
	if (db == NULL)
		return (-1);

	/* The daemon has already dropped these fds from its epoll set. */
	dhcp_core_drop_interface(ifi);

	free(path_dhclient_db);
	path_dhclient_db = db;

	strlcpy(ifi->name, interface, IFNAMSIZ);
	if (ifi->ifp != NULL) {
		free(ifi->ifp);
		ifi->ifp = NULL;
	}
	ifi->index = (u_int16_t)if_nametoindex(ifi->name);
	ifi->errors = 0;
	ifi->dead = 0;
	ifi->linkstat = 1;

	note("re-entering on %s (config reload)", ifi->name);
	discover_interfaces(ifi);

	ifi->client->state = S_INIT;
	state_reboot(ifi);

	return (0);
}

/*
 * Daemon integration (plan §4): re-enter the state machine after a role flip
 * back to master. The core is inited once and kept across demotions, so its
 * timeouts froze while the daemon was not pumping it; simply re-registering its
 * fds would let a stale reboot timer fire and DISCOVER a new address. Cancel
 * those timeouts, advance the clock to now, and re-enter on the lease we already
 * hold: the next action is the renewal that is due now (unicast to the pinned
 * server-id), not a DISCOVER. The daemon passes its aged view of the remaining
 * timers so the deadlines are relative to now, not the frozen pre-demotion
 * clock (all three come from the same lease; a negative t3_s means "not pushed"
 * and the held lease's own times are kept). With no lease held, reboot as usual.
 */
int
dhcp_core_resume(const char *interface, long t1_s, long t2_s, long t3_s)
{
	struct interface_info *ip;

	if (interface == NULL)
		return (-1);
	for (ip = ifi; ip != NULL; ip = ip->next) {
		if (strcmp(ip->name, interface) != 0 || ip->client == NULL)
			continue;
		clock_gettime(CLOCK_MONOTONIC, &time_now);
		cur_time = time_now.tv_sec;
		cancel_timeouts_for(ip);
		paced_cancel(ip);
		if (ip->client->active != NULL && !ip->client->active->is_bootp) {
			if (t3_s >= 0) {
				ip->client->active->renewal = cur_time + (t1_s > 0 ? t1_s : 0);
				ip->client->active->rebind = cur_time + (t2_s > 0 ? t2_s : 0);
				ip->client->active->expiry = cur_time + t3_s;
			}
			ip->client->state = S_BOUND;
			note("resuming on the held lease after promotion: %s",
			    piaddr(ip->client->active->address));
			state_bound(ip);
		} else {
			ip->client->state = S_INIT;
			note("no lease to resume on after promotion: rebooting");
			state_reboot(ip);
		}
		return (0);
	}
	return (-1);
}

int
dhcp_core_force_discover(const char *interface)
{
	struct interface_info *ip;

	if (interface == NULL)
		return (-1);
	for (ip = ifi; ip != NULL; ip = ip->next) {
		if (strcmp(ip->name, interface) != 0 || ip->client == NULL)
			continue;
		cancel_timeouts_for(ip);
		paced_cancel(ip);
		ip->client->state = S_INIT;
		note("forcing a new DISCOVER on %s", ip->name);
		state_init(ip);
		return (0);
	}
	return (-1);
}

int
dhcp_core_force_renew(const char *interface)
{
	struct interface_info *ip;

	if (interface == NULL)
		return (-1);
	for (ip = ifi; ip != NULL; ip = ip->next) {
		if (strcmp(ip->name, interface) != 0 || ip->client == NULL)
			continue;
		if (ip->client->active == NULL || ip->client->active->is_bootp)
			return (-1);
		clock_gettime(CLOCK_MONOTONIC, &time_now);
		cur_time = time_now.tv_sec;
		cancel_timeouts_for(ip);
		paced_cancel(ip);
		ip->client->state = S_BOUND;
		note("forcing a RENEW on %s", ip->name);
		state_bound(ip);
		return (0);
	}
	return (-1);
}

void
usage(void)
{

	fprintf(stderr, "usage: %s [-bdnqu] ", getprogname());
	fprintf(stderr, "[-c conffile] [-l leasefile] interface\n");
	exit(1);
}

/*
 * Individual States:
 *
 * Each routine is called from the dhclient_state_machine() in one of
 * these conditions:
 * -> entering INIT state
 * -> recvpacket_flag == 0: timeout in this state
 * -> otherwise: received a packet in this state
 *
 * Return conditions as handled by dhclient_state_machine():
 * Returns 1, sendpacket_flag = 1: send packet, reset timer.
 * Returns 1, sendpacket_flag = 0: just reset the timer (wait for a milestone).
 * Returns 0: finish the nap which was interrupted for no good reason.
 *
 * Several per-interface variables are used to keep track of the process:
 *   active_lease: the lease that is being used on the interface
 *                 (null pointer if not configured yet).
 *   offered_leases: leases corresponding to DHCPOFFER messages that have
 *                   been sent to us by DHCP servers.
 *   acked_leases: leases corresponding to DHCPACK messages that have been
 *                 sent to us by DHCP servers.
 *   sendpacket: DHCP packet we're trying to send.
 *   destination: IP address to send sendpacket to
 * In addition, there are several relevant per-lease variables.
 *   T1_expiry, T2_expiry, lease_expiry: lease milestones
 * In the active lease, these control the process of renewing the lease;
 * In leases on the acked_leases list, this simply determines when we
 * can no longer legitimately use the lease.
 */

void
state_reboot(void *ipp)
{
	struct interface_info *ip = ipp;

	paced_cancel(ip);

	/* If we don't remember an active lease, go straight to INIT. */
	if (!ip->client->active || ip->client->active->is_bootp) {
		state_init(ip);
		return;
	}

	/* We are in the rebooting state. */
	ip->client->state = S_REBOOTING;

	/* make_request doesn't initialize xid because it normally comes
	   from the DHCPDISCOVER, but we haven't sent a DHCPDISCOVER,
	   so pick an xid now. */
	ip->client->xid = arc4random();
	core_xid_known = 1;

	/* Make a DHCPREQUEST packet, and set appropriate per-interface
	   flags. */
	make_request(ip, ip->client->active);
	ip->client->destination = iaddr_broadcast;
	ip->client->first_sending = cur_time;
	ip->client->interval = ip->client->config->initial_interval;

	/* Zap the medium list... */
	ip->client->medium = NULL;

	/* Send out the first DHCPREQUEST packet. */
	send_request(ip);
}

/*
 * Called when a lease has completely expired and we've
 * been unable to renew it.
 */
void
state_init(void *ipp)
{
	struct interface_info *ip = ipp;

	paced_cancel(ip);
	ASSERT_STATE(state, S_INIT);

	/* Make a DHCPDISCOVER packet, and set appropriate per-interface
	   flags. */
	make_discover(ip, ip->client->active);
	ip->client->xid = ip->client->packet.xid;
	core_xid_known = 1;
	ip->client->destination = iaddr_broadcast;
	ip->client->state = S_SELECTING;
	ip->client->first_sending = cur_time;
	ip->client->interval = ip->client->config->initial_interval;

	/* Add an immediate timeout to cause the first DHCPDISCOVER packet
	   to go out. */
	send_discover(ip);
}

/*
 * state_selecting is called when one or more DHCPOFFER packets
 * have been received and a configurable period of time has passed.
 */
void
state_selecting(void *ipp)
{
	struct interface_info *ip = ipp;
	struct client_lease *lp, *next, *picked;

	ASSERT_STATE(state, S_SELECTING);

	/* Cancel state_selecting and send_discover timeouts, since either
	   one could have got us here. */
	cancel_timeout(state_selecting, ip);
	cancel_timeout(send_discover, ip);

	/* We have received one or more DHCPOFFER packets.   Currently,
	   the only criterion by which we judge leases is whether or
	   not we get a response when we arp for them. */
	picked = NULL;
	for (lp = ip->client->offered_leases; lp; lp = next) {
		next = lp->next;

		/* Check to see if we got an ARPREPLY for the address
		   in this particular lease. */
		if (!picked) {
			/* An offer for the address we already hold is not a
			   conflict: the ARPCHECK would only answer ourselves. */
			if (ip->client->active &&
			    lp->address.len == ip->client->active->address.len &&
			    !memcmp(lp->address.iabuf,
			    ip->client->active->address.iabuf, lp->address.len)) {
				picked = lp;
				picked->next = NULL;
				continue;
			}
			script_init("ARPCHECK", lp->medium);
			script_write_params("check_", lp);

			/* If the ARPCHECK code detects another
			   machine using the offered address, it exits
			   nonzero.  We need to send a DHCPDECLINE and
			   toss the lease. */
			if (script_go()) {
				debug("offer of %s ignored: ARPCHECK found "
				    "another user, declining",
				    piaddr(lp->address));
				make_decline(ip, lp);
				send_decline(ip);
				goto freeit;
			}
			picked = lp;
			picked->next = NULL;
		} else {
freeit:
			free_client_lease(lp);
		}
	}
	ip->client->offered_leases = NULL;

	/* If we just tossed all the leases we were offered, go back
	   to square one. */
	if (!picked) {
		ip->client->state = S_INIT;
		state_init(ip);
		return;
	}

	/* If it was a BOOTREPLY, we can just take the address right now. */
	if (!picked->options[DHO_DHCP_MESSAGE_TYPE].len) {
		ip->client->new = picked;

		/* Make up some lease expiry times
		   XXX these should be configurable. */
		ip->client->new->expiry = cur_time + 12000;
		ip->client->new->renewal += cur_time + 8000;
		ip->client->new->rebind += cur_time + 10000;

		ip->client->state = S_REQUESTING;

		/* Bind to the address we received. */
		bind_lease(ip);
		return;
	}

	/* Go to the REQUESTING state. */
	ip->client->destination = iaddr_broadcast;
	ip->client->state = S_REQUESTING;
	ip->client->first_sending = cur_time;
	ip->client->interval = ip->client->config->initial_interval;

	/* Make a DHCPREQUEST packet from the lease we picked. */
	make_request(ip, picked);
	ip->client->xid = ip->client->packet.xid;

	/* Toss the lease we picked - we'll get it back in a DHCPACK. */
	free_client_lease(picked);

	/* Add an immediate timeout to send the first DHCPREQUEST packet. */
	send_request(ip);
}

/* state_requesting is called when we receive a DHCPACK message after
   having sent out one or more DHCPREQUEST packets. */

void
dhcpack(struct packet *packet)
{
	struct interface_info *ip = packet->interface;
	struct client_lease *lease;

	/* If we're not receptive to an offer right now, or if the offer
	   has an unrecognizable transaction id, then just drop it. */
	if (packet->interface->client->xid != packet->raw->xid) {
		debug("DHCPACK from %s ignored: xid 0x%x != our xid 0x%x",
		    piaddr(packet->client_addr), packet->raw->xid,
		    packet->interface->client->xid);
		return;
	}
	if ((packet->interface->hw_address.hlen != packet->raw->hlen) ||
	    (memcmp(packet->interface->hw_address.haddr,
	    packet->raw->chaddr, packet->raw->hlen))) {
		debug("DHCPACK from %s ignored: chaddr does not match ours",
		    piaddr(packet->client_addr));
		return;
	}

	if (ip->client->state != S_REBOOTING &&
	    ip->client->state != S_REQUESTING &&
	    ip->client->state != S_RENEWING &&
	    ip->client->state != S_REBINDING) {
		debug("DHCPACK from %s ignored: state is %s",
		    piaddr(packet->client_addr),
		    state_names[ip->client->state]);
		return;
	}

	note("DHCPACK from %s", piaddr(packet->client_addr));

	lease = packet_to_lease(packet);
	if (!lease) {
		note("packet_to_lease failed.");
		return;
	}

	ip->client->new = lease;

	/* Stop resending DHCPREQUEST. */
	cancel_timeout(send_request, ip);

	/* Figure out the lease time. */
        if (ip->client->config->default_actions[DHO_DHCP_LEASE_TIME] ==
            ACTION_SUPERSEDE)
		ip->client->new->expiry = getULong(
		    ip->client->config->defaults[DHO_DHCP_LEASE_TIME].data);
        else if (ip->client->new->options[DHO_DHCP_LEASE_TIME].len >= 4)
		ip->client->new->expiry = getULong(
		    ip->client->new->options[DHO_DHCP_LEASE_TIME].data);
	else
		ip->client->new->expiry = default_lease_time;
	/* A number that looks negative here is really just very large,
	   because the lease expiry offset is unsigned. Also make sure that
           the addition of cur_time below does not overflow (a 32 bit) time_t. */
	if (ip->client->new->expiry < 0 ||
            ip->client->new->expiry > TIME_MAX - cur_time)
		ip->client->new->expiry = TIME_MAX - cur_time;
	/* XXX should be fixed by resetting the client state */
	if (ip->client->new->expiry < 60)
		ip->client->new->expiry = 60;

        /* Unless overridden in the config, take the server-provided renewal
         * time if there is one. Otherwise figure it out according to the spec.
         * Also make sure the renewal time does not exceed the expiry time.
         */
        if (ip->client->config->default_actions[DHO_DHCP_RENEWAL_TIME] ==
            ACTION_SUPERSEDE)
		ip->client->new->renewal = getULong(
		    ip->client->config->defaults[DHO_DHCP_RENEWAL_TIME].data);
        else if (ip->client->new->options[DHO_DHCP_RENEWAL_TIME].len >= 4)
		ip->client->new->renewal = getULong(
		    ip->client->new->options[DHO_DHCP_RENEWAL_TIME].data);
	else
		ip->client->new->renewal = ip->client->new->expiry / 2;
        if (ip->client->new->renewal < 0 ||
            ip->client->new->renewal > ip->client->new->expiry / 2)
                ip->client->new->renewal = ip->client->new->expiry / 2;

	/* Same deal with the rebind time. */
        if (ip->client->config->default_actions[DHO_DHCP_REBINDING_TIME] ==
            ACTION_SUPERSEDE)
		ip->client->new->rebind = getULong(
		    ip->client->config->defaults[DHO_DHCP_REBINDING_TIME].data);
        else if (ip->client->new->options[DHO_DHCP_REBINDING_TIME].len >= 4)
		ip->client->new->rebind = getULong(
		    ip->client->new->options[DHO_DHCP_REBINDING_TIME].data);
	else
		ip->client->new->rebind = ip->client->new->renewal / 4 * 7;
	if (ip->client->new->rebind < 0 ||
            ip->client->new->rebind > ip->client->new->renewal / 4 * 7)
                ip->client->new->rebind = ip->client->new->renewal / 4 * 7;

        /* Convert the time offsets into seconds-since-the-epoch */
        ip->client->new->expiry += cur_time;
        ip->client->new->renewal += cur_time;
        ip->client->new->rebind += cur_time;

	bind_lease(ip);
}

void
bind_lease(struct interface_info *ip)
{
	struct option_data *opt;

	/* Remember the medium. */
	ip->client->new->medium = ip->client->medium;

	opt = &ip->client->new->options[DHO_INTERFACE_MTU];
	if (opt->len == sizeof(u_int16_t)) {
		u_int16_t mtu = 0;
		u_int16_t old_mtu = 0;
		bool supersede = (ip->client->config->default_actions[DHO_INTERFACE_MTU] ==
			ACTION_SUPERSEDE);

		if (supersede)
			mtu = getUShort(ip->client->config->defaults[DHO_INTERFACE_MTU].data);
		else
			mtu = be16dec(opt->data);

		if (ip->client->active) {
			opt = &ip->client->active->options[DHO_INTERFACE_MTU];
			if (opt->len == sizeof(u_int16_t)) {
				old_mtu = be16dec(opt->data);
			}
		}

		if (mtu < MIN_MTU) {
			/* Treat 0 like a user intentionally doesn't want to change MTU and,
			 * therefore, warning is not needed */
			if (!supersede || mtu != 0)
				warning("mtu size %u < %d: ignored", (unsigned)mtu, MIN_MTU);
		} else if (ip->client->state != S_RENEWING || mtu != old_mtu) {
			interface_set_mtu_unpriv(privfd, mtu);
		}
	}

	/* Write out the new lease. */
	write_client_lease(ip, ip->client->new, 0);

	/* Run the client script with the new parameters. */
	{
		const char *reason = (ip->client->state == S_REQUESTING ?
		    "BOUND" :
		    (ip->client->state == S_RENEWING ? "RENEW" :
		    (ip->client->state == S_REBOOTING ? "REBOOT" : "REBIND")));

		script_init(reason, ip->client->new->medium);
		if (ip->client->active && ip->client->state != S_REBOOTING)
			script_write_params("old_", ip->client->active);
		script_write_params("new_", ip->client->new);
		if (ip->client->alias)
			script_write_params("alias_", ip->client->alias);
		script_go();
		if (retention_active) {
			note("lease restored: leaving RETAINED");
			retention_active = 0;
			if (core_on_reason != NULL)
				core_on_reason(core_on_arg, "RETAINED-EXIT",
				    ip->client->new);
		}
		if (core_on_reason != NULL)
			core_on_reason(core_on_arg, reason, ip->client->new);
	}

	/* Replace the old active lease with the new one. */
	if (ip->client->active)
		free_client_lease(ip->client->active);
	ip->client->active = ip->client->new;
	ip->client->new = NULL;

	/* Set up a timeout to start the renewal process. */
	add_timeout(ip->client->active->renewal, state_bound, ip);

	note("bound to %s -- renewal in %d seconds.",
	    piaddr(ip->client->active->address),
	    (int)(ip->client->active->renewal - cur_time));
	ip->client->state = S_BOUND;
	reinitialize_interfaces();
	go_daemon();
}

/*
 * state_bound is called when we've successfully bound to a particular
 * lease, but the renewal time on that lease has expired.   We are
 * expected to unicast a DHCPREQUEST to the server that gave us our
 * original lease.
 */
void
state_bound(void *ipp)
{
	struct interface_info *ip = ipp;
	u_int8_t *dp = NULL;
	int len;

	ASSERT_STATE(state, S_BOUND);

	/* T1 has expired. */
	make_request(ip, ip->client->active);
	ip->client->xid = ip->client->packet.xid;

	if (ip->client->config->default_actions[DHO_DHCP_SERVER_IDENTIFIER] ==
	    ACTION_SUPERSEDE) {
		dp = ip->client->config->defaults[DHO_DHCP_SERVER_IDENTIFIER].data;
		len = ip->client->config->defaults[DHO_DHCP_SERVER_IDENTIFIER].len;
	} else {
		dp = ip->client->active->options[DHO_DHCP_SERVER_IDENTIFIER].data;
		len = ip->client->active->options[DHO_DHCP_SERVER_IDENTIFIER].len;
	}
	if (len == 4) {
		memcpy(ip->client->destination.iabuf, dp, len);
		ip->client->destination.len = len;
	} else
		ip->client->destination = iaddr_broadcast;

	ip->client->first_sending = cur_time;
	ip->client->interval = ip->client->config->initial_interval;
	ip->client->state = S_RENEWING;

	/* Send the first packet immediately. */
	send_request(ip);
}

void
bootp(struct packet *packet)
{
	struct iaddrlist *ap;

	if (packet->raw->op != BOOTREPLY)
		return;

	/* If there's a reject list, make sure this packet's sender isn't
	   on it. */
	for (ap = packet->interface->client->config->reject_list;
	    ap; ap = ap->next) {
		if (addr_eq(packet->client_addr, ap->addr)) {
			note("BOOTREPLY from %s rejected.", piaddr(ap->addr));
			return;
		}
	}
	dhcpoffer(packet);
}

void
dhcp(struct packet *packet)
{
	struct iaddrlist *ap;
	void (*handler)(struct packet *);
	const char *type;

	switch (packet->packet_type) {
	case DHCPOFFER:
		handler = dhcpoffer;
		type = "DHCPOFFER";
		break;
	case DHCPNAK:
		handler = dhcpnak;
		type = "DHCPNACK";
		break;
	case DHCPACK:
		handler = dhcpack;
		type = "DHCPACK";
		break;
	default:
		return;
	}

	/* If there's a reject list, make sure this packet's sender isn't
	   on it. */
	for (ap = packet->interface->client->config->reject_list;
	    ap; ap = ap->next) {
		if (addr_eq(packet->client_addr, ap->addr)) {
			note("%s from %s rejected.", type, piaddr(ap->addr));
			return;
		}
	}
	(*handler)(packet);
}

void
dhcpoffer(struct packet *packet)
{
	struct interface_info *ip = packet->interface;
	struct client_lease *lease, *lp;
	int i;
	struct timespec arp_timeout_needed;
	struct timespec stop_selecting = { .tv_sec = 0, .tv_nsec = 0 };
	time_now.tv_sec = cur_time;
	time_now.tv_nsec = 0;

	const char *name = packet->options[DHO_DHCP_MESSAGE_TYPE].len ?
	    "DHCPOFFER" : "BOOTREPLY";
	int answered_request = 0;

	/* If we're not receptive to an offer right now, or if the offer
	   has an unrecognizable transaction id, then just drop it. */
	if (ip->client->state != S_SELECTING) {
		/* A server that cannot honour our renewal answers the
		   REQUEST with an OFFER for a new lease; the xid check
		   below proves this one answers our transaction, so take
		   it when a renewal is in flight, or with retention on
		   (the failed renew is being retried on the
		   last-known-good lease). */
		if (!(core_retention && (ip->client->state == S_RENEWING ||
		    ip->client->state == S_REBINDING ||
		    ip->client->state == S_BOUND))) {
			debug("%s from %s ignored: state is %s, not SELECTING",
			    name, piaddr(packet->client_addr),
			    state_names[ip->client->state]);
			return;
		}
		answered_request = 1;
	}
	if (packet->interface->client->xid != packet->raw->xid) {
		debug("%s from %s ignored: xid 0x%x != our xid 0x%x",
		    name, piaddr(packet->client_addr),
		    packet->raw->xid, packet->interface->client->xid);
		return;
	}
	if ((packet->interface->hw_address.hlen != packet->raw->hlen) ||
	    (memcmp(packet->interface->hw_address.haddr,
	    packet->raw->chaddr, packet->raw->hlen))) {
		debug("%s from %s ignored: chaddr does not match ours",
		    name, piaddr(packet->client_addr));
		return;
	}

	note("%s from %s", name, piaddr(packet->client_addr));


	/* If this lease doesn't supply the minimum required parameters,
	   blow it off. */
	for (i = 0; ip->client->config->required_options[i]; i++) {
		if (!packet->options[ip->client->config->
		    required_options[i]].len) {
			note("%s isn't satisfactory.", name);
			return;
		}
	}

	/* If we've already seen this lease, don't record it again. */
	for (lease = ip->client->offered_leases;
	    lease; lease = lease->next) {
		if (lease->address.len == sizeof(packet->raw->yiaddr) &&
		    !memcmp(lease->address.iabuf,
		    &packet->raw->yiaddr, lease->address.len)) {
			debug("%s already seen (%s).", name,
			    piaddr(lease->address));
			return;
		}
	}

	lease = packet_to_lease(packet);
	if (!lease) {
		note("packet_to_lease failed.");
		return;
	}

	/* If this lease was acquired through a BOOTREPLY, record that
	   fact. */
	if (!packet->options[DHO_DHCP_MESSAGE_TYPE].len)
		lease->is_bootp = 1;

	/* Record the medium under which this lease was offered. */
	lease->medium = ip->client->medium;

	/* Send out an ARP Request for the offered IP address. */
	script_init("ARPSEND", lease->medium);
	script_write_params("check_", lease);
	/* If the script can't send an ARP request without waiting,
	   we'll be waiting when we do the ARPCHECK, so don't wait now. */
	if (script_go())
		arp_timeout_needed = zero_timespec;

	else
		arp_timeout_needed = arp_timeout;

	/* Figure out when we're supposed to stop selecting. */
	stop_selecting.tv_sec =
	    ip->client->first_sending + ip->client->config->select_interval;

	/* If this is the lease we asked for, put it at the head of the
	   list, and don't mess with the arp request timeout. */
	if (lease->address.len == ip->client->requested_address.len &&
	    !memcmp(lease->address.iabuf,
	    ip->client->requested_address.iabuf,
	    ip->client->requested_address.len)) {
		lease->next = ip->client->offered_leases;
		ip->client->offered_leases = lease;
	} else {
		/* If we already have an offer, and arping for this
		   offer would take us past the selection timeout,
		   then don't extend the timeout - just hope for the
		   best. */

		struct timespec interm_struct;
		timespecadd(&time_now, &arp_timeout_needed, &interm_struct);

		if (ip->client->offered_leases &&
		    timespeccmp(&interm_struct, &stop_selecting, >))
			arp_timeout_needed = zero_timespec;

		/* Put the lease at the end of the list. */
		lease->next = NULL;
		if (!ip->client->offered_leases)
			ip->client->offered_leases = lease;
		else {
			for (lp = ip->client->offered_leases; lp->next;
			    lp = lp->next)
				;	/* nothing */
			lp->next = lease;
		}
	}

	/* Accepted straight from a bound/renewal state: this offer answered
	   the REQUEST we sent, so there is no selection window to wait
	   for — pick it now. Stop resending the renewal REQUEST first. */
	if (answered_request) {
		cancel_timeout(send_request, ip);
		ip->client->state = S_SELECTING;
		state_selecting(ip);
		return;
	}

	/* If we're supposed to stop selecting before we've had time
	   to wait for the ARPREPLY, add some delay to wait for
	   the ARPREPLY. */
	struct timespec time_left;
	timespecsub(&stop_selecting, &time_now, &time_left);

	if (timespeccmp(&time_left, &arp_timeout_needed, <)) {
		timespecadd(&time_now, &arp_timeout_needed, &stop_selecting);
	}

	/* If the selecting interval has expired, go immediately to
	   state_selecting().  Otherwise, time out into
	   state_selecting at the select interval. */


	if (timespeccmp(&stop_selecting, &zero_timespec, <=))
		state_selecting(ip);
	else {
		add_timeout_timespec(stop_selecting, state_selecting, ip);
		cancel_timeout(send_discover, ip);
	}
}

/* Allocate a client_lease structure and initialize it from the parameters
   in the specified packet. */

struct client_lease *
packet_to_lease(struct packet *packet)
{
	struct client_lease *lease;
	int i;

	lease = malloc(sizeof(struct client_lease));

	if (!lease) {
		warning("dhcpoffer: no memory to record lease.");
		return (NULL);
	}

	memset(lease, 0, sizeof(*lease));

	/* Copy the lease options. */
	for (i = 0; i < 256; i++) {
		if (packet->options[i].len) {
			lease->options[i].data =
			    malloc(packet->options[i].len + 1);
			if (!lease->options[i].data) {
				warning("dhcpoffer: no memory for option %d", i);
				free_client_lease(lease);
				return (NULL);
			} else {
				memcpy(lease->options[i].data,
				    packet->options[i].data,
				    packet->options[i].len);
				lease->options[i].len =
				    packet->options[i].len;
				lease->options[i].data[lease->options[i].len] =
				    0;
			}
			if (!check_option(lease,i)) {
				/* ignore a bogus lease offer */
				warning("Invalid lease option - ignoring offer");
				free_client_lease(lease);
				return (NULL);
			}
		}
	}

	lease->address.len = sizeof(packet->raw->yiaddr);
	memcpy(lease->address.iabuf, &packet->raw->yiaddr, lease->address.len);

	lease->nextserver.len = sizeof(packet->raw->siaddr);
	memcpy(lease->nextserver.iabuf, &packet->raw->siaddr, lease->nextserver.len);

	/* If the server name was filled out, copy it.
	   Do not attempt to validate the server name as a host name.
	   RFC 2131 merely states that sname is NUL-terminated (which do
	   do not assume) and that it is the server's host name.  Since
	   the ISC client and server allow arbitrary characters, we do
	   as well. */
	if ((!packet->options[DHO_DHCP_OPTION_OVERLOAD].len ||
	    !(packet->options[DHO_DHCP_OPTION_OVERLOAD].data[0] & 2)) &&
	    packet->raw->sname[0]) {
		lease->server_name = malloc(DHCP_SNAME_LEN + 1);
		if (!lease->server_name) {
			warning("dhcpoffer: no memory for server name.");
			free_client_lease(lease);
			return (NULL);
		}
		memcpy(lease->server_name, packet->raw->sname, DHCP_SNAME_LEN);
		lease->server_name[DHCP_SNAME_LEN]='\0';
	}

	/* Ditto for the filename. */
	if ((!packet->options[DHO_DHCP_OPTION_OVERLOAD].len ||
	    !(packet->options[DHO_DHCP_OPTION_OVERLOAD].data[0] & 1)) &&
	    packet->raw->file[0]) {
		/* Don't count on the NUL terminator. */
		lease->filename = malloc(DHCP_FILE_LEN + 1);
		if (!lease->filename) {
			warning("dhcpoffer: no memory for filename.");
			free_client_lease(lease);
			return (NULL);
		}
		memcpy(lease->filename, packet->raw->file, DHCP_FILE_LEN);
		lease->filename[DHCP_FILE_LEN]='\0';
	}
	return lease;
}

/* Retention only: a NAK that answers the persisted lease we resumed on. We
   never generated that transaction id in this lifetime, so the only proof it
   is about us is that it comes from the server the lease is pinned to
   (RFC 2131: only that server can relinquish the lease) and is for our
   hardware address. Relayed NAKs often carry no server identifier, so the
   packet source stands in for it. */
static int
nak_answers_persisted_lease(struct interface_info *ip, struct packet *packet)
{
	struct option_data *ours, *theirs;
	struct in_addr ours_id, from;

	if (core_xid_known || ip->client->active == NULL)
		return (0);
	ours = &ip->client->active->options[DHO_DHCP_SERVER_IDENTIFIER];
	if (ours->len != 4)
		return (0);
	memcpy(&ours_id, ours->data, 4);
	theirs = &packet->options[DHO_DHCP_SERVER_IDENTIFIER];
	if (theirs->len == 4)
		memcpy(&from, theirs->data, 4);
	else if (packet->client_addr.len == 4)
		memcpy(&from, packet->client_addr.iabuf, 4);
	else
		return (0);
	return (memcmp(&ours_id, &from, 4) == 0);
}

void
dhcpnak(struct packet *packet)
{
	struct interface_info *ip = packet->interface;
	int answers_persisted = core_retention &&
	    nak_answers_persisted_lease(ip, packet);

	/* If we're not receptive to an offer right now, or if the offer
	   has an unrecognizable transaction id, then just drop it. */
	if (packet->interface->client->xid != packet->raw->xid &&
	    !answers_persisted) {
		debug("DHCPNAK from %s ignored: xid 0x%x != our xid 0x%x",
		    piaddr(packet->client_addr), packet->raw->xid,
		    packet->interface->client->xid);
		return;
	}
	if ((packet->interface->hw_address.hlen != packet->raw->hlen) ||
	    (memcmp(packet->interface->hw_address.haddr,
	    packet->raw->chaddr, packet->raw->hlen))) {
		debug("DHCPNAK from %s ignored: chaddr does not match ours",
		    piaddr(packet->client_addr));
		return;
	}

	if (ip->client->state != S_REBOOTING &&
	    ip->client->state != S_REQUESTING &&
	    ip->client->state != S_RENEWING &&
	    ip->client->state != S_REBINDING &&
	    !(answers_persisted && ip->client->state == S_BOUND)) {
		debug("DHCPNAK from %s ignored: state is %s",
		    piaddr(packet->client_addr),
		    state_names[ip->client->state]);
		return;
	}

	note("DHCPNAK from %s%s", piaddr(packet->client_addr),
	    answers_persisted ? " (answers the lease we resumed on)" : "");

	if (!ip->client->active) {
		note("DHCPNAK with no active lease.");
	} else {
		free_client_lease(ip->client->active);
		ip->client->active = NULL;
	}

	/* Stop sending DHCPREQUEST packets... */
	cancel_timeout(send_request, ip);

	ip->client->state = S_INIT;
	state_init(ip);
}

/* Send out a DHCPDISCOVER packet, and set a timeout to send out another
   one after the right interval has expired.  If we don't get an offer by
   the time we reach the panic interval, call the panic function. */

void
send_discover(void *ipp)
{
	struct interface_info *ip = ipp;
	int interval, increase = 1;

	/* Figure out how long it's been since we started transmitting. */
	interval = cur_time - ip->client->first_sending;

	/* If we're past the panic timeout, call the script and tell it
	   we haven't found anything for this interface yet. */
	if (interval > ip->client->config->timeout) {
		state_panic(ip);
		return;
	}

	/* If we're selecting media, try the whole list before doing
	   the exponential backoff, but if we've already received an
	   offer, stop looping, because we obviously have it right. */
	if (!ip->client->offered_leases &&
	    ip->client->config->media) {
		int fail = 0;
again:
		if (ip->client->medium) {
			ip->client->medium = ip->client->medium->next;
			increase = 0;
		}
		if (!ip->client->medium) {
			if (fail)
				error("No valid media types for %s!", ip->name);
			ip->client->medium = ip->client->config->media;
			increase = 1;
		}

		note("Trying medium \"%s\" %d", ip->client->medium->string,
		    increase);
		script_init("MEDIUM", ip->client->medium);
		if (script_go())
			goto again;
	}

	/*
	 * If we're supposed to increase the interval, do so.  If it's
	 * currently zero (i.e., we haven't sent any packets yet), set
	 * it to one; otherwise, add to it a random number between zero
	 * and two times itself.  On average, this means that it will
	 * double with every transmission.
	 */
	if (increase) {
		if (!ip->client->interval)
			ip->client->interval =
			    ip->client->config->initial_interval;
		else {
			ip->client->interval += (arc4random() >> 2) %
			    (2 * ip->client->interval);
		}

		/* Don't backoff past cutoff. */
		if (ip->client->interval >
		    ip->client->config->backoff_cutoff)
			ip->client->interval =
				((ip->client->config->backoff_cutoff / 2)
				 + ((arc4random() >> 2) %
				    ip->client->config->backoff_cutoff));
	} else if (!ip->client->interval)
		ip->client->interval =
			ip->client->config->initial_interval;

	/* If the backoff would take us to the panic timeout, just use that
	   as the interval. */
	if (cur_time + ip->client->interval >
	    ip->client->first_sending + ip->client->config->timeout)
		ip->client->interval =
			(ip->client->first_sending +
			 ip->client->config->timeout) - cur_time + 1;

	/* Never retry faster than the send pacing window allows. */
	if (paced_min_interval() > ip->client->interval)
		ip->client->interval = paced_min_interval();

	/* Record the number of seconds since we started sending. */
	if (interval < 65536)
		ip->client->packet.secs = htons(interval);
	else
		ip->client->packet.secs = htons(65535);
	ip->client->secs = ip->client->packet.secs;

	note("DHCPDISCOVER on %s to %s port %d interval %d",
	    ip->name, inet_ntoa(inaddr_broadcast), REMOTE_PORT,
	    (int)ip->client->interval);

	/* Send out a packet. */
	{
		int delay = paced_send_packet(ip, inaddr_any, inaddr_broadcast);
		if (delay > 0)
			ip->client->first_sending += delay;
	}

	add_timeout(cur_time + ip->client->interval, send_discover, ip);
}

/*
 * state_panic gets called if we haven't received any offers in a preset
 * amount of time.   When this happens, we try to use existing leases
 * that haven't yet expired, and failing that, we call the client script
 * and hope it can do something.
 */
void
state_panic(void *ipp)
{
	struct interface_info *ip = ipp;
	struct client_lease *loop = ip->client->active;
	struct client_lease *lp;

	note("No DHCPOFFERS received.");

	/* We may not have an active lease, but we may have some
	   predefined leases that we can try. */
	if (!ip->client->active && ip->client->leases)
		goto activate_next;

	/* Run through the list of leases and see if one can be used. */
	while (ip->client->active) {
		if (ip->client->active->expiry > cur_time) {
			note("Trying recorded lease %s",
			    piaddr(ip->client->active->address));
			/* Run the client script with the existing
			   parameters. */
			script_init("TIMEOUT",
			    ip->client->active->medium);
			script_write_params("new_", ip->client->active);
			if (ip->client->alias)
				script_write_params("alias_",
				    ip->client->alias);

			/* If the old lease is still good and doesn't
			   yet need renewal, go into BOUND state and
			   timeout at the renewal time. */
			if (!script_go()) {
				if (core_on_reason != NULL)
					core_on_reason(core_on_arg, "TIMEOUT",
					    ip->client->active);
				if (cur_time <
				    ip->client->active->renewal) {
					ip->client->state = S_BOUND;
					note("bound: renewal in %d seconds.",
					    (int)(ip->client->active->renewal -
					    cur_time));
					add_timeout(
					    ip->client->active->renewal,
					    state_bound, ip);
				} else {
					ip->client->state = S_BOUND;
					note("bound: immediate renewal.");
					state_bound(ip);
				}
				reinitialize_interfaces();
				go_daemon();
				return;
			}
		}

		/* If there are no other leases, give up. */
		if (!ip->client->leases) {
			ip->client->leases = ip->client->active;
			ip->client->active = NULL;
			break;
		}

activate_next:
		/* Otherwise, put the active lease at the end of the
		   lease list, and try another lease.. */
		for (lp = ip->client->leases; lp->next; lp = lp->next)
			;
		lp->next = ip->client->active;
		if (lp->next)
			lp->next->next = NULL;
		ip->client->active = ip->client->leases;
		ip->client->leases = ip->client->leases->next;

		/* If we already tried this lease, we've exhausted the
		   set of leases, so we might as well give up for
		   now. */
		if (ip->client->active == loop)
			break;
		else if (!loop)
			loop = ip->client->active;
	}

	/* No leases were available, or what was available didn't work, so
	   tell the shell script that we failed to allocate an address,
	   and try again later. */
	note("No working leases in persistent database - sleeping.\n");
	script_init("FAIL", NULL);
	if (ip->client->alias)
		script_write_params("alias_", ip->client->alias);
	script_go();
	if (core_on_reason != NULL)
		core_on_reason(core_on_arg, "FAIL", NULL);
	ip->client->state = S_INIT;
	add_timeout(cur_time + ip->client->config->retry_interval, state_init,
	    ip);
	go_daemon();
}

void
send_request(void *ipp)
{
	struct interface_info *ip = ipp;
	struct in_addr from, to;
	int interval;

	/* Figure out how long it's been since we started transmitting. */
	interval = cur_time - ip->client->first_sending;

	/* If we're in the INIT-REBOOT or REQUESTING state and we're
	   past the reboot timeout, go to INIT and see if we can
	   DISCOVER an address... */
	/* XXX In the INIT-REBOOT state, if we don't get an ACK, it
	   means either that we're on a network with no DHCP server,
	   or that our server is down.  In the latter case, assuming
	   that there is a backup DHCP server, DHCPDISCOVER will get
	   us a new address, but we could also have successfully
	   reused our old address.  In the former case, we're hosed
	   anyway.  This is not a win-prone situation. */
	if ((ip->client->state == S_REBOOTING ||
	    ip->client->state == S_REQUESTING) &&
	    interval > ip->client->config->reboot_timeout) {
		debug("no answer after %d s (reboot timeout %d s): "
		    "going back to INIT", interval,
		    (int)ip->client->config->reboot_timeout);
cancel:
		ip->client->state = S_INIT;
		cancel_timeout(send_request, ip);
		state_init(ip);
		return;
	}

	/* If we're in the reboot state, make sure the media is set up
	   correctly. */
	if (ip->client->state == S_REBOOTING &&
	    !ip->client->medium &&
	    ip->client->active->medium ) {
		script_init("MEDIUM", ip->client->active->medium);

		/* If the medium we chose won't fly, go to INIT state. */
		if (script_go())
			goto cancel;

		/* Record the medium. */
		ip->client->medium = ip->client->active->medium;
	}

	/* If the lease has expired, relinquish the address and go back
	   to the INIT state. */
	if (ip->client->state != S_REQUESTING &&
	    cur_time > ip->client->active->expiry) {
		debug("lease %s expired (expiry %d s ago) in state %s: "
		    "relinquishing", piaddr(ip->client->active->address),
		    (int)(cur_time - ip->client->active->expiry),
		    state_names[ip->client->state]);
		/* Retention beats expiry (plan §5): keep the last-known-good
		   configuration applied and keep trying. */
		if (core_retention) {
			retention_enter(ip);
			if (core_retention_rediscover) {
				ip->client->state = S_INIT;
				state_init(ip);
				return;
			}
			ip->client->state = S_BOUND;
			state_bound(ip);
			return;
		}

		/* Run the client script with the new parameters. */
		script_init("EXPIRE", NULL);
		script_write_params("old_", ip->client->active);
		if (ip->client->alias)
			script_write_params("alias_", ip->client->alias);
		script_go();
		if (core_on_reason != NULL)
			core_on_reason(core_on_arg, "EXPIRE",
			    ip->client->active);

		/* Now do a preinit on the interface so that we can
		   discover a new address. */
		script_init("PREINIT", NULL);
		if (ip->client->alias)
			script_write_params("alias_", ip->client->alias);
		script_go();

		ip->client->state = S_INIT;
		state_init(ip);
		return;
	}

	/* Renewal retries use the configured fixed interval (default 30 s);
	   the initial acquisition path keeps the exponential backoff. */
	if (core_renew_retry_interval_s > 0 &&
	    (ip->client->state == S_RENEWING ||
	     ip->client->state == S_REBINDING))
		ip->client->interval = core_renew_retry_interval_s;
	else if (!ip->client->interval)
		ip->client->interval = ip->client->config->initial_interval;
	else
		ip->client->interval += ((arc4random() >> 2) %
		    (2 * ip->client->interval));

	/* Don't backoff past cutoff. */
	if (ip->client->interval >
	    ip->client->config->backoff_cutoff &&
	    !(core_renew_retry_interval_s > 0 &&
	    (ip->client->state == S_RENEWING ||
	     ip->client->state == S_REBINDING)))
		ip->client->interval =
		    ((ip->client->config->backoff_cutoff / 2) +
		    ((arc4random() >> 2) % ip->client->interval));

	/* If the backoff would take us to the expiry time, just set the
	   timeout to the expiry time. */
	if (ip->client->state != S_REQUESTING &&
	    cur_time + ip->client->interval >
	    ip->client->active->expiry)
		ip->client->interval =
		    ip->client->active->expiry - cur_time + 1;

	/* Never retry faster than the send pacing window allows. */
	if (paced_min_interval() > ip->client->interval)
		ip->client->interval = paced_min_interval();

	/* If the lease T2 time has elapsed, or if we're not yet bound,
	   broadcast the DHCPREQUEST rather than unicasting. */
	if (ip->client->state == S_REQUESTING ||
	    ip->client->state == S_REBOOTING ||
	    cur_time > ip->client->active->rebind)
		to.s_addr = INADDR_BROADCAST;
	else
		memcpy(&to.s_addr, ip->client->destination.iabuf,
		    sizeof(to.s_addr));

	if (ip->client->state != S_REQUESTING &&
	    ip->client->state != S_REBOOTING)
		memcpy(&from, ip->client->active->address.iabuf,
		    sizeof(from));
	else
		from.s_addr = INADDR_ANY;

	/* Record the number of seconds since we started sending. */
	if (ip->client->state == S_REQUESTING)
		ip->client->packet.secs = ip->client->secs;
	else {
		if (interval < 65536)
			ip->client->packet.secs = htons(interval);
		else
			ip->client->packet.secs = htons(65535);
	}

	note("DHCPREQUEST on %s to %s port %d", ip->name, inet_ntoa(to),
	    REMOTE_PORT);

	/* Send out a packet. */
	{
		int delay = paced_send_packet(ip, from, to);
		if (delay > 0 &&
		    (ip->client->state == S_REQUESTING ||
		     ip->client->state == S_REBOOTING))
			ip->client->first_sending += delay;
	}

	add_timeout(cur_time + ip->client->interval, send_request, ip);
}

void
send_decline(void *ipp)
{
	struct interface_info *ip = ipp;

	note("DHCPDECLINE on %s to %s port %d", ip->name,
	    inet_ntoa(inaddr_broadcast), REMOTE_PORT);

	/* Send out a packet. */
	(void)paced_send_packet(ip, inaddr_any, inaddr_broadcast);
}

void
make_discover(struct interface_info *ip, struct client_lease *lease)
{
	unsigned char discover = DHCPDISCOVER;
	struct tree_cache *options[256];
	struct tree_cache option_elements[256];
	int i;

	memset(option_elements, 0, sizeof(option_elements));
	memset(options, 0, sizeof(options));
	memset(&ip->client->packet, 0, sizeof(ip->client->packet));

	/* Set DHCP_MESSAGE_TYPE to DHCPDISCOVER */
	i = DHO_DHCP_MESSAGE_TYPE;
	options[i] = &option_elements[i];
	options[i]->value = &discover;
	options[i]->len = sizeof(discover);
	options[i]->buf_size = sizeof(discover);
	options[i]->timeout = 0xFFFFFFFF;

	/* Request the options we want */
	i  = DHO_DHCP_PARAMETER_REQUEST_LIST;
	options[i] = &option_elements[i];
	options[i]->value = ip->client->config->requested_options;
	options[i]->len = ip->client->config->requested_option_count;
	options[i]->buf_size =
		ip->client->config->requested_option_count;
	options[i]->timeout = 0xFFFFFFFF;

	/* If we had an address, try to get it again. */
	if (lease) {
		ip->client->requested_address = lease->address;
		i = DHO_DHCP_REQUESTED_ADDRESS;
		options[i] = &option_elements[i];
		options[i]->value = lease->address.iabuf;
		options[i]->len = lease->address.len;
		options[i]->buf_size = lease->address.len;
		options[i]->timeout = 0xFFFFFFFF;
	} else
		ip->client->requested_address.len = 0;

	/* Send any options requested in the config file. */
	for (i = 0; i < 256; i++)
		if (!options[i] &&
		    ip->client->config->send_options[i].data) {
			options[i] = &option_elements[i];
			options[i]->value =
			    ip->client->config->send_options[i].data;
			options[i]->len =
			    ip->client->config->send_options[i].len;
			options[i]->buf_size =
			    ip->client->config->send_options[i].len;
			options[i]->timeout = 0xFFFFFFFF;
		}

	/* send host name if not set via config file. */
	if (!options[DHO_HOST_NAME]) {
		if (hostname[0] != '\0') {
			size_t len;
			char* posDot = strchr(hostname, '.');
			if (posDot != NULL)
				len = posDot - hostname;
			else
				len = strlen(hostname);
			options[DHO_HOST_NAME] = &option_elements[DHO_HOST_NAME];
			options[DHO_HOST_NAME]->value = (unsigned char *)hostname;
			options[DHO_HOST_NAME]->len = len;
			options[DHO_HOST_NAME]->buf_size = len;
			options[DHO_HOST_NAME]->timeout = 0xFFFFFFFF;
		}
	}

	/* set unique client identifier */
	char client_ident[sizeof(ip->hw_address.haddr) + 1];
	if (!options[DHO_DHCP_CLIENT_IDENTIFIER]) {
		int hwlen = (ip->hw_address.hlen < sizeof(client_ident)-1) ?
				ip->hw_address.hlen : sizeof(client_ident)-1;
		client_ident[0] = ip->hw_address.htype;
		memcpy(&client_ident[1], ip->hw_address.haddr, hwlen);
		options[DHO_DHCP_CLIENT_IDENTIFIER] = &option_elements[DHO_DHCP_CLIENT_IDENTIFIER];
		options[DHO_DHCP_CLIENT_IDENTIFIER]->value = (unsigned char *)client_ident;
		options[DHO_DHCP_CLIENT_IDENTIFIER]->len = hwlen+1;
		options[DHO_DHCP_CLIENT_IDENTIFIER]->buf_size = hwlen+1;
		options[DHO_DHCP_CLIENT_IDENTIFIER]->timeout = 0xFFFFFFFF;
	}

	/* Set up the option buffer... */
	ip->client->packet_length = cons_options(NULL, &ip->client->packet, 0,
	    options, 0, 0, 0, NULL, 0);
	if (ip->client->packet_length < BOOTP_MIN_LEN)
		ip->client->packet_length = BOOTP_MIN_LEN;

	ip->client->packet.op = BOOTREQUEST;
	ip->client->packet.htype = ip->hw_address.htype;
	ip->client->packet.hlen = ip->hw_address.hlen;
	ip->client->packet.hops = 0;
	ip->client->packet.xid = arc4random();
	ip->client->packet.secs = 0; /* filled in by send_discover. */
	ip->client->packet.flags = 0;

	memset(&(ip->client->packet.ciaddr),
	    0, sizeof(ip->client->packet.ciaddr));
	memset(&(ip->client->packet.yiaddr),
	    0, sizeof(ip->client->packet.yiaddr));
	memset(&(ip->client->packet.siaddr),
	    0, sizeof(ip->client->packet.siaddr));
	memset(&(ip->client->packet.giaddr),
	    0, sizeof(ip->client->packet.giaddr));
	memcpy(ip->client->packet.chaddr,
	    ip->hw_address.haddr, ip->hw_address.hlen);
}


void
make_request(struct interface_info *ip, struct client_lease * lease)
{
	unsigned char request = DHCPREQUEST;
	struct tree_cache *options[256];
	struct tree_cache option_elements[256];
	int i;

	memset(options, 0, sizeof(options));
	memset(&ip->client->packet, 0, sizeof(ip->client->packet));

	/* Set DHCP_MESSAGE_TYPE to DHCPREQUEST */
	i = DHO_DHCP_MESSAGE_TYPE;
	options[i] = &option_elements[i];
	options[i]->value = &request;
	options[i]->len = sizeof(request);
	options[i]->buf_size = sizeof(request);
	options[i]->timeout = 0xFFFFFFFF;

	/* Request the options we want */
	i = DHO_DHCP_PARAMETER_REQUEST_LIST;
	options[i] = &option_elements[i];
	options[i]->value = ip->client->config->requested_options;
	options[i]->len = ip->client->config->requested_option_count;
	options[i]->buf_size =
		ip->client->config->requested_option_count;
	options[i]->timeout = 0xFFFFFFFF;

	/* If we are requesting an address that hasn't yet been assigned
	   to us, use the DHCP Requested Address option. */
	if (ip->client->state == S_REQUESTING) {
		/* Send back the server identifier... */
		i = DHO_DHCP_SERVER_IDENTIFIER;
		options[i] = &option_elements[i];
		options[i]->value = lease->options[i].data;
		options[i]->len = lease->options[i].len;
		options[i]->buf_size = lease->options[i].len;
		options[i]->timeout = 0xFFFFFFFF;
	}
	if (ip->client->state == S_REQUESTING ||
	    ip->client->state == S_REBOOTING) {
		ip->client->requested_address = lease->address;
		i = DHO_DHCP_REQUESTED_ADDRESS;
		options[i] = &option_elements[i];
		options[i]->value = lease->address.iabuf;
		options[i]->len = lease->address.len;
		options[i]->buf_size = lease->address.len;
		options[i]->timeout = 0xFFFFFFFF;
	} else
		ip->client->requested_address.len = 0;

	/* Send any options requested in the config file. */
	for (i = 0; i < 256; i++)
		if (!options[i] &&
		    ip->client->config->send_options[i].data) {
			options[i] = &option_elements[i];
			options[i]->value =
			    ip->client->config->send_options[i].data;
			options[i]->len =
			    ip->client->config->send_options[i].len;
			options[i]->buf_size =
			    ip->client->config->send_options[i].len;
			options[i]->timeout = 0xFFFFFFFF;
		}

	/* send host name if not set via config file. */
	if (!options[DHO_HOST_NAME]) {
		if (hostname[0] != '\0') {
			size_t len;
			char* posDot = strchr(hostname, '.');
			if (posDot != NULL)
				len = posDot - hostname;
			else
				len = strlen(hostname);
			options[DHO_HOST_NAME] = &option_elements[DHO_HOST_NAME];
			options[DHO_HOST_NAME]->value = (unsigned char *)hostname;
			options[DHO_HOST_NAME]->len = len;
			options[DHO_HOST_NAME]->buf_size = len;
			options[DHO_HOST_NAME]->timeout = 0xFFFFFFFF;
		}
	}

	/* set unique client identifier */
	char client_ident[sizeof(ip->hw_address.haddr) + 1];
	if (!options[DHO_DHCP_CLIENT_IDENTIFIER]) {
		int hwlen = (ip->hw_address.hlen < sizeof(client_ident)-1) ?
				ip->hw_address.hlen : sizeof(client_ident)-1;
		client_ident[0] = ip->hw_address.htype;
		memcpy(&client_ident[1], ip->hw_address.haddr, hwlen);
		options[DHO_DHCP_CLIENT_IDENTIFIER] = &option_elements[DHO_DHCP_CLIENT_IDENTIFIER];
		options[DHO_DHCP_CLIENT_IDENTIFIER]->value = (unsigned char *)client_ident;
		options[DHO_DHCP_CLIENT_IDENTIFIER]->len = hwlen+1;
		options[DHO_DHCP_CLIENT_IDENTIFIER]->buf_size = hwlen+1;
		options[DHO_DHCP_CLIENT_IDENTIFIER]->timeout = 0xFFFFFFFF;
	}

	/* Set up the option buffer... */
	ip->client->packet_length = cons_options(NULL, &ip->client->packet, 0,
	    options, 0, 0, 0, NULL, 0);
	if (ip->client->packet_length < BOOTP_MIN_LEN)
		ip->client->packet_length = BOOTP_MIN_LEN;

	ip->client->packet.op = BOOTREQUEST;
	ip->client->packet.htype = ip->hw_address.htype;
	ip->client->packet.hlen = ip->hw_address.hlen;
	ip->client->packet.hops = 0;
	ip->client->packet.xid = ip->client->xid;
	ip->client->packet.secs = 0; /* Filled in by send_request. */

	/* If we own the address we're requesting, put it in ciaddr;
	   otherwise set ciaddr to zero. */
	if (ip->client->state == S_BOUND ||
	    ip->client->state == S_RENEWING ||
	    ip->client->state == S_REBINDING) {
		memcpy(&ip->client->packet.ciaddr,
		    lease->address.iabuf, lease->address.len);
		ip->client->packet.flags = 0;
	} else {
		memset(&ip->client->packet.ciaddr, 0,
		    sizeof(ip->client->packet.ciaddr));
		ip->client->packet.flags = 0;
	}

	memset(&ip->client->packet.yiaddr, 0,
	    sizeof(ip->client->packet.yiaddr));
	memset(&ip->client->packet.siaddr, 0,
	    sizeof(ip->client->packet.siaddr));
	memset(&ip->client->packet.giaddr, 0,
	    sizeof(ip->client->packet.giaddr));
	memcpy(ip->client->packet.chaddr,
	    ip->hw_address.haddr, ip->hw_address.hlen);
}

void
make_decline(struct interface_info *ip, struct client_lease *lease)
{
	struct tree_cache *options[256], message_type_tree;
	struct tree_cache requested_address_tree;
	struct tree_cache server_id_tree, client_id_tree;
	unsigned char decline = DHCPDECLINE;
	int i;

	memset(options, 0, sizeof(options));
	memset(&ip->client->packet, 0, sizeof(ip->client->packet));

	/* Set DHCP_MESSAGE_TYPE to DHCPDECLINE */
	i = DHO_DHCP_MESSAGE_TYPE;
	options[i] = &message_type_tree;
	options[i]->value = &decline;
	options[i]->len = sizeof(decline);
	options[i]->buf_size = sizeof(decline);
	options[i]->timeout = 0xFFFFFFFF;

	/* Send back the server identifier... */
	i = DHO_DHCP_SERVER_IDENTIFIER;
	options[i] = &server_id_tree;
	options[i]->value = lease->options[i].data;
	options[i]->len = lease->options[i].len;
	options[i]->buf_size = lease->options[i].len;
	options[i]->timeout = 0xFFFFFFFF;

	/* Send back the address we're declining. */
	i = DHO_DHCP_REQUESTED_ADDRESS;
	options[i] = &requested_address_tree;
	options[i]->value = lease->address.iabuf;
	options[i]->len = lease->address.len;
	options[i]->buf_size = lease->address.len;
	options[i]->timeout = 0xFFFFFFFF;

	/* Send the uid if the user supplied one. */
	i = DHO_DHCP_CLIENT_IDENTIFIER;
	if (ip->client->config->send_options[i].len) {
		options[i] = &client_id_tree;
		options[i]->value = ip->client->config->send_options[i].data;
		options[i]->len = ip->client->config->send_options[i].len;
		options[i]->buf_size = ip->client->config->send_options[i].len;
		options[i]->timeout = 0xFFFFFFFF;
	}


	/* Set up the option buffer... */
	ip->client->packet_length = cons_options(NULL, &ip->client->packet, 0,
	    options, 0, 0, 0, NULL, 0);
	if (ip->client->packet_length < BOOTP_MIN_LEN)
		ip->client->packet_length = BOOTP_MIN_LEN;

	ip->client->packet.op = BOOTREQUEST;
	ip->client->packet.htype = ip->hw_address.htype;
	ip->client->packet.hlen = ip->hw_address.hlen;
	ip->client->packet.hops = 0;
	ip->client->packet.xid = ip->client->xid;
	ip->client->packet.secs = 0; /* Filled in by send_request. */
	ip->client->packet.flags = 0;

	/* ciaddr must always be zero. */
	memset(&ip->client->packet.ciaddr, 0,
	    sizeof(ip->client->packet.ciaddr));
	memset(&ip->client->packet.yiaddr, 0,
	    sizeof(ip->client->packet.yiaddr));
	memset(&ip->client->packet.siaddr, 0,
	    sizeof(ip->client->packet.siaddr));
	memset(&ip->client->packet.giaddr, 0,
	    sizeof(ip->client->packet.giaddr));
	memcpy(ip->client->packet.chaddr,
	    ip->hw_address.haddr, ip->hw_address.hlen);
}

void
free_client_lease(struct client_lease *lease)
{
	int i;

	if (lease->server_name)
		free(lease->server_name);
	if (lease->filename)
		free(lease->filename);
	for (i = 0; i < 256; i++) {
		if (lease->options[i].len)
			free(lease->options[i].data);
	}
	free(lease);
}

static FILE *leaseFile;

void
rewrite_client_leases(void)
{
	struct client_lease *lp;

	if (path_dhclient_db == NULL || *path_dhclient_db == '\0')
		return; /* lease DB opted out (plan §6 lease_file: none) */

	if (!leaseFile) {
		leaseFile = fopen(path_dhclient_db, "w");
		if (!leaseFile)
			error("can't create %s: %m", path_dhclient_db);
	} else {
		fflush(leaseFile);
		rewind(leaseFile);
	}

	for (lp = ifi->client->leases; lp; lp = lp->next)
		write_client_lease(ifi, lp, 1);
	if (ifi->client->active)
		write_client_lease(ifi, ifi->client->active, 1);

	fflush(leaseFile);
	ftruncate(fileno(leaseFile), ftello(leaseFile));
	fsync(fileno(leaseFile));
}

/*
 * The daemon runs its timers on CLOCK_MONOTONIC (plan §8), so the lease
 * struct's renewal/rebind/expiry are monotonic-based. The lease file keeps
 * dhclient-compatible wall-clock stamps, so convert at the file boundary using
 * this offset — sampled once so the round-trip is stable.
 */
time_t
dhcp_monotonic_to_epoch_offset(void)
{
	static time_t offset;
	struct timespec mono, real;

	if (offset == 0) {
		clock_gettime(CLOCK_MONOTONIC, &mono);
		clock_gettime(CLOCK_REALTIME, &real);
		offset = real.tv_sec - mono.tv_sec;
	}
	return (offset);
}

time_t
dhcp_mono_to_file_time(time_t mono)
{
	time_t off = dhcp_monotonic_to_epoch_offset();

	if (mono > 0 && off > 0 && mono > TIME_MAX - off)
		return (TIME_MAX);
	return (mono + off);
}

time_t
dhcp_file_to_mono_time(time_t epoch)
{
	return (epoch - dhcp_monotonic_to_epoch_offset());
}

void
write_client_lease(struct interface_info *ip, struct client_lease *lease,
    int rewrite)
{
	static int leases_written;
	struct tm *t;
	time_t when;
	int i;

	if (!rewrite) {
		if (leases_written++ > 20) {
			rewrite_client_leases();
			leases_written = 0;
		}
	}

	if (path_dhclient_db == NULL || *path_dhclient_db == '\0')
		return; /* lease DB opted out (plan §6 lease_file: none) */

	/* If the lease came from the config file, we don't need to stash
	   a copy in the lease database. */
	if (lease->is_static)
		return;

	if (!leaseFile) {	/* XXX */
		leaseFile = fopen(path_dhclient_db, "w");
		if (!leaseFile)
			error("can't create %s: %m", path_dhclient_db);
	}

	fprintf(leaseFile, "lease {\n");
	if (lease->is_bootp)
		fprintf(leaseFile, "  bootp;\n");
	fprintf(leaseFile, "  interface \"%s\";\n", ip->name);
	fprintf(leaseFile, "  fixed-address %s;\n", piaddr(lease->address));
	if (lease->nextserver.len == sizeof(inaddr_any) &&
	    0 != memcmp(lease->nextserver.iabuf, &inaddr_any,
	    sizeof(inaddr_any)))
		fprintf(leaseFile, "  next-server %s;\n",
		    piaddr(lease->nextserver));
	if (lease->filename)
		fprintf(leaseFile, "  filename \"%s\";\n", lease->filename);
	if (lease->server_name)
		fprintf(leaseFile, "  server-name \"%s\";\n",
		    lease->server_name);
	if (lease->medium)
		fprintf(leaseFile, "  medium \"%s\";\n", lease->medium->string);
	for (i = 0; i < 256; i++)
		if (lease->options[i].len)
			fprintf(leaseFile, "  option %s %s;\n",
			    dhcp_options[i].name,
			    pretty_print_option(i, lease->options[i].data,
			    lease->options[i].len, 1, 1));

	when = dhcp_mono_to_file_time(lease->renewal);
	t = gmtime(&when);
	fprintf(leaseFile, "  renew %d %d/%d/%d %02d:%02d:%02d;\n",
	    t->tm_wday, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
	    t->tm_hour, t->tm_min, t->tm_sec);
	when = dhcp_mono_to_file_time(lease->rebind);
	t = gmtime(&when);
	fprintf(leaseFile, "  rebind %d %d/%d/%d %02d:%02d:%02d;\n",
	    t->tm_wday, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
	    t->tm_hour, t->tm_min, t->tm_sec);
	when = dhcp_mono_to_file_time(lease->expiry);
	t = gmtime(&when);
	fprintf(leaseFile, "  expire %d %d/%d/%d %02d:%02d:%02d;\n",
	    t->tm_wday, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
	    t->tm_hour, t->tm_min, t->tm_sec);
	fprintf(leaseFile, "}\n");
	fflush(leaseFile);
}

void
script_init(const char *reason, struct string_list *medium)
{
	/* Single process on Linux: the BSD privsep imsg hop is direct. */
	priv_script_init(reason, medium != NULL ? medium->string : NULL);
}

void
priv_script_init(const char *reason, char *medium)
{
	struct interface_info *ip = ifi;

	if (ip) {
		ip->client->scriptEnvsize = 100;
		if (ip->client->scriptEnv == NULL)
			ip->client->scriptEnv =
			    malloc(ip->client->scriptEnvsize * sizeof(char *));
		if (ip->client->scriptEnv == NULL)
			error("script_init: no memory for environment");

		ip->client->scriptEnv[0] = strdup(CLIENT_PATH);
		if (ip->client->scriptEnv[0] == NULL)
			error("script_init: no memory for environment");

		ip->client->scriptEnv[1] = NULL;

		script_set_env(ip->client, "", "interface", ip->name);

		if (medium)
			script_set_env(ip->client, "", "medium", medium);

		script_set_env(ip->client, "", "reason", reason);
	}
}

void
priv_script_write_params(const char *prefix, struct client_lease *lease)
{
	struct interface_info *ip = ifi;
	u_int8_t dbuf[1500], *dp = NULL;
	int i;
	size_t len;
	char tbuf[128];

	script_set_env(ip->client, prefix, "ip_address",
	    piaddr(lease->address));

	if (ip->client->config->default_actions[DHO_SUBNET_MASK] ==
	    ACTION_SUPERSEDE) {
		dp = ip->client->config->defaults[DHO_SUBNET_MASK].data;
		len = ip->client->config->defaults[DHO_SUBNET_MASK].len;
	} else {
		dp = lease->options[DHO_SUBNET_MASK].data;
		len = lease->options[DHO_SUBNET_MASK].len;
	}
	if (len && (len < sizeof(lease->address.iabuf))) {
		struct iaddr netmask, subnet, broadcast;

		memcpy(netmask.iabuf, dp, len);
		netmask.len = len;
		subnet = subnet_number(lease->address, netmask);
		if (subnet.len) {
			script_set_env(ip->client, prefix, "network_number",
			    piaddr(subnet));
			if (!lease->options[DHO_BROADCAST_ADDRESS].len) {
				broadcast = broadcast_addr(subnet, netmask);
				if (broadcast.len)
					script_set_env(ip->client, prefix,
					    "broadcast_address",
					    piaddr(broadcast));
			}
		}
	}

	if (lease->filename)
		script_set_env(ip->client, prefix, "filename", lease->filename);
	if (lease->server_name)
		script_set_env(ip->client, prefix, "server_name",
		    lease->server_name);
	for (i = 0; i < 256; i++) {
		len = 0;

		if (ip->client->config->defaults[i].len) {
			if (lease->options[i].len) {
				switch (
				    ip->client->config->default_actions[i]) {
				case ACTION_DEFAULT:
					dp = lease->options[i].data;
					len = lease->options[i].len;
					break;
				case ACTION_SUPERSEDE:
supersede:
					dp = ip->client->
						config->defaults[i].data;
					len = ip->client->
						config->defaults[i].len;
					break;
				case ACTION_PREPEND:
					len = ip->client->
					    config->defaults[i].len +
					    lease->options[i].len;
					if (len >= sizeof(dbuf)) {
						warning("no space to %s %s",
						    "prepend option",
						    dhcp_options[i].name);
						goto supersede;
					}
					dp = dbuf;
					memcpy(dp,
						ip->client->
						config->defaults[i].data,
						ip->client->
						config->defaults[i].len);
					memcpy(dp + ip->client->
						config->defaults[i].len,
						lease->options[i].data,
						lease->options[i].len);
					dp[len] = '\0';
					break;
				case ACTION_APPEND:
					/*
					 * When we append, we assume that we're
					 * appending to text.  Some MS servers
					 * include a NUL byte at the end of
					 * the search string provided.
					 */
					len = ip->client->
					    config->defaults[i].len +
					    lease->options[i].len;
					if (len >= sizeof(dbuf)) {
						warning("no space to %s %s",
						    "append option",
						    dhcp_options[i].name);
						goto supersede;
					}
					memcpy(dbuf,
						lease->options[i].data,
						lease->options[i].len);
					for (dp = dbuf + lease->options[i].len;
					    dp > dbuf; dp--, len--)
						if (dp[-1] != '\0')
							break;
					memcpy(dp,
						ip->client->
						config->defaults[i].data,
						ip->client->
						config->defaults[i].len);
					dp = dbuf;
					dp[len] = '\0';
				}
			} else {
				dp = ip->client->
					config->defaults[i].data;
				len = ip->client->
					config->defaults[i].len;
			}
		} else if (lease->options[i].len) {
			len = lease->options[i].len;
			dp = lease->options[i].data;
		} else {
			len = 0;
		}
		if (len) {
			char name[256];

			if (dhcp_option_ev_name(name, sizeof(name),
			    &dhcp_options[i]))
				script_set_env(ip->client, prefix, name,
				    pretty_print_option(i, dp, len, 0, 0));
		}
	}
	snprintf(tbuf, sizeof(tbuf), "%d", (int)lease->expiry);
	script_set_env(ip->client, prefix, "expiry", tbuf);
}

void
script_write_params(const char *prefix, struct client_lease *lease)
{
	/* Single process on Linux: the BSD privsep imsg hop is direct. */
	scripttime = time(NULL);
	priv_script_write_params(prefix, lease);
}

int
script_go(void)
{
	return (priv_script_go());
}

int
priv_script_go(void)
{
	char *scriptName, *argv[2], **envp, *epp[3], reason[] = "REASON=NBI";
	static char client_path[] = CLIENT_PATH;
	struct interface_info *ip = ifi;
	int pid, wpid, wstatus;

	scripttime = time(NULL);

	if (ip) {
		scriptName = ip->client->config->script_name;
		envp = ip->client->scriptEnv;
	} else {
		scriptName = top_level_config.script_name;
		epp[0] = reason;
		epp[1] = client_path;
		epp[2] = NULL;
		envp = epp;
	}

	if (scriptName == NULL || scriptName[0] == '\0') {
		/* No hook configured: accept the outcome (dhclient-script
		   compatible dispatch happens in the daemon executor). */
		if (ip)
			script_flush_env(ip->client);
		return (0);
	}

	argv[0] = scriptName;
	argv[1] = NULL;

	pid = fork();
	if (pid < 0) {
		error("fork: %m");
		wstatus = 0;
	} else if (pid) {
		do {
			wpid = wait(&wstatus);
		} while (wpid != pid && wpid > 0);
		if (wpid < 0) {
			error("wait: %m");
			wstatus = 0;
		}
	} else {
		execve(scriptName, argv, envp);
		error("execve (%s, ...): %m", scriptName);
	}

	if (ip)
		script_flush_env(ip->client);

	return (WIFEXITED(wstatus) ?
	    WEXITSTATUS(wstatus) : 128 + WTERMSIG(wstatus));
}

void
script_set_env(struct client_state *client, const char *prefix,
    const char *name, const char *value)
{
	int i, namelen;
	size_t j;

	/* No `` or $() command substitution allowed in environment values! */
	for (j=0; j < strlen(value); j++)
		switch (value[j]) {
		case '`':
		case '$':
			warning("illegal character (%c) in value '%s'",
			    value[j], value);
			/* Ignore this option */
			return;
		}

	namelen = strlen(name);

	for (i = 0; client->scriptEnv[i]; i++)
		if (strncmp(client->scriptEnv[i], name, namelen) == 0 &&
		    client->scriptEnv[i][namelen] == '=')
			break;

	if (client->scriptEnv[i])
		/* Reuse the slot. */
		free(client->scriptEnv[i]);
	else {
		/* New variable.  Expand if necessary. */
		if (i >= client->scriptEnvsize - 1) {
			char **newscriptEnv;
			int newscriptEnvsize = client->scriptEnvsize + 50;

			newscriptEnv = realloc(client->scriptEnv,
			    newscriptEnvsize);
			if (newscriptEnv == NULL) {
				free(client->scriptEnv);
				client->scriptEnv = NULL;
				client->scriptEnvsize = 0;
				error("script_set_env: no memory for variable");
			}
			client->scriptEnv = newscriptEnv;
			client->scriptEnvsize = newscriptEnvsize;
		}
		/* need to set the NULL pointer at end of array beyond
		   the new slot. */
		client->scriptEnv[i + 1] = NULL;
	}
	/* Allocate space and format the variable in the appropriate slot. */
	client->scriptEnv[i] = malloc(strlen(prefix) + strlen(name) + 1 +
	    strlen(value) + 1);
	if (client->scriptEnv[i] == NULL)
		error("script_set_env: no memory for variable assignment");
	snprintf(client->scriptEnv[i], strlen(prefix) + strlen(name) +
	    1 + strlen(value) + 1, "%s%s=%s", prefix, name, value);
}

void
script_flush_env(struct client_state *client)
{
	int i;

	for (i = 0; client->scriptEnv[i]; i++) {
		free(client->scriptEnv[i]);
		client->scriptEnv[i] = NULL;
	}
	client->scriptEnvsize = 0;
}

int
dhcp_option_ev_name(char *buf, size_t buflen, struct option *option)
{
	size_t i;

	for (i = 0; option->name[i]; i++) {
		if (i + 1 == buflen)
			return 0;
		if (option->name[i] == '-')
			buf[i] = '_';
		else
			buf[i] = option->name[i];
	}

	buf[i] = 0;
	return 1;
}

void
go_daemon(void)
{
	/* Daemonization is the daemon's business (systemd); the core runs
	   inside the daemon process, so this is a no-op on Linux. */
	no_daemon = 1;
}

int
check_option(struct client_lease *l, int option)
{
	const char *opbuf;
	const char *sbuf;

	/* we use this, since this is what gets passed to dhclient-script */

	opbuf = pretty_print_option(option, l->options[option].data,
	    l->options[option].len, 0, 0);

	sbuf = option_as_string(option, l->options[option].data,
	    l->options[option].len);

	switch (option) {
	case DHO_SUBNET_MASK:
	case DHO_TIME_SERVERS:
	case DHO_NAME_SERVERS:
	case DHO_ROUTERS:
	case DHO_DOMAIN_NAME_SERVERS:
	case DHO_LOG_SERVERS:
	case DHO_COOKIE_SERVERS:
	case DHO_LPR_SERVERS:
	case DHO_IMPRESS_SERVERS:
	case DHO_RESOURCE_LOCATION_SERVERS:
	case DHO_SWAP_SERVER:
	case DHO_BROADCAST_ADDRESS:
	case DHO_NIS_SERVERS:
	case DHO_NTP_SERVERS:
	case DHO_NETBIOS_NAME_SERVERS:
	case DHO_NETBIOS_DD_SERVER:
	case DHO_FONT_SERVERS:
	case DHO_DHCP_SERVER_IDENTIFIER:
	case DHO_NISPLUS_SERVERS:
	case DHO_MOBILE_IP_HOME_AGENT:
	case DHO_SMTP_SERVER:
	case DHO_POP_SERVER:
	case DHO_NNTP_SERVER:
	case DHO_WWW_SERVER:
	case DHO_FINGER_SERVER:
	case DHO_IRC_SERVER:
	case DHO_STREETTALK_SERVER:
	case DHO_STREETTALK_DA_SERVER:
		if (!ipv4addrs(opbuf)) {
			warning("Invalid IP address in option: %s", opbuf);
			return (0);
		}
		return (1)  ;
	case DHO_HOST_NAME:
	case DHO_NIS_DOMAIN:
	case DHO_NISPLUS_DOMAIN:
	case DHO_TFTP_SERVER_NAME:
		if (!res_hnok(sbuf)) {
			warning("Bogus Host Name option %d: %s (%s)", option,
			    sbuf, opbuf);
			l->options[option].len = 0;
			free(l->options[option].data);
		}
		return (1);
	case DHO_DOMAIN_NAME:
	case DHO_DOMAIN_SEARCH:
		if (!res_hnok(sbuf)) {
			if (!check_search(sbuf)) {
				warning("Bogus domain search list %d: %s (%s)",
				    option, sbuf, opbuf);
				l->options[option].len = 0;
				free(l->options[option].data);
			}
		}
		return (1);
	case DHO_PAD:
	case DHO_TIME_OFFSET:
	case DHO_BOOT_SIZE:
	case DHO_MERIT_DUMP:
	case DHO_ROOT_PATH:
	case DHO_EXTENSIONS_PATH:
	case DHO_IP_FORWARDING:
	case DHO_NON_LOCAL_SOURCE_ROUTING:
	case DHO_POLICY_FILTER:
	case DHO_MAX_DGRAM_REASSEMBLY:
	case DHO_DEFAULT_IP_TTL:
	case DHO_PATH_MTU_AGING_TIMEOUT:
	case DHO_PATH_MTU_PLATEAU_TABLE:
	case DHO_INTERFACE_MTU:
	case DHO_ALL_SUBNETS_LOCAL:
	case DHO_PERFORM_MASK_DISCOVERY:
	case DHO_MASK_SUPPLIER:
	case DHO_ROUTER_DISCOVERY:
	case DHO_ROUTER_SOLICITATION_ADDRESS:
	case DHO_STATIC_ROUTES:
	case DHO_TRAILER_ENCAPSULATION:
	case DHO_ARP_CACHE_TIMEOUT:
	case DHO_IEEE802_3_ENCAPSULATION:
	case DHO_DEFAULT_TCP_TTL:
	case DHO_TCP_KEEPALIVE_INTERVAL:
	case DHO_TCP_KEEPALIVE_GARBAGE:
	case DHO_VENDOR_ENCAPSULATED_OPTIONS:
	case DHO_NETBIOS_NODE_TYPE:
	case DHO_NETBIOS_SCOPE:
	case DHO_X_DISPLAY_MANAGER:
	case DHO_DHCP_REQUESTED_ADDRESS:
	case DHO_DHCP_LEASE_TIME:
	case DHO_DHCP_OPTION_OVERLOAD:
	case DHO_DHCP_MESSAGE_TYPE:
	case DHO_DHCP_PARAMETER_REQUEST_LIST:
	case DHO_DHCP_MESSAGE:
	case DHO_DHCP_MAX_MESSAGE_SIZE:
	case DHO_DHCP_RENEWAL_TIME:
	case DHO_DHCP_REBINDING_TIME:
	case DHO_DHCP_CLASS_IDENTIFIER:
	case DHO_DHCP_CLIENT_IDENTIFIER:
	case DHO_BOOTFILE_NAME:
	case DHO_DHCP_USER_CLASS_ID:
	case DHO_URL:
	case DHO_SIP_SERVERS:
	case DHO_V_I_VENDOR_CLASS:
	case DHO_V_I_VENDOR_OPTS:
	case DHO_END:
		return (1);
	case DHO_CLASSLESS_ROUTES:
		return (check_classless_option(l->options[option].data,
		    l->options[option].len));
	default:
		warning("unknown dhcp option value 0x%x", option);
		return (unknown_ok);
	}
}

/* RFC 3442 The Classless Static Routes option checks */
int
check_classless_option(unsigned char *data, int len)
{
	int i = 0;
	unsigned char width;
	in_addr_t addr, mask;

	if (len < 5) {
		warning("Too small length: %d", len);
		return (0);
	}
	while(i < len) {
		width = data[i++];
		if (width == 0) {
			i += 4;
			continue;
		} else if (width < 9) {
			addr =  (in_addr_t)(data[i]	<< 24);
			i += 1;
		} else if (width < 17) {
			addr =  (in_addr_t)(data[i]	<< 24) +
				(in_addr_t)(data[i + 1]	<< 16);
			i += 2;
		} else if (width < 25) {
			addr =  (in_addr_t)(data[i]	<< 24) +
				(in_addr_t)(data[i + 1]	<< 16) +
				(in_addr_t)(data[i + 2]	<< 8);
			i += 3;
		} else if (width < 33) {
			addr =  (in_addr_t)(data[i]	<< 24) +
				(in_addr_t)(data[i + 1]	<< 16) +
				(in_addr_t)(data[i + 2]	<< 8)  +
				data[i + 3];
			i += 4;
		} else {
			warning("Incorrect subnet width: %d", width);
			return (0);
		}
		mask = (in_addr_t)(~0) << (32 - width);
		addr = ntohl(addr);
		mask = ntohl(mask);

		/*
		 * From RFC 3442:
		 * ... After deriving a subnet number and subnet mask
		 * from each destination descriptor, the DHCP client
		 * MUST zero any bits in the subnet number where the
		 * corresponding bit in the mask is zero...
		 */
		if ((addr & mask) != addr) {
			addr &= mask;
			data[i - 1] = (unsigned char)(
				(addr >> (((32 - width)/8)*8)) & 0xFF);
		}
		i += 4;
	}
	if (i > len) {
		warning("Incorrect data length: %d (must be %d)", len, i);
		return (0);
	}
	return (1);
}

int
res_hnok(const char *dn)
{
	int pch = PERIOD, ch = *dn++;

	while (ch != '\0') {
		int nch = *dn++;

		if (periodchar(ch)) {
			;
		} else if (periodchar(pch)) {
			if (!borderchar(ch))
				return (0);
		} else if (periodchar(nch) || nch == '\0') {
			if (!borderchar(ch))
				return (0);
		} else {
			if (!middlechar(ch))
				return (0);
		}
		pch = ch, ch = nch;
	}
	return (1);
}

int
check_search(const char *srch)
{
        int pch = PERIOD, ch = *srch++;
	int domains = 1;

	/* 256 char limit re resolv.conf(5) */
	if (strlen(srch) > 256)
		return (0);

	while (whitechar(ch))
		ch = *srch++;

        while (ch != '\0') {
                int nch = *srch++;

                if (periodchar(ch) || whitechar(ch)) {
                        ;
                } else if (periodchar(pch)) {
                        if (!borderchar(ch))
                                return (0);
                } else if (periodchar(nch) || nch == '\0') {
                        if (!borderchar(ch))
                                return (0);
                } else {
                        if (!middlechar(ch))
                                return (0);
                }
		if (!whitechar(ch)) {
			pch = ch;
		} else {
			while (whitechar(nch)) {
				nch = *srch++;
			}
			if (nch != '\0')
				domains++;
			pch = PERIOD;
		}
		ch = nch;
        }
	/* 6 domain limit re resolv.conf(5) */
	if (domains > 6)
		return (0);
        return (1);
}

/* Does buf consist only of dotted decimal ipv4 addrs?
 * return how many if so,
 * otherwise, return 0
 */
int
ipv4addrs(const char * buf)
{
	struct in_addr jnk;
	int count = 0;

	/* musl's inet_aton rejects trailing text, so validate each
	 * space-separated address token instead of the whole buffer */
	while (*buf != '\0') {
		char tok[64];
		size_t n = 0;
		while (*buf != '\0' && *buf != ' ') {
			if (n + 1 >= sizeof(tok))
				return (0);
			tok[n++] = *buf++;
		}
		tok[n] = '\0';
		if (n == 0) {
			while (*buf == ' ')
				buf++;
			continue;
		}
		if (inet_aton(tok, &jnk) != 1)
			return (0);
		count++;
		while (*buf == ' ')
			buf++;
	}
	return (count);
}


const char *
option_as_string(unsigned int code, unsigned char *data, int len)
{
	static char optbuf[32768]; /* XXX */
	char *op = optbuf;
	int opleft = sizeof(optbuf);
	unsigned char *dp = data;

	if (code > 255)
		error("option_as_string: bad code %d", code);

	for (; dp < data + len; dp++) {
		if (!isascii(*dp) || !isprint(*dp)) {
			if (dp + 1 != data + len || *dp != 0) {
				snprintf(op, opleft, "\\%03o", *dp);
				op += 4;
				opleft -= 4;
			}
		} else if (*dp == '"' || *dp == '\'' || *dp == '$' ||
		    *dp == '`' || *dp == '\\') {
			*op++ = '\\';
			*op++ = *dp;
			opleft -= 2;
		} else {
			*op++ = *dp;
			opleft--;
		}
	}
	if (opleft < 1)
		goto toobig;
	*op = 0;
	return optbuf;
toobig:
	warning("dhcp option too large");
	return "<error>";
}
