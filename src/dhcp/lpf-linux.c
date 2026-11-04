/* Linux packet layer (AF_PACKET) for the vendored FreeBSD dhclient fork,
 * replacing bpf.c + the OpenBSD-derived privsep plumbing.
 *
 * Semantics preserved from bpf.c:
 *  - receive: one frame per read on rfdesc (AF_PACKET SOCK_RAW returns whole
 *    Ethernet frames; the BSD bpf framing header is handled here).
 *  - send broadcast: full assembled frame (Ethernet + IP + UDP + payload)
 *    written to the packet socket with an explicit destination hardware
 *    address (was writev() on the bpf write fd).
 *  - send unicast: raw UDP socket with user-supplied IP+UDP headers (the
 *    kernel builds the hardware header from its route, as on BSD).
 *  - the receive filter (UDP, destination port LOCAL_PORT, IPv4, optional
 *    VLAN) is applied in software.
 *
 * Copyright (c) 1995-1999 The Internet Software Consortium (BSD-3-Clause,
 * as the upstream files). Linux port: ha-dhcpc project.
 */
#define _GNU_SOURCE

#if !defined(__has_include) || __has_include(<sys/cdefs.h>)
#include <sys/cdefs.h>
#endif
#include "dhcpd.h"

#include <net/if.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <linux/if_packet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
lpf_open(struct interface_info *info)
{
	struct sockaddr_ll sll;
	int sock, flags;

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0)
		error("socket(AF_PACKET): %m");

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = (int)info->index;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		error("Can't bind AF_PACKET socket to %s: %m", info->name);

	flags = fcntl(sock, F_GETFL, 0);
	if (flags >= 0)
		fcntl(sock, F_SETFL, flags | O_NONBLOCK);

	return (sock);
}

/*
 * Called by get_interface_list for each interface that's discovered.
 * Opens a packet filter for each interface and adds it to the select
 * mask.
 */
int
if_register_bpf(struct interface_info *info, int flags)
{
	(void)flags;
	return (lpf_open(info));
}

void
if_register_send(struct interface_info *info)
{
	int sock, on = 1;

	/* Packet socket for broadcast sends (full frames). */
	info->wfdesc = lpf_open(info);

	/*
	 * Use raw socket for unicast send (IP+UDP headers supplied by the
	 * caller; the kernel builds the hardware header from its route).
	 */
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
		error("socket(SOCK_RAW): %m");
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on,
	    sizeof(on)) == -1)
		error("setsockopt(IP_HDRINCL): %m");
	info->ufdesc = sock;

	if (info->client->config->vlan_pcp != 0)
		warning("vlan pcp tag setting is not supported on Linux; ignored");
}

void
if_register_receive(struct interface_info *info)
{
	int flag = 1, sz;

	info->rfdesc = lpf_open(info);

	/*
	 * Set immediate mode so that reads return as soon as a packet
	 * comes in, rather than waiting for the input buffer to fill
	 * with packets.
	 */
	if (ioctl(info->rfdesc, FIONREAD, &sz) < 0)
		error("Can't get socket buffer length: %m");
	(void)flag;

	/* Receive buffer: one whole frame per read. */
	info->rbuf_max = 65536 + 64;
	info->rbuf = malloc(info->rbuf_max);
	if (!info->rbuf)
		error("Can't allocate %lu bytes for input buffer.",
	    (unsigned long)info->rbuf_max);
	info->rbuf_offset = 0;
	info->rbuf_len = 0;
}

void
send_packet_unpriv(int privfd, struct dhcp_packet *raw, size_t len,
    struct in_addr from, struct in_addr to)
{
	struct interface_info *interface = ifi;
	unsigned char buf[65536 + 64];
	struct iovec iov[2];
	struct msghdr msg;
	struct sockaddr_in sato;
	size_t frame_len;
	int result, bufp = 0;

	(void)privfd;

	if (to.s_addr == INADDR_BROADCAST) {
		/* Full frame: Ethernet + IP + UDP + payload. */
		assemble_hw_header(interface, buf, &bufp);
		assemble_udp_ip_header(buf, &bufp, from.s_addr, to.s_addr,
		    htons(REMOTE_PORT), (unsigned char *)raw, (int)len);

		memcpy(buf + bufp, raw, len);
		frame_len = bufp + len;

		if (write(interface->wfdesc, buf, frame_len) < 0)
			warning("send_packet: %m");
		return;
	}

	/* Assembled headers (IP + UDP) + payload over the raw UDP socket. */
	assemble_udp_ip_header(buf, &bufp, from.s_addr, to.s_addr,
	    htons(REMOTE_PORT), (unsigned char *)raw, (int)len);

	iov[0].iov_base = buf;
	iov[0].iov_len = bufp;
	iov[1].iov_base = raw;
	iov[1].iov_len = len;

	memset(&msg, 0, sizeof(msg));
	if (to.s_addr != INADDR_ANY) {
		memset(&sato, 0, sizeof(sato));
		sato.sin_addr = to;
		sato.sin_port = htons(REMOTE_PORT);
		sato.sin_family = AF_INET;

		msg.msg_name = (struct sockaddr *)&sato;
		msg.msg_namelen = sizeof(sato);
	}
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	result = sendmsg(interface->ufdesc, &msg, 0);

	if (result < 0)
		warning("send_packet: %m");
}

ssize_t
receive_packet(struct interface_info *interface, unsigned char *buf,
    size_t len, struct sockaddr_in *from, struct hardware *hfrom)
{
	struct sockaddr_in sfrom;
	unsigned char frame[65536 + 64];
	unsigned ihl, udp_dport;
	ssize_t n, off, dlen;

	(void)buf;
	(void)len;

	/* One whole Ethernet frame per read on an AF_PACKET socket. */
	n = read(interface->rfdesc, frame, sizeof(frame));
	if (n <= 0) {
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return (0);
		return (n);
	}

	/* Decode the physical header (handles VLAN)... */
	off = decode_hw_header(frame, 0, hfrom);
	if (off < 0)
		return (0);

	/* Software receive filter (was the kernel bpf program): IPv4,
	 * UDP, destined to our port. Anything else — ICMP errors the
	 * local stack generates for our own broadcasts, other protocol
	 * noise — must not reach the UDP/IP decoders. */
	if (n < off + 20 || frame[off] >> 4 != 4 || frame[off + 9] != 17)
		return (0);
	ihl = (frame[off] & 0xf) << 2;
	if (ihl < 20 || n < off + ihl + 8)
		return (0);
	udp_dport = frame[off + ihl + 2] << 8 | frame[off + ihl + 3];
	if (udp_dport != (unsigned)LOCAL_PORT)
		return (0);

	/* Decode the IP and UDP headers... */
	memset(&sfrom, 0, sizeof(sfrom));
	sfrom.sin_family = AF_INET;
	dlen = decode_udp_ip_header(frame, (int)off, &sfrom, NULL,
	    (int)(n - off));
	if (dlen < 0)
		return (0);

	/* The filter above guarantees the destination port; from->sin_port
	   is the sender's port (the server's 67). */

	memcpy(buf, frame + off + dlen, (size_t)n - (size_t)off - (size_t)dlen);
	*from = sfrom;
	return ((ssize_t)n - off - dlen);
}
