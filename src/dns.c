// SPDX-License-Identifier: GPL-3.0-only
#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

/* RFC 1035 4.1: header, one question, QTYPE AAAA (28), QCLASS IN. */
static int build_query(const char *name, uint16_t id, unsigned char *q, size_t size)
{
	size_t n = 12;
	memset(q, 0, 12);
	q[0] = id >> 8;
	q[1] = id & 0xff;
	q[2] = 0x01; /* RD */
	q[5] = 1;    /* QDCOUNT */

	const char *p = name;
	while (*p) {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p);
		if (l == 0 || l > 63 || n + l + 2 > size)
			return -EINVAL;
		q[n++] = (unsigned char)l;
		memcpy(q + n, p, l);
		n += l;
		p += l;
		if (*p == '.')
			p++;
	}
	if (n + 5 > size)
		return -EINVAL;
	q[n++] = 0;
	q[n++] = 0; q[n++] = 28;
	q[n++] = 0; q[n++] = 1;
	return (int)n;
}

/* Skips a (possibly compressed) name; returns the offset after it or -1. */
static int skip_name(const unsigned char *m, size_t len, size_t off)
{
	while (off < len) {
		unsigned char l = m[off];
		if (l == 0)
			return (int)off + 1;
		if ((l & 0xc0) == 0xc0)
			return off + 2 <= len ? (int)off + 2 : -1;
		off += 1 + l;
	}
	return -1;
}

static int parse_answer(const unsigned char *m, size_t len, uint16_t id,
			struct in6_addr *out, size_t max)
{
	if (len < 12 || ((m[0] << 8) | m[1]) != id || !(m[2] & 0x80) || (m[3] & 0x0f))
		return -EPROTO;
	unsigned qd = (m[4] << 8) | m[5], an = (m[6] << 8) | m[7];
	int off = 12;
	for (unsigned i = 0; i < qd; i++) {
		off = skip_name(m, len, (size_t)off);
		if (off < 0 || (size_t)off + 4 > len)
			return -EPROTO;
		off += 4;
	}
	size_t found = 0;
	for (unsigned i = 0; i < an && found < max; i++) {
		off = skip_name(m, len, (size_t)off);
		if (off < 0 || (size_t)off + 10 > len)
			return -EPROTO;
		uint16_t type = (m[off] << 8) | m[off + 1];
		uint16_t rdlen = (m[off + 8] << 8) | m[off + 9];
		off += 10;
		if ((size_t)off + rdlen > len)
			return -EPROTO;
		if (type == 28 && rdlen == 16)
			memcpy(&out[found++], m + off, 16);
		off += rdlen;
	}
	return (int)found;
}

static int query_one(const char *name, const char *server, const char *src_addr,
		     const char *iface, struct in6_addr *out, size_t max, int timeout_ms)
{
	struct sockaddr_in6 to = { .sin6_family = AF_INET6, .sin6_port = htons(53) };
	struct sockaddr_in6 from = { .sin6_family = AF_INET6 };
	unsigned char q[512], a[1500];
	uint16_t id;

	if (inet_pton(AF_INET6, server, &to.sin6_addr) != 1 ||
	    inet_pton(AF_INET6, src_addr, &from.sin6_addr) != 1)
		return -EINVAL;
	if (getrandom(&id, sizeof(id), 0) != sizeof(id))
		id = (uint16_t)rand();
	int qlen = build_query(name, id, q, sizeof(q));
	if (qlen < 0)
		return qlen;

	int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	int r = 0;
	if ((iface && *iface && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) + 1) < 0) ||
	    bind(fd, (struct sockaddr *)&from, sizeof(from)) < 0 ||
	    connect(fd, (struct sockaddr *)&to, sizeof(to)) < 0 ||
	    send(fd, q, (size_t)qlen, 0) != qlen) {
		r = -errno;
		close(fd);
		return r;
	}
	struct pollfd p = { .fd = fd, .events = POLLIN };
	r = poll(&p, 1, timeout_ms);
	if (r <= 0) {
		close(fd);
		return r < 0 ? -errno : -ETIMEDOUT;
	}
	ssize_t n = recv(fd, a, sizeof(a), 0);
	close(fd);
	if (n < 0)
		return -errno;
	return parse_answer(a, (size_t)n, id, out, max);
}

int imsroha_dns_aaaa(const char *name, const char *servers, const char *src_addr,
		     const char *iface, struct in6_addr *out, size_t max, int timeout_ms)
{
	char list[256];
	int last = -ENOENT;

	snprintf(list, sizeof(list), "%s", servers ? servers : "");
	for (char *save = NULL, *s = strtok_r(list, " ", &save); s; s = strtok_r(NULL, " ", &save)) {
		int r = query_one(name, s, src_addr, iface, out, max, timeout_ms);
		if (r > 0)
			return r;
		last = r ? r : -ENOENT;
		fprintf(stderr, "imsroha: DNS %s via %s: %s\n", name, s,
			r ? strerror(-r) : "no AAAA record");
	}
	return last;
}
