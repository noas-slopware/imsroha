// SPDX-License-Identifier: GPL-3.0-only
#include "ipsec.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <glib.h>

static uint32_t random_spi(void)
{
	uint32_t v = 0;
	if (getrandom(&v, sizeof(v), 0) != sizeof(v))
		v = (uint32_t)rand() << 16 ^ (uint32_t)rand();
	/* 0-255 are reserved (RFC 4303 2.1); keep clear of them. */
	return v < 0x1000 ? v + 0x1000 : v;
}

void imsroha_ipsec_new_spis(struct imsroha_ipsec *s)
{
	s->spi_uc = random_spi();
	do
		s->spi_us = random_spi();
	while (s->spi_us == s->spi_uc);
}

int imsroha_ipsec_client_header(const struct imsroha_ipsec *s, char *out, size_t size)
{
	char algs[64], ealgs[64];
	size_t n = 0;

	out[0] = '\0';
	snprintf(algs, sizeof(algs), "%s", s->offer_alg);
	for (char *sa = NULL, *a = strtok_r(algs, ",", &sa); a; a = strtok_r(NULL, ",", &sa)) {
		snprintf(ealgs, sizeof(ealgs), "%s", s->offer_ealg);
		for (char *se = NULL, *e = strtok_r(ealgs, ",", &se); e; e = strtok_r(NULL, ",", &se)) {
			int w = snprintf(out + n, size - n,
					 "%sipsec-3gpp;alg=%s;ealg=%s;spi-c=%u;spi-s=%u;port-c=%u;port-s=%u",
					 n ? ", " : "", a, e, s->spi_uc, s->spi_us,
					 s->offer_port_uc ? s->offer_port_uc : s->port_uc, s->port_us);
			if (w < 0 || (size_t)w >= size - n)
				return -ENOSPC;
			n += (size_t)w;
		}
	}
	return n ? 0 : -EINVAL;
}

/* "name=value" out of one ';'-separated mechanism entry. */
static int param(const char *entry, const char *name, char *out, size_t size)
{
	size_t nl = strlen(name);
	const char *p = entry;
	while ((p = strchr(p, ';'))) {
		p++;
		while (*p == ' ')
			p++;
		if (!strncasecmp(p, name, nl) && p[nl] == '=') {
			p += nl + 1;
			size_t l = strcspn(p, ";, ");
			snprintf(out, size, "%.*s", (int)l, p);
			return 0;
		}
	}
	return -ENOENT;
}

static int in_list(const char *list, const char *item)
{
	char buf[64];
	snprintf(buf, sizeof(buf), "%s", list);
	for (char *s = NULL, *t = strtok_r(buf, ",", &s); t; t = strtok_r(NULL, ",", &s))
		if (!strcasecmp(t, item))
			return 1;
	return 0;
}

int imsroha_ipsec_parse_server(struct imsroha_ipsec *s, const char *value)
{
	char buf[1024];
	double best_q = -1;
	int found = 0;

	if (!value || !*value)
		return -ENOENT;
	snprintf(buf, sizeof(buf), "%s", value);
	for (char *sv = NULL, *e = strtok_r(buf, ",", &sv); e; e = strtok_r(NULL, ",", &sv)) {
		while (*e == ' ')
			e++;
		if (strncasecmp(e, "ipsec-3gpp", 10))
			continue;
		char alg[24] = "", ealg[24] = "null", prot[8] = "esp", q[16] = "0.1", v[16];
		param(e, "alg", alg, sizeof(alg));
		param(e, "ealg", ealg, sizeof(ealg));
		param(e, "prot", prot, sizeof(prot));
		param(e, "q", q, sizeof(q));
		/* An ealg the P-CSCF names but we did not offer cannot be used. */
		if (strcasecmp(prot, "esp") || !in_list(s->offer_alg, alg) || !in_list(s->offer_ealg, ealg))
			continue;
		double qv = strtod(q, NULL);
		if (qv <= best_q)
			continue;
		uint32_t spi_c = 0, spi_s = 0, port_c = 0, port_s = 0;
		if (!param(e, "spi-c", v, sizeof(v))) spi_c = (uint32_t)strtoul(v, NULL, 10);
		if (!param(e, "spi-s", v, sizeof(v))) spi_s = (uint32_t)strtoul(v, NULL, 10);
		if (!param(e, "port-c", v, sizeof(v))) port_c = (uint32_t)strtoul(v, NULL, 10);
		if (!param(e, "port-s", v, sizeof(v))) port_s = (uint32_t)strtoul(v, NULL, 10);
		if (!spi_c || !spi_s || !port_c || port_c > 65535 || !port_s || port_s > 65535)
			continue;
		best_q = qv;
		found = 1;
		s->spi_pc = spi_c;
		s->spi_ps = spi_s;
		s->port_pc = (uint16_t)port_c;
		s->port_ps = (uint16_t)port_s;
		snprintf(s->alg, sizeof(s->alg), "%s", alg);
		snprintf(s->ealg, sizeof(s->ealg), "%s", ealg);
		snprintf(s->server_line, sizeof(s->server_line), "%s", e);
	}
	return found ? 0 : -ENOENT;
}

/* $IMSROHA_IP or ip, without a shell. */
static int ip(const char *const *args)
{
	const char *bin = getenv("IMSROHA_IP");
	const char *argv[40];
	int n = 0;
	argv[n++] = bin && *bin ? bin : "ip";
	for (int i = 0; args[i] && n < 39; i++)
		argv[n++] = args[i];
	argv[n] = NULL;

	GError *error = NULL;
	int status = 0;
	if (!g_spawn_sync(NULL, (char **)argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
			  NULL, NULL, &status, &error)) {
		fprintf(stderr, "imsroha: %s: %s\n", argv[0], error->message);
		g_error_free(error);
		return -EIO;
	}
	if (!g_spawn_check_wait_status(status, NULL)) {
		fprintf(stderr, "imsroha: ip %s %s %s failed\n", args[0], args[1], args[2]);
		return -EIO;
	}
	return 0;
}

static void hex(const unsigned char *b, size_t n, char *out)
{
	out[0] = '0';
	out[1] = 'x';
	for (size_t i = 0; i < n; i++)
		sprintf(out + 2 + 2 * i, "%02x", b[i]);
}

/* TS 33.203 Annex I: the ESP keys from IK and CK. */
static int esp_keys(const struct imsroha_ipsec *s, const unsigned char ik[16], const unsigned char ck[16],
		    const char **auth, char *akey, const char **enc, char *ekey)
{
	unsigned char k[20] = { 0 };
	if (!strcasecmp(s->alg, "hmac-sha-1-96")) {
		/* IK with 32 zero bits appended: a 160-bit key */
		memcpy(k, ik, 16);
		*auth = "hmac(sha1)";
		hex(k, 20, akey);
	} else if (!strcasecmp(s->alg, "hmac-md5-96")) {
		*auth = "hmac(md5)";
		hex(ik, 16, akey);
	} else {
		return -ENOTSUP;
	}
	if (!strcasecmp(s->ealg, "aes-cbc")) {
		*enc = "cbc(aes)";
		hex(ck, 16, ekey);
	} else if (!strcasecmp(s->ealg, "null")) {
		*enc = "ecb(cipher_null)";
		ekey[0] = '\0';
	} else {
		return -ENOTSUP;
	}
	return 0;
}

static int add_sa(const char *src, const char *dst, uint32_t spi, const char *auth, const char *akey,
		  const char *enc, const char *ekey)
{
	char spi_s[16];
	snprintf(spi_s, sizeof(spi_s), "0x%08x", spi);
	const char *args[] = { "-6", "xfrm", "state", "add", "src", src, "dst", dst, "proto", "esp",
		"spi", spi_s, "mode", "transport", "auth-trunc", auth, akey, "96",
		"enc", enc, ekey, NULL };
	return ip(args);
}

static int add_policy(const char *src, const char *dst, uint16_t sport, uint16_t dport,
		      const char *dir, uint32_t spi)
{
	char s128[72], d128[72], sp[8], dp[8], spi_s[16];
	snprintf(s128, sizeof(s128), "%s/128", src);
	snprintf(d128, sizeof(d128), "%s/128", dst);
	snprintf(sp, sizeof(sp), "%u", sport);
	snprintf(dp, sizeof(dp), "%u", dport);
	snprintf(spi_s, sizeof(spi_s), "0x%08x", spi);
	const char *args[] = { "-6", "xfrm", "policy", "add", "src", s128, "dst", d128,
		"proto", "udp", "sport", sp, "dport", dp, "dir", dir,
		"tmpl", "src", src, "dst", dst, "proto", "esp", "spi", spi_s, "mode", "transport", NULL };
	return ip(args);
}

static void del_sa(const char *src, const char *dst, uint32_t spi)
{
	char spi_s[16];
	snprintf(spi_s, sizeof(spi_s), "0x%08x", spi);
	const char *args[] = { "-6", "xfrm", "state", "delete", "src", src, "dst", dst,
		"proto", "esp", "spi", spi_s, NULL };
	ip(args);
}

static void del_policy(const char *src, const char *dst, uint16_t sport, uint16_t dport, const char *dir)
{
	char s128[72], d128[72], sp[8], dp[8];
	snprintf(s128, sizeof(s128), "%s/128", src);
	snprintf(d128, sizeof(d128), "%s/128", dst);
	snprintf(sp, sizeof(sp), "%u", sport);
	snprintf(dp, sizeof(dp), "%u", dport);
	const char *args[] = { "-6", "xfrm", "policy", "delete", "src", s128, "dst", d128,
		"proto", "udp", "sport", sp, "dport", dp, "dir", dir, NULL };
	ip(args);
}

/* What is installed, as it was installed (the SPIs may have moved on since). */
static struct {
	char ue[64], pcscf[64];
	uint32_t spi_uc, spi_us, spi_pc, spi_ps;
	uint16_t port_uc, port_us, port_pc, port_ps;
} live;

void imsroha_ipsec_remove(struct imsroha_ipsec *s)
{
	if (!s->installed)
		return;
	del_policy(live.ue, live.pcscf, live.port_uc, live.port_ps, "out");
	del_policy(live.pcscf, live.ue, live.port_ps, live.port_uc, "in");
	del_policy(live.pcscf, live.ue, live.port_pc, live.port_us, "in");
	del_policy(live.ue, live.pcscf, live.port_us, live.port_pc, "out");
	del_sa(live.ue, live.pcscf, live.spi_ps);
	del_sa(live.pcscf, live.ue, live.spi_uc);
	del_sa(live.pcscf, live.ue, live.spi_us);
	del_sa(live.ue, live.pcscf, live.spi_pc);
	s->installed = 0;
}

int imsroha_ipsec_install(struct imsroha_ipsec *s, const char *ue, const char *pcscf,
			  const unsigned char ik[16], const unsigned char ck[16])
{
	const char *auth, *enc;
	char akey[64], ekey[64];
	int r = esp_keys(s, ik, ck, &auth, akey, &enc, ekey);
	if (r < 0) {
		fprintf(stderr, "imsroha: IPsec %s/%s is not supported\n", s->alg, s->ealg);
		return r;
	}
	imsroha_ipsec_remove(s);

	snprintf(live.ue, sizeof(live.ue), "%s", ue);
	snprintf(live.pcscf, sizeof(live.pcscf), "%s", pcscf);
	live.spi_uc = s->spi_uc; live.spi_us = s->spi_us;
	live.spi_pc = s->spi_pc; live.spi_ps = s->spi_ps;
	live.port_uc = s->port_uc; live.port_us = s->port_us;
	live.port_pc = s->port_pc; live.port_ps = s->port_ps;
	s->installed = 1;

	if ((r = add_sa(ue, pcscf, s->spi_ps, auth, akey, enc, ekey)) ||
	    (r = add_sa(pcscf, ue, s->spi_uc, auth, akey, enc, ekey)) ||
	    (r = add_sa(pcscf, ue, s->spi_us, auth, akey, enc, ekey)) ||
	    (r = add_sa(ue, pcscf, s->spi_pc, auth, akey, enc, ekey)) ||
	    (r = add_policy(ue, pcscf, s->port_uc, s->port_ps, "out", s->spi_ps)) ||
	    (r = add_policy(pcscf, ue, s->port_ps, s->port_uc, "in", s->spi_uc)) ||
	    (r = add_policy(pcscf, ue, s->port_pc, s->port_us, "in", s->spi_us)) ||
	    (r = add_policy(ue, pcscf, s->port_us, s->port_pc, "out", s->spi_pc))) {
		imsroha_ipsec_remove(s);
		return r;
	}
	snprintf(s->ue, sizeof(s->ue), "%s", ue);
	snprintf(s->pcscf, sizeof(s->pcscf), "%s", pcscf);
	fprintf(stderr, "imsroha: IPsec SAs up (%s, %s): [%s]:%u/%u <-> [%s]:%u/%u\n",
		s->alg, s->ealg, ue, s->port_uc, s->port_us, pcscf, s->port_pc, s->port_ps);
	return 0;
}
