// SPDX-License-Identifier: GPL-3.0-only
#include "bot.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- the Chatbot characteristic -------------------------------------------- */

static int has_characteristic(const struct acs_xml *x, const char *type)
{
	size_t n = strlen(type);
	for (guint i = 0; x && i < x->keys->len; i++) {
		const char *k = g_ptr_array_index(x->keys, i);
		for (const char *p = k; (p = strstr(p, type)); p += n)
			if ((p == k || p[-1] == '/') && p[n] == '/')
				return 1;
	}
	return 0;
}

static int xml_int(const struct acs_xml *x, const char *k, int def)
{
	const char *v = x ? acs_xml_get(x, k) : NULL;
	return v && *v ? atoi(v) : def;
}

void bot_config_from_xml(const struct acs_xml *x, int enable, int xbot, struct bot_config *c)
{
	memset(c, 0, sizeof(*c));
	c->present = has_characteristic(x, "Chatbot");
	/* Stock ImConfig's defaults: ChatbotMsgTech 1 (session only), standaloneMsgAuth 0. */
	c->msg_tech = xml_int(x, "Chatbot/ChatbotMsgTech", 1);
	c->slm_auth = xml_int(x, "SERVICES/standaloneMsgAuth", 0);
	const char *v;
	if (x && (v = acs_xml_get(x, "Chatbot/BotinfoFQDNRoot")))
		g_strlcpy(c->root, v, sizeof(c->root));
	if (x && (v = acs_xml_get(x, "Chatbot/ChatbotDirectory")))
		g_strlcpy(c->directory, v, sizeof(c->directory));
	if (!enable || !c->present)
		return;
	/* As stock FeatureUpdater.updateChatBotFeatures and updateExtendedBotMsgFeature. */
	c->session = c->msg_tech == 1 || c->msg_tech == 2;
	c->sa = (c->msg_tech == 2 || c->msg_tech == 3) && c->slm_auth != 0;
	c->xbot = xbot && (c->session || c->sa);
}

/* ---- content types ---------------------------------------------------------- */

static int prefixed(const char *s, const char *prefix)
{
	return !g_ascii_strncasecmp(s, prefix, strlen(prefix));
}

enum bot_kind bot_kind_of(const char *ctype)
{
	if (!ctype)
		return BOT_KIND_NONE;
	if (!g_ascii_strcasecmp(ctype, BOT_CT_MESSAGE))
		return BOT_KIND_MESSAGE;
	if (prefixed(ctype, BOT_CT_XBOT_PREFIX))
		return BOT_KIND_XBOT;
	if (prefixed(ctype, BOT_CT_OPENRICH_PREFIX))
		return BOT_KIND_OPENRICH;
	return BOT_KIND_NONE;
}

int bot_xbot_version_ok(const char *ctype)
{
	const char *p = NULL;
	if (prefixed(ctype, BOT_CT_XBOT_PREFIX))
		p = ctype + strlen(BOT_CT_XBOT_PREFIX);
	else if (prefixed(ctype, BOT_CT_OPENRICH_PREFIX))
		p = ctype + strlen(BOT_CT_OPENRICH_PREFIX);
	if (!p)
		return 1;
	char *end;
	double v = g_ascii_strtod(p, &end);
	return end != p && v <= 1.0 + 1e-9;
}

/* ---- multipart/mixed ---------------------------------------------------------- */

static char *param(const char *ctype, const char *name)
{
	size_t n = strlen(name);
	for (const char *p = strchr(ctype, ';'); p; p = strchr(p + 1, ';')) {
		const char *q = p + 1;
		while (*q == ' ' || *q == '\t')
			q++;
		if (g_ascii_strncasecmp(q, name, n) || q[n] != '=')
			continue;
		q += n + 1;
		if (*q == '"') {
			const char *e = strchr(q + 1, '"');
			return e ? g_strndup(q + 1, (gsize)(e - q - 1)) : NULL;
		}
		return g_strndup(q, strcspn(q, "; \t\r\n"));
	}
	return NULL;
}

static char *bare_ctype(const char *v)
{
	char *c = g_strndup(v, strcspn(v, ";"));
	return g_strstrip(c);
}

/* The Content-Type of a part's header block, parameters stripped. */
static char *part_ctype(const char *h, size_t len)
{
	const char *p = h, *end = h + len;
	while (p < end) {
		const char *eol = memchr(p, '\n', (size_t)(end - p));
		if (!eol)
			eol = end;
		if ((size_t)(eol - p) > 13 && !g_ascii_strncasecmp(p, "Content-Type:", 13)) {
			char *v = g_strndup(p + 13, (gsize)(eol - p - 13));
			char *c = bare_ctype(g_strstrip(v));
			g_free(v);
			return c;
		}
		p = eol + 1;
	}
	return NULL;
}

/* The next delimiter line "--B" at the start of buf or after a line break,
 * from p on. *pre: where the content before it ends (its CRLF excluded). */
static const char *next_delim(const char *buf, const char *p, const char *end, const char *delim,
			      const char **pre)
{
	size_t dl = strlen(delim);
	for (const char *q = p; q + dl <= end; q++) {
		if (memcmp(q, delim, dl))
			continue;
		if (q == buf) {
			*pre = q;
			return q;
		}
		if (q[-1] == '\n') {
			*pre = q - 1;
			if (*pre > p && (*pre)[-1] == '\r')
				(*pre)--;
			return q;
		}
	}
	return NULL;
}

int bot_multipart_split(const char *ctype_full, const char *body, size_t len, char **ctype, char **part,
			size_t *plen, char **suggestion)
{
	*ctype = *part = *suggestion = NULL;
	*plen = 0;
	char *b = ctype_full ? param(ctype_full, "boundary") : NULL;
	if (!b || !*b || strlen(b) > 70) {
		g_free(b);
		return -EBADMSG;
	}
	char *delim = g_strconcat("--", b, NULL);
	g_free(b);
	size_t dl = strlen(delim);
	const char *end = body + len, *pre;
	const char *d = next_delim(body, body, end, delim, &pre);
	while (d) {
		const char *p = d + dl;
		if (p + 2 <= end && p[0] == '-' && p[1] == '-')
			break; /* the close delimiter */
		const char *eol = memchr(p, '\n', (size_t)(end - p));
		if (!eol)
			break;
		const char *start = eol + 1;
		const char *nd = next_delim(body, start, end, delim, &pre);
		const char *stop = nd ? pre : end;
		if (stop < start)
			stop = start; /* an empty part: the next delimiter right after this one */
		/* Headers, a blank line, the content; no headers: text/plain (stock). */
		const char *content = start;
		char *ct = NULL;
		if (start < stop && (*start == '\n' || (*start == '\r' && start + 1 < stop && start[1] == '\n'))) {
			content = start + (*start == '\r' ? 2 : 1);
		} else {
			const char *sep = g_strstr_len(start, stop - start, "\r\n\r\n");
			size_t sl = 4;
			const char *sep2 = g_strstr_len(start, stop - start, "\n\n");
			if (!sep || (sep2 && sep2 < sep)) {
				sep = sep2;
				sl = 2;
			}
			if (sep) {
				ct = part_ctype(start, (size_t)(sep - start));
				content = sep + sl;
			}
		}
		if (!ct)
			ct = g_strdup("text/plain");
		if (!g_ascii_strcasecmp(ct, BOT_CT_SUGGESTION)) {
			if (!*suggestion)
				*suggestion = g_strndup(content, (gsize)(stop - content));
			g_free(ct);
		} else if (!*part) {
			*part = g_strndup(content, (gsize)(stop - content));
			*plen = (size_t)(stop - content);
			*ctype = ct;
		} else {
			g_free(ct);
		}
		d = nd;
	}
	g_free(delim);
	if (!*part) {
		g_free(*suggestion);
		*suggestion = NULL;
		return -EBADMSG;
	}
	return 0;
}

/* ---- URIs ------------------------------------------------------------------- */

int bot_uri_key(const char *uri, char *out, size_t size)
{
	if (!uri || (g_ascii_strncasecmp(uri, "sip:", 4) && g_ascii_strncasecmp(uri, "sips:", 5)))
		return -EINVAL;
	size_t n = strcspn(uri, ";?>");
	for (size_t i = 0; i < n; i++)
		if ((unsigned char)uri[i] <= ' ' || (unsigned char)uri[i] >= 0x7f || strchr("<\"\\", uri[i]))
			return -EINVAL;
	const char *at = memchr(uri, '@', n);
	if (!at || at + 1 == uri + n || n + 1 > size)
		return -EINVAL;
	snprintf(out, size, "%.*s", (int)n, uri);
	return 0;
}

/* ---- botinfo ------------------------------------------------------------------ */

static int host_ok(const char *h)
{
	if (!*h)
		return 0;
	for (const char *p = h; *p; p++)
		if (!g_ascii_isalnum(*p) && *p != '.' && *p != '-')
			return 0;
	return 1;
}

/* "host", "host:port", "[v6]:port", optionally after https://. */
static int split_host(const char *in, char *host, size_t hsize, uint16_t *port)
{
	char buf[256];
	if (!g_ascii_strncasecmp(in, "https://", 8))
		in += 8;
	g_strlcpy(buf, in, sizeof(buf));
	size_t n = strlen(buf);
	if (n && buf[n - 1] == '/')
		buf[--n] = '\0';
	if (strchr(buf, '/'))
		return -EINVAL;
	*port = 443;
	char *colon;
	if (buf[0] == '[') {
		char *rb = strchr(buf, ']');
		if (!rb)
			return -EINVAL;
		*rb = '\0';
		if (rb[1] == ':')
			*port = (uint16_t)strtoul(rb + 2, NULL, 10);
		for (const char *p = buf + 1; *p; p++)
			if (!g_ascii_isxdigit(*p) && *p != ':' && *p != '.')
				return -EINVAL;
		g_strlcpy(host, buf + 1, hsize);
		return *port ? 0 : -EINVAL;
	}
	if ((colon = strchr(buf, ':'))) {
		*colon = '\0';
		char *e;
		unsigned long p = strtoul(colon + 1, &e, 10);
		if (*e || !p || p > 65535)
			return -EINVAL;
		*port = (uint16_t)p;
	}
	if (!host_ok(buf) || strlen(buf) + 1 > hsize)
		return -EINVAL;
	g_strlcpy(host, buf, hsize);
	return 0;
}

static int header_ok(const char *v)
{
	for (const char *p = v; *p; p++)
		if ((unsigned char)*p < ' ' || *p == 0x7f)
			return 0;
	return 1;
}

/* stock ji.c.a: "6" -> "006", "06" -> "006", "450" -> "450", anything else "000". */
static void pad3(const char *s, char out[4])
{
	size_t n = s ? strlen(s) : 0;
	memcpy(out, "000", 4);
	if (n < 1 || n > 3)
		return;
	for (size_t i = 0; i < n; i++)
		if (!g_ascii_isdigit(s[i]))
			return;
	memcpy(out + 3 - n, s, n);
}

char *bot_info_request(const char *root, const char *bot_id, const char *lang, const char *mcc,
		       const char *mnc, int v, const char *user_agent, const char *etag, char *host,
		       size_t hsize, uint16_t *port)
{
	char key[256];
	if (bot_uri_key(bot_id, key, sizeof(key)) < 0)
		return NULL;
	if (root && *root) {
		if (split_host(root, host, hsize, port) < 0)
			return NULL;
	} else {
		/* R9 7.7.3.2: no BotinfoFQDNRoot, the domain part of the service id. */
		if (split_host(strchr(key, '@') + 1, host, hsize, port) < 0)
			return NULL;
	}
	char hl[3] = "en";
	if (lang && g_ascii_isalpha(lang[0]) && g_ascii_isalpha(lang[1])) {
		hl[0] = g_ascii_tolower(lang[0]);
		hl[1] = g_ascii_tolower(lang[1]);
	}
	char m1[4], m2[4];
	pad3(mcc, m1);
	pad3(mnc, m2);
	if (!mcc || !*mcc || !mnc || !*mnc)
		snprintf(m1, 4, "000"), snprintf(m2, 4, "000");
	char *id = g_uri_escape_string(key, NULL, FALSE);
	GString *s = g_string_new(NULL);
	g_string_append_printf(s, "GET /bot?id=%s&hl=%s&ho=%s%s", id, hl, m1, m2);
	if (v > 0)
		g_string_append_printf(s, "&v=%d", v);
	g_free(id);
	int v6 = strchr(host, ':') != NULL;
	g_string_append_printf(s, " HTTP/1.1\r\nHost: %s%s%s", v6 ? "[" : "", host, v6 ? "]" : "");
	if (*port != 443)
		g_string_append_printf(s, ":%u", *port);
	g_string_append(s, "\r\n");
	if (user_agent && *user_agent && header_ok(user_agent))
		g_string_append_printf(s, "User-Agent: %s\r\n", user_agent);
	g_string_append(s, "Accept: application/json\r\n");
	if (etag && *etag && header_ok(etag))
		g_string_append_printf(s, "If-None-Match: %s\r\n", etag);
	g_string_append(s, "Connection: close\r\n\r\n");
	return g_string_free(s, FALSE);
}

long bot_max_age(const char *cc)
{
	if (!cc)
		return -1;
	long age = -1;
	char **t = g_strsplit(cc, ",", -1);
	for (int i = 0; t[i]; i++) {
		char *x = g_strstrip(t[i]);
		if (!g_ascii_strcasecmp(x, "no-cache") || !g_ascii_strcasecmp(x, "no-store")) {
			age = 0;
			break;
		}
		if (!g_ascii_strncasecmp(x, "max-age=", 8)) {
			const char *v = x + 8;
			if (*v == '"')
				v++;
			age = strtol(v, NULL, 10);
			if (age < 0)
				age = 0;
		}
	}
	g_strfreev(t);
	return age;
}
