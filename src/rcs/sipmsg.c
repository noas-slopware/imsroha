// SPDX-License-Identifier: GPL-3.0-only
#include "sipmsg.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *expand(const char *n)
{
	static const struct { char c; const char *full; } compact[] = {
		{ 'i', "Call-ID" }, { 'f', "From" }, { 't', "To" }, { 'v', "Via" }, { 'm', "Contact" },
		{ 'l', "Content-Length" }, { 'c', "Content-Type" }, { 'k', "Supported" }, { 'e', "Content-Encoding" },
		{ 's', "Subject" }, { 'o', "Event" }, { 'r', "Refer-To" }, { 'b', "Referred-By" }, { 'a', "Accept-Contact" },
		{ 'u', "Allow-Events" },
	};
	if (n[0] && !n[1])
		for (size_t i = 0; i < G_N_ELEMENTS(compact); i++)
			if (g_ascii_tolower(n[0]) == compact[i].c)
				return compact[i].full;
	return n;
}

void sipmsg_free(struct sipmsg *m)
{
	if (!m)
		return;
	g_ptr_array_free(m->names, TRUE);
	g_ptr_array_free(m->values, TRUE);
	g_free(m->body);
	g_free(m);
}

gssize sipmsg_frame(const char *buf, size_t len, struct sipmsg **out)
{
	size_t skip = 0;
	*out = NULL;
	while (skip < len && (buf[skip] == '\r' || buf[skip] == '\n'))
		skip++;
	buf += skip;
	len -= skip;
	const char *end = NULL;
	for (size_t i = 0; i + 3 < len; i++)
		if (!memcmp(buf + i, "\r\n\r\n", 4)) {
			end = buf + i;
			break;
		}
	if (!end)
		return len > 65536 ? -EMSGSIZE : (gssize)skip * (len == 0);

	struct sipmsg *m = g_new0(struct sipmsg, 1);
	m->names = g_ptr_array_new_with_free_func(g_free);
	m->values = g_ptr_array_new_with_free_func(g_free);
	char *head = g_strndup(buf, (gsize)(end - buf));
	/* Unfold continuation lines (RFC 3261 7.3.1). */
	char **lines = g_strsplit(head, "\r\n", -1);
	g_free(head);
	int ok = lines[0] != NULL;
	if (ok && !strncmp(lines[0], "SIP/2.0 ", 8)) {
		m->code = atoi(lines[0] + 8);
		const char *sp = strchr(lines[0] + 8, ' ');
		snprintf(m->reason, sizeof(m->reason), "%s", sp ? sp + 1 : "");
		ok = m->code >= 100 && m->code < 700;
	} else if (ok) {
		m->request = 1;
		ok = sscanf(lines[0], "%15s %511s SIP/2.0", m->method, m->ruri) == 2;
	}
	for (int i = 1; ok && lines[i]; i++) {
		if ((lines[i][0] == ' ' || lines[i][0] == '\t') && m->values->len) {
			char *prev = g_ptr_array_index(m->values, m->values->len - 1);
			char *joined = g_strconcat(prev, " ", g_strstrip(lines[i]), NULL);
			g_free(m->values->pdata[m->values->len - 1]);
			m->values->pdata[m->values->len - 1] = joined;
			continue;
		}
		char *colon = strchr(lines[i], ':');
		if (!colon)
			continue;
		*colon = '\0';
		g_strstrip(lines[i]);
		g_ptr_array_add(m->names, g_strdup(expand(lines[i])));
		g_ptr_array_add(m->values, g_strstrip(g_strdup(colon + 1)));
	}
	g_strfreev(lines);
	if (!ok) {
		sipmsg_free(m);
		return -EBADMSG;
	}
	const char *cl = sipmsg_header(m, "Content-Length");
	size_t blen = cl ? strtoul(cl, NULL, 10) : 0;
	size_t hlen = (size_t)(end - buf) + 4;
	if (blen > 1u << 20) {
		sipmsg_free(m);
		return -EMSGSIZE;
	}
	if (hlen + blen > len) {
		sipmsg_free(m);
		return 0;
	}
	m->body = g_strndup(buf + hlen, blen);
	m->blen = blen;
	*out = m;
	return (gssize)(skip + hlen + blen);
}

const char *sipmsg_header(const struct sipmsg *m, const char *name)
{
	for (guint i = 0; i < m->names->len; i++)
		if (!g_ascii_strcasecmp(g_ptr_array_index(m->names, i), name))
			return g_ptr_array_index(m->values, i);
	return NULL;
}

/* Splits on commas outside quotes and angle brackets. */
static void split_list(GPtrArray *out, const char *v)
{
	int q = 0, a = 0;
	const char *start = v;
	for (const char *p = v;; p++) {
		if (*p == '"')
			q = !q;
		else if (!q && *p == '<')
			a = 1;
		else if (!q && *p == '>')
			a = 0;
		if (!*p || (*p == ',' && !q && !a)) {
			char *item = g_strstrip(g_strndup(start, (gsize)(p - start)));
			if (*item)
				g_ptr_array_add(out, item);
			else
				g_free(item);
			if (!*p)
				break;
			start = p + 1;
		}
	}
}

char **sipmsg_header_all(const struct sipmsg *m, const char *name)
{
	GPtrArray *a = g_ptr_array_new();
	int is_auth = !g_ascii_strcasecmp(name, "WWW-Authenticate") || !g_ascii_strcasecmp(name, "Authorization");
	for (guint i = 0; i < m->names->len; i++) {
		if (g_ascii_strcasecmp(g_ptr_array_index(m->names, i), name))
			continue;
		if (is_auth)
			g_ptr_array_add(a, g_strdup(g_ptr_array_index(m->values, i)));
		else
			split_list(a, g_ptr_array_index(m->values, i));
	}
	g_ptr_array_add(a, NULL);
	return (char **)g_ptr_array_free(a, FALSE);
}

int sip_param(const char *hval, const char *name, char *out, size_t size)
{
	size_t nl = strlen(name);
	const char *gt = strrchr(hval, '>');
	const char *p = gt ? gt : hval;
	while ((p = strchr(p, ';'))) {
		p++;
		while (*p == ' ')
			p++;
		if (!g_ascii_strncasecmp(p, name, nl) && (p[nl] == '=' || p[nl] == ';' || !p[nl] || p[nl] == ' ')) {
			if (p[nl] != '=') {
				if (size)
					out[0] = '\0';
				return 0;
			}
			const char *v = p + nl + 1;
			size_t n;
			if (*v == '"') {
				v++;
				const char *e = strchr(v, '"');
				n = e ? (size_t)(e - v) : strlen(v);
			} else {
				n = strcspn(v, ";, ");
			}
			snprintf(out, size, "%.*s", (int)n, v);
			return 0;
		}
	}
	return -ENOENT;
}

int sip_auth_param(const char *hval, const char *name, char *out, size_t size)
{
	size_t nl = strlen(name);
	const char *p = hval;
	/* Skip the scheme. */
	while (*p && *p != ' ')
		p++;
	while (*p) {
		while (*p == ' ' || *p == ',')
			p++;
		const char *eq = strchr(p, '=');
		if (!eq)
			break;
		int match = (size_t)(eq - p) == nl && !g_ascii_strncasecmp(p, name, nl);
		const char *v = eq + 1, *e;
		size_t n;
		if (*v == '"') {
			v++;
			e = strchr(v, '"');
			n = e ? (size_t)(e - v) : strlen(v);
			p = e ? e + 1 : v + n;
		} else {
			n = strcspn(v, ",");
			p = v + n;
		}
		if (match) {
			snprintf(out, size, "%.*s", (int)n, v);
			g_strstrip(out);
			return 0;
		}
	}
	return -ENOENT;
}

void sip_uri_of(const char *hval, char *out, size_t size)
{
	const char *lt = strchr(hval, '<');
	if (lt) {
		const char *gt = strchr(lt, '>');
		snprintf(out, size, "%.*s", (int)(gt ? gt - lt - 1 : (long)strlen(lt + 1)), lt + 1);
		return;
	}
	size_t n = strcspn(hval, "; ");
	snprintf(out, size, "%.*s", (int)n, hval);
}

void sip_user_of(const char *uri, char *out, size_t size)
{
	const char *p = uri;
	if (!g_ascii_strncasecmp(p, "sip:", 4))
		p += 4;
	else if (!g_ascii_strncasecmp(p, "sips:", 5))
		p += 5;
	else if (!g_ascii_strncasecmp(p, "tel:", 4))
		p += 4;
	size_t n = strcspn(p, "@;>?");
	snprintf(out, size, "%.*s", (int)n, p);
}

void sip_random(char *out, size_t len)
{
	static const char al[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	for (size_t i = 0; i < len; i++)
		out[i] = al[g_random_int_range(0, (gint32)sizeof(al) - 1)];
	out[len] = '\0';
}
