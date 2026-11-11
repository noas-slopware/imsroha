// SPDX-License-Identifier: GPL-3.0-only
#include "cpim.h"
#include "sipmsg.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cpim_msg_id(char *out, size_t size)
{
	sip_random(out, MIN(size - 1, (size_t)24));
}

static void now_iso(char *out, size_t size)
{
	GDateTime *t = g_date_time_new_now_utc();
	char *s = g_date_time_format(t, "%Y-%m-%dT%H:%M:%S");
	snprintf(out, size, "%s.%03dZ", s, g_date_time_get_microsecond(t) / 1000);
	g_free(s);
	g_date_time_unref(t);
}

static char *wrap(const char *msg_id, const char *disp, const char *ctype, const char *extra_mime,
		  const char *body, size_t *len)
{
	char dt[40];
	now_iso(dt, sizeof(dt));
	GString *s = g_string_new(NULL);
	g_string_append(s, "From: <sip:anonymous@anonymous.invalid>\r\n");
	g_string_append(s, "To: <sip:anonymous@anonymous.invalid>\r\n");
	g_string_append_printf(s, "DateTime: %s\r\n", dt);
	if (msg_id) {
		g_string_append(s, "NS: imdn <urn:ietf:params:imdn>\r\n");
		g_string_append_printf(s, "imdn.Message-ID: %s\r\n", msg_id);
		if (disp)
			g_string_append_printf(s, "imdn.Disposition-Notification: %s\r\n", disp);
	}
	g_string_append_printf(s, "\r\nContent-Type: %s\r\n", ctype);
	if (extra_mime)
		g_string_append(s, extra_mime);
	g_string_append_printf(s, "Content-Length: %zu\r\n\r\n%s", strlen(body), body);
	*len = s->len;
	return g_string_free(s, FALSE);
}

char *cpim_text(const char *msg_id, const char *text, size_t *len)
{
	return wrap(msg_id, "positive-delivery, display", "text/plain; charset=utf-8", NULL, text, len);
}

char *cpim_message(const char *msg_id, const char *ctype, const char *body, size_t *len)
{
	return wrap(msg_id, "positive-delivery, display", ctype, NULL, body, len);
}

char *cpim_imdn(const char *orig_id, const char *status, size_t *len)
{
	char id[32], dt[40];
	cpim_msg_id(id, sizeof(id));
	now_iso(dt, sizeof(dt));
	int disp = !strcmp(status, "displayed");
	char *xml = g_strdup_printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
				    "<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\">\r\n"
				    "<message-id>%s</message-id>\r\n<datetime>%s</datetime>\r\n"
				    "<%s-notification><status><%s/></status></%s-notification>\r\n</imdn>\r\n",
				    orig_id, dt, disp ? "display" : "delivery", status, disp ? "display" : "delivery");
	char *c = wrap(id, NULL, "message/imdn+xml", "Content-Disposition: notification\r\n", xml, len);
	g_free(xml);
	return c;
}

char *iscomposing(int active, int wrapped, size_t *len)
{
	char *xml = g_strdup_printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
				    "<isComposing xmlns=\"urn:ietf:params:xml:ns:im-iscomposing\">"
				    "<state>%s</state><contenttype>text/plain</contenttype>%s</isComposing>\r\n",
				    active ? "active" : "idle", active ? "<refresh>60</refresh>" : "");
	if (!wrapped) {
		*len = strlen(xml);
		return xml;
	}
	char *c = wrap(NULL, NULL, "application/im-iscomposing+xml", NULL, xml, len);
	g_free(xml);
	return c;
}

static const char *block_end(const char *p, const char *end, const char **next)
{
	for (const char *q = p; q < end; q++) {
		if (q + 3 < end && !memcmp(q, "\r\n\r\n", 4)) {
			*next = q + 4;
			return q;
		}
		if (q + 1 < end && !memcmp(q, "\n\n", 2)) {
			*next = q + 2;
			return q;
		}
	}
	return NULL;
}

static char *hdr(const char *block, size_t len, const char *name)
{
	size_t nl = strlen(name);
	const char *p = block, *end = block + len;
	while (p < end) {
		const char *eol = memchr(p, '\n', (size_t)(end - p));
		if (!eol)
			eol = end;
		if ((size_t)(eol - p) > nl && !g_ascii_strncasecmp(p, name, nl) && p[nl] == ':') {
			char *v = g_strndup(p + nl + 1, (gsize)(eol - p - nl - 1));
			return g_strstrip(v);
		}
		p = eol + 1;
	}
	return NULL;
}

void cpim_clear(struct cpim *c)
{
	g_free(c->ctype);
	g_free(c->msg_id);
	g_free(c->datetime);
	g_free(c->disposition);
	g_free(c->body);
	memset(c, 0, sizeof(*c));
}

int cpim_parse(const char *buf, size_t len, struct cpim *out)
{
	memset(out, 0, sizeof(*out));
	const char *end = buf + len, *mime, *content;
	const char *h1 = block_end(buf, end, &mime);
	if (!h1)
		return -EBADMSG;
	const char *h2 = block_end(mime, end, &content);
	if (!h2) {
		/* Headers without a body. */
		h2 = end;
		content = end;
	}
	out->msg_id = hdr(buf, (size_t)(h1 - buf), "imdn.Message-ID");
	out->datetime = hdr(buf, (size_t)(h1 - buf), "DateTime");
	out->disposition = hdr(buf, (size_t)(h1 - buf), "imdn.Disposition-Notification");
	char *ct = hdr(mime, (size_t)(h2 - mime), "Content-Type");
	if (ct) {
		char *semi = strchr(ct, ';');
		if (semi)
			*semi = '\0';
		g_strstrip(ct);
	}
	out->ctype = ct ? ct : g_strdup("text/plain");
	char *cl = hdr(mime, (size_t)(h2 - mime), "Content-Length");
	size_t n = (size_t)(end - content);
	if (cl) {
		size_t want = strtoul(cl, NULL, 10);
		if (want < n)
			n = want;
		g_free(cl);
	}
	out->body = g_strndup(content, n);
	out->blen = n;
	return 0;
}

static int tag_text(const char *xml, size_t len, const char *tag, char *out, size_t size)
{
	char *x = g_strndup(xml, len);
	char *open = g_strdup_printf("<%s>", tag), *close = g_strdup_printf("</%s>", tag);
	const char *a = strstr(x, open), *b = a ? strstr(a, close) : NULL;
	int r = -ENOENT;
	if (a && b) {
		a += strlen(open);
		snprintf(out, size, "%.*s", (int)(b - a), a);
		g_strstrip(out);
		r = 0;
	}
	g_free(open);
	g_free(close);
	g_free(x);
	return r;
}

int imdn_parse(const char *xml, size_t len, char *id, size_t idsize, char *status, size_t ssize)
{
	if (tag_text(xml, len, "message-id", id, idsize) < 0)
		return -EBADMSG;
	char st[256];
	if (tag_text(xml, len, "status", st, sizeof(st)) < 0)
		return -EBADMSG;
	const char *p = strchr(st, '<');
	if (!p)
		return -EBADMSG;
	size_t n = strcspn(p + 1, "/> ");
	snprintf(status, ssize, "%.*s", (int)n, p + 1);
	return 0;
}

int iscomposing_parse(const char *xml, size_t len)
{
	char st[32];
	if (!g_strstr_len(xml, (gssize)len, "isComposing") || tag_text(xml, len, "state", st, sizeof(st)) < 0)
		return -EBADMSG;
	return !strcmp(st, "active");
}

gint64 cpim_time_ms(const char *datetime)
{
	GDateTime *t = datetime ? g_date_time_new_from_iso8601(datetime, NULL) : NULL;
	gint64 ms;
	if (t) {
		ms = g_date_time_to_unix(t) * 1000 + g_date_time_get_microsecond(t) / 1000;
		g_date_time_unref(t);
	} else {
		ms = g_get_real_time() / 1000;
	}
	return ms;
}
