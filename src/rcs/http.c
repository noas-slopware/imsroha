// SPDX-License-Identifier: GPL-3.0-only
#include "http.h"
#include "net.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HTTP_MAX (4u << 20) /* a full XML is ~10 kB; anything near this is wrong */

void http_response_clear(struct http_response *r)
{
	if (r->names)
		g_ptr_array_free(r->names, TRUE);
	if (r->values)
		g_ptr_array_free(r->values, TRUE);
	g_free(r->body);
	memset(r, 0, sizeof(*r));
}

const char *http_header(const struct http_response *r, const char *name)
{
	for (guint i = 0; r->names && i < r->names->len; i++)
		if (!g_ascii_strcasecmp(g_ptr_array_index(r->names, i), name))
			return g_ptr_array_index(r->values, i);
	return NULL;
}

static const char *find_crlfcrlf(const char *p, size_t len)
{
	for (size_t i = 0; i + 3 < len; i++)
		if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' && p[i + 3] == '\n')
			return p + i;
	return NULL;
}

/* Dechunks in into out; 1 when the last chunk was seen, 0 when more is needed, <0 on junk. */
static int dechunk(const char *in, size_t len, GByteArray *out)
{
	size_t i = 0;
	for (;;) {
		const char *nl = memchr(in + i, '\n', len - i);
		if (!nl)
			return 0;
		char *end;
		unsigned long n = strtoul(in + i, &end, 16);
		if (end == in + i)
			return -EBADMSG;
		size_t data = (size_t)(nl - in) + 1;
		if (n == 0)
			return 1;
		if (data + n + 2 > len)
			return 0;
		g_byte_array_append(out, (const guint8 *)in + data, (guint)n);
		i = data + n + 2;
	}
}

static int inflate_gzip(struct http_response *r)
{
	GConverter *dec = G_CONVERTER(g_zlib_decompressor_new(G_ZLIB_COMPRESSOR_FORMAT_GZIP));
	GByteArray *out = g_byte_array_new();
	guint8 buf[8192];
	size_t in_off = 0;
	int ret = 0;

	for (;;) {
		gsize rd = 0, wr = 0;
		GError *e = NULL;
		GConverterResult cr = g_converter_convert(dec, r->body + in_off, r->len - in_off, buf, sizeof(buf),
							  G_CONVERTER_INPUT_AT_END, &rd, &wr, &e);
		in_off += rd;
		g_byte_array_append(out, buf, (guint)wr);
		if (cr == G_CONVERTER_ERROR) {
			g_error_free(e);
			ret = -EBADMSG;
			break;
		}
		if (cr == G_CONVERTER_FINISHED || out->len > HTTP_MAX)
			break;
	}
	g_object_unref(dec);
	if (ret == 0) {
		g_free(r->body);
		r->len = out->len;
		g_byte_array_append(out, (const guint8 *)"", 1);
		r->body = (char *)g_byte_array_free(out, FALSE);
	} else {
		g_byte_array_free(out, TRUE);
	}
	return ret;
}

/*
 * 1: complete, 0: needs more, <0: broken. eof: the peer closed, so a body
 * without a length ends here.
 */
static int parse(const char *raw, size_t len, int eof, struct http_response *out)
{
	const char *hend = find_crlfcrlf(raw, len);
	if (!hend)
		return eof ? -EBADMSG : 0;

	http_response_clear(out);
	out->names = g_ptr_array_new_with_free_func(g_free);
	out->values = g_ptr_array_new_with_free_func(g_free);

	char *head = g_strndup(raw, (gsize)(hend - raw));
	char **lines = g_strsplit(head, "\r\n", -1);
	g_free(head);
	int ok = lines[0] && sscanf(lines[0], "HTTP/%*d.%*d %d", &out->status) == 1;
	if (ok) {
		const char *sp = strchr(lines[0], ' ');
		sp = sp ? strchr(sp + 1, ' ') : NULL;
		snprintf(out->reason, sizeof(out->reason), "%s", sp ? sp + 1 : "");
	}
	for (int i = 1; ok && lines[i]; i++) {
		char *colon = strchr(lines[i], ':');
		if (!colon)
			continue;
		*colon = '\0';
		g_ptr_array_add(out->names, g_strstrip(g_strdup(lines[i])));
		g_ptr_array_add(out->values, g_strstrip(g_strdup(colon + 1)));
	}
	g_strfreev(lines);
	if (!ok) {
		out->status = 0;
		return -EBADMSG;
	}

	const char *body = hend + 4;
	size_t blen = len - (size_t)(body - raw);
	const char *cl = http_header(out, "Content-Length");
	const char *te = http_header(out, "Transfer-Encoding");
	GByteArray *b = g_byte_array_new();
	int done;

	if (te && g_ascii_strcasecmp(te, "identity")) {
		done = dechunk(body, blen, b);
		if (done < 0) {
			g_byte_array_free(b, TRUE);
			return done;
		}
	} else if (cl) {
		size_t n = strtoul(cl, NULL, 10);
		done = blen >= n;
		g_byte_array_append(b, (const guint8 *)body, (guint)MIN(n, blen));
	} else if (out->status == 204 || out->status == 304 || (out->status >= 100 && out->status < 200)) {
		done = 1;
	} else {
		done = eof;
		g_byte_array_append(b, (const guint8 *)body, (guint)blen);
	}
	if (!done && eof) {
		g_byte_array_free(b, TRUE);
		return -EBADMSG;
	}
	out->len = b->len;
	g_byte_array_append(b, (const guint8 *)"", 1);
	out->body = (char *)g_byte_array_free(b, FALSE);
	if (!done)
		return 0;

	const char *ce = http_header(out, "Content-Encoding");
	if (ce && !g_ascii_strcasecmp(ce, "gzip") && out->len)
		return inflate_gzip(out) < 0 ? -EBADMSG : 1;
	return 1;
}

int http_parse_response(const char *raw, size_t len, struct http_response *out)
{
	return parse(raw, len, 1, out) == 1 ? 0 : -EBADMSG;
}

int http_exchange(const struct rcs_config *cfg, const char *host, uint16_t port, int tls,
		  const char *request, unsigned timeout_s, GCancellable *cancel,
		  struct http_response *out)
{
	GError *e = NULL;
	memset(out, 0, sizeof(*out));

	GIOStream *s = rcs_net_connect(cfg, host, port, tls, timeout_s, cancel, &e);
	if (!s) {
		snprintf(out->error, sizeof(out->error), "%s", e->message);
		g_error_free(e);
		return -ECONNREFUSED;
	}
	rcs_net_set_timeout(s, timeout_s);

	GOutputStream *os = g_io_stream_get_output_stream(s);
	if (!g_output_stream_write_all(os, request, strlen(request), NULL, cancel, &e)) {
		snprintf(out->error, sizeof(out->error), "sending: %s", e->message);
		g_error_free(e);
		g_object_unref(s);
		return -EIO;
	}

	GInputStream *is = g_io_stream_get_input_stream(s);
	GByteArray *raw = g_byte_array_new();
	char buf[8192];
	int r = 0;
	for (;;) {
		gssize n = g_input_stream_read(is, buf, sizeof(buf), cancel, &e);
		if (n < 0) {
			/* A TLS peer that closes without close_notify still ends the body. */
			if (raw->len && g_error_matches(e, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
				g_clear_error(&e);
				n = 0;
			} else {
				snprintf(out->error, sizeof(out->error), "receiving: %s", e->message);
				g_error_free(e);
				r = -EIO;
				break;
			}
		}
		if (n > 0)
			g_byte_array_append(raw, (const guint8 *)buf, (guint)n);
		int p = parse((const char *)raw->data, raw->len, n == 0, out);
		if (p == 1)
			break;
		if (p < 0 || raw->len > HTTP_MAX) {
			snprintf(out->error, sizeof(out->error), "unparsable response (%u bytes)", raw->len);
			out->status = 0;
			r = -EBADMSG;
			break;
		}
	}
	g_byte_array_free(raw, TRUE);
	g_io_stream_close(s, NULL, NULL);
	g_object_unref(s);
	if (r < 0) {
		char keep[256];
		snprintf(keep, sizeof(keep), "%s", out->error);
		http_response_clear(out);
		snprintf(out->error, sizeof(out->error), "%s", keep);
	}
	return r;
}
