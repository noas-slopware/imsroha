// SPDX-License-Identifier: GPL-3.0-only
#include "http.h"
#include "net.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

/* The status line and headers: the bytes they took (with the blank line), 0
 * when they are not complete yet, <0 when broken. */
static gssize parse_head(const char *raw, size_t len, struct http_response *out)
{
	const char *hend = find_crlfcrlf(raw, len);
	if (!hend)
		return 0;

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
	return (gssize)(hend - raw) + 4;
}

/*
 * 1: complete, 0: needs more, <0: broken. eof: the peer closed, so a body
 * without a length ends here.
 */
static int parse(const char *raw, size_t len, int eof, struct http_response *out)
{
	gssize hl = parse_head(raw, len, out);
	if (hl < 0)
		return (int)hl;
	if (hl == 0)
		return eof ? -EBADMSG : 0;
	const char *hend = raw + hl - 4;

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

/* Writes the request: head, then the file, then the tail. */
static int send_body(GOutputStream *os, const struct http_body *req, GCancellable *cancel, GError **e)
{
	if (!g_output_stream_write_all(os, req->head, req->head_len, NULL, cancel, e))
		return -EIO;
	if (req->fd >= 0) {
		char buf[16384];
		guint64 left = req->fd_len;
		if (lseek(req->fd, 0, SEEK_SET) < 0) {
			g_set_error(e, G_IO_ERROR, g_io_error_from_errno(errno), "file: %s", g_strerror(errno));
			return -EIO;
		}
		while (left) {
			ssize_t n = read(req->fd, buf, (size_t)MIN(left, (guint64)sizeof(buf)));
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0) {
				/* The file shrank under us: what Content-Length promised cannot be sent. */
				g_set_error(e, G_IO_ERROR, G_IO_ERROR_FAILED, "file: %s",
					    n < 0 ? g_strerror(errno) : "shorter than when it was opened");
				return -EIO;
			}
			if (!g_output_stream_write_all(os, buf, (gsize)n, NULL, cancel, e))
				return -EIO;
			left -= (guint64)n;
		}
	}
	if (req->tail_len && !g_output_stream_write_all(os, req->tail, req->tail_len, NULL, cancel, e))
		return -EIO;
	return 0;
}

static GIOStream *open_and_send(const struct rcs_config *cfg, const char *host, uint16_t port, int tls,
				const struct http_body *req, unsigned timeout_s, GCancellable *cancel,
				struct http_response *out, int *err)
{
	GError *e = NULL;
	memset(out, 0, sizeof(*out));
	GIOStream *s = rcs_net_connect(cfg, host, port, tls, timeout_s, cancel, &e);
	if (!s) {
		snprintf(out->error, sizeof(out->error), "%s", e->message);
		g_error_free(e);
		*err = -ECONNREFUSED;
		return NULL;
	}
	rcs_net_set_timeout(s, timeout_s);
	if (send_body(g_io_stream_get_output_stream(s), req, cancel, &e) < 0) {
		snprintf(out->error, sizeof(out->error), "sending: %s", e ? e->message : "?");
		g_clear_error(&e);
		g_io_stream_close(s, NULL, NULL);
		g_object_unref(s);
		*err = -EIO;
		return NULL;
	}
	return s;
}

/* One read; 0 at EOF (a TLS peer closing without close_notify included once
 * something came), <0 with out->error set. */
static gssize read_some(GInputStream *is, char *buf, size_t size, int have, GCancellable *cancel,
			struct http_response *out)
{
	GError *e = NULL;
	gssize n = g_input_stream_read(is, buf, size, cancel, &e);
	if (n >= 0)
		return n;
	if (have && g_error_matches(e, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
		g_error_free(e);
		return 0;
	}
	snprintf(out->error, sizeof(out->error), "receiving: %s", e->message);
	g_error_free(e);
	return -EIO;
}

/* Reads the rest of a response into out, raw holding what came so far. */
static int read_rest(GInputStream *is, GByteArray *raw, GCancellable *cancel, struct http_response *out)
{
	char buf[8192];
	int p = parse((const char *)raw->data, raw->len, 0, out);
	while (p == 0) {
		gssize n = read_some(is, buf, sizeof(buf), raw->len > 0, cancel, out);
		if (n < 0)
			return -EIO;
		if (n > 0)
			g_byte_array_append(raw, (const guint8 *)buf, (guint)n);
		p = parse((const char *)raw->data, raw->len, n == 0, out);
		if (p == 0 && raw->len > HTTP_MAX)
			p = -EBADMSG;
	}
	if (p < 0) {
		snprintf(out->error, sizeof(out->error), "unparsable response (%u bytes)", raw->len);
		out->status = 0;
		return -EBADMSG;
	}
	return 0;
}

static void finish(GIOStream *s, struct http_response *out, int r)
{
	g_io_stream_close(s, NULL, NULL);
	g_object_unref(s);
	if (r < 0) {
		char keep[256];
		snprintf(keep, sizeof(keep), "%s", out->error);
		http_response_clear(out);
		snprintf(out->error, sizeof(out->error), "%s", keep);
	}
}

int http_exchange_body(const struct rcs_config *cfg, const char *host, uint16_t port, int tls,
		       const struct http_body *req, unsigned timeout_s, GCancellable *cancel,
		       struct http_response *out)
{
	int r = 0;
	GIOStream *s = open_and_send(cfg, host, port, tls, req, timeout_s, cancel, out, &r);
	if (!s)
		return r;
	GByteArray *raw = g_byte_array_new();
	r = read_rest(g_io_stream_get_input_stream(s), raw, cancel, out);
	g_byte_array_free(raw, TRUE);
	finish(s, out, r);
	return r;
}

int http_exchange(const struct rcs_config *cfg, const char *host, uint16_t port, int tls,
		  const char *request, unsigned timeout_s, GCancellable *cancel,
		  struct http_response *out)
{
	struct http_body req = { .head = request, .head_len = strlen(request), .fd = -1 };
	return http_exchange_body(cfg, host, port, tls, &req, timeout_s, cancel, out);
}

/* ---- a 200's body into a file, as it comes -------------------------------- */

struct sink {
	int fd;
	guint64 max, written;
	int err;
};

static int sink_write(struct sink *k, const char *p, size_t n)
{
	if (k->max && k->written + n > k->max)
		return k->err = -EFBIG;
	while (n) {
		ssize_t w = write(k->fd, p, n);
		if (w < 0 && errno == EINTR)
			continue;
		if (w < 0)
			return k->err = -errno;
		p += w;
		n -= (size_t)w;
		k->written += (guint64)w;
	}
	return 0;
}

/* Chunked transfer coding (RFC 9112 7.1), fed as it arrives. */
enum { CH_SIZE, CH_DATA, CH_DATA_END, CH_TRAILER, CH_DONE };
struct dechunker {
	int state;
	guint64 left;
	GString *line;
};

/* 1 done, 0 more, <0 broken or the sink refused. */
static int dechunk_feed(struct dechunker *c, const char *p, size_t n, struct sink *k)
{
	while (n && c->state != CH_DONE) {
		if (c->state == CH_DATA) {
			size_t take = (size_t)MIN(c->left, (guint64)n);
			if (sink_write(k, p, take) < 0)
				return k->err;
			p += take;
			n -= take;
			c->left -= take;
			if (!c->left)
				c->state = CH_DATA_END;
			continue;
		}
		/* The other states are lines. */
		char ch = *p++;
		n--;
		if (ch != '\n') {
			if (c->line->len > 1024)
				return -EBADMSG;
			g_string_append_c(c->line, ch);
			continue;
		}
		if (c->line->len && c->line->str[c->line->len - 1] == '\r')
			g_string_truncate(c->line, c->line->len - 1);
		if (c->state == CH_SIZE) {
			char *end;
			errno = 0;
			guint64 v = g_ascii_strtoull(c->line->str, &end, 16);
			if (end == c->line->str || errno)
				return -EBADMSG;
			c->left = v;
			c->state = v ? CH_DATA : CH_TRAILER;
		} else if (c->state == CH_DATA_END) {
			if (c->line->len)
				return -EBADMSG;
			c->state = CH_SIZE;
		} else if (c->state == CH_TRAILER && !c->line->len) {
			c->state = CH_DONE;
		}
		g_string_truncate(c->line, 0);
	}
	return c->state == CH_DONE;
}

int http_download(const struct rcs_config *cfg, const char *host, uint16_t port, int tls,
		  const char *request, unsigned timeout_s, GCancellable *cancel, int out_fd,
		  guint64 max, struct http_response *out)
{
	struct http_body req = { .head = request, .head_len = strlen(request), .fd = -1 };
	int r = 0;
	GIOStream *s = open_and_send(cfg, host, port, tls, &req, timeout_s, cancel, out, &r);
	if (!s)
		return r;
	GInputStream *is = g_io_stream_get_input_stream(s);
	GByteArray *raw = g_byte_array_new();
	char buf[16384];
	gssize hl = 0;
	while (!(hl = parse_head((const char *)raw->data, raw->len, out))) {
		gssize n = read_some(is, buf, sizeof(buf), raw->len > 0, cancel, out);
		if (n <= 0 || raw->len > 65536) {
			if (n == 0 || raw->len > 65536)
				snprintf(out->error, sizeof(out->error), "no response header");
			r = -EIO;
			break;
		}
		g_byte_array_append(raw, (const guint8 *)buf, (guint)n);
	}
	if (hl < 0) {
		snprintf(out->error, sizeof(out->error), "unparsable response header");
		r = -EBADMSG;
	}
	if (r < 0 || out->status != 200) {
		if (r == 0)
			r = read_rest(is, raw, cancel, out);
		g_byte_array_free(raw, TRUE);
		finish(s, out, r);
		return r;
	}

	const char *ce = http_header(out, "Content-Encoding");
	const char *te = http_header(out, "Transfer-Encoding");
	const char *cl = http_header(out, "Content-Length");
	struct sink k = { .fd = out_fd, .max = max };
	struct dechunker ch = { .state = CH_SIZE, .line = g_string_new(NULL) };
	int chunked = te && g_ascii_strcasecmp(te, "identity");
	guint64 want = 0;
	int done = 0;
	if (ce && g_ascii_strcasecmp(ce, "identity")) {
		/* We asked for none (no Accept-Encoding); a file is stored as sent. */
		snprintf(out->error, sizeof(out->error), "Content-Encoding %s", ce);
		r = -EBADMSG;
	} else if (!chunked && cl) {
		want = g_ascii_strtoull(cl, NULL, 10);
		if (max && want > max)
			r = k.err = -EFBIG;
	}
	const char *p = (const char *)raw->data + hl;
	size_t n = raw->len - (size_t)hl;
	while (r == 0 && !done) {
		if (n) {
			if (chunked) {
				int c = dechunk_feed(&ch, p, n, &k);
				if (c < 0)
					r = c;
				done = c == 1;
			} else {
				size_t take = cl ? (size_t)MIN((guint64)n, want - k.written) : n;
				if (sink_write(&k, p, take) < 0)
					r = k.err;
				done = cl && k.written == want;
			}
		} else if (cl && !chunked && k.written == want) {
			done = 1;
		}
		if (r < 0 || done)
			break;
		gssize got = read_some(is, buf, sizeof(buf), 1, cancel, out);
		if (got < 0) {
			r = -EIO;
		} else if (got == 0) {
			/* Without a length the body ends at EOF; with one, EOF is a cut. */
			if (chunked || cl) {
				snprintf(out->error, sizeof(out->error), "connection closed after %" G_GUINT64_FORMAT " bytes",
					 k.written);
				r = -EIO;
			}
			done = 1;
		}
		p = buf;
		n = got > 0 ? (size_t)got : 0;
	}
	if (r == -EFBIG)
		snprintf(out->error, sizeof(out->error), "larger than %" G_GUINT64_FORMAT " bytes", max);
	else if (r < 0 && !out->error[0])
		snprintf(out->error, sizeof(out->error), "%s", g_strerror(-r));
	g_string_free(ch.line, TRUE);
	g_byte_array_free(raw, TRUE);
	out->len = (size_t)k.written;
	if (!out->body)
		out->body = g_strdup("");
	finish(s, out, r);
	return r;
}

int http_parse_url(const char *url, int *tls, char *host, size_t hsize, uint16_t *port,
		   char *path, size_t psize)
{
	const char *p;
	if (!g_ascii_strncasecmp(url, "http://", 7)) {
		*tls = 0;
		p = url + 7;
	} else if (!g_ascii_strncasecmp(url, "https://", 8)) {
		*tls = 1;
		p = url + 8;
	} else {
		return -EINVAL;
	}
	*port = *tls ? 443 : 80;
	size_t hl = strcspn(p, "/?#");
	const char *rest = p + hl;
	char hp[256];
	if (!hl || hl >= sizeof(hp) || hl >= hsize)
		return -EINVAL;
	memcpy(hp, p, hl);
	hp[hl] = '\0';
	if (strchr(hp, '@'))
		return -EINVAL; /* no userinfo: nothing in a URL picks credentials */
	char *colon = strrchr(hp, ':');
	if (colon && !strchr(hp, ']')) {
		*colon = '\0';
		char *end;
		long v = strtol(colon + 1, &end, 10);
		if (v <= 0 || v > 65535 || *end)
			return -EINVAL;
		*port = (uint16_t)v;
	}
	if (!hp[0])
		return -EINVAL;
	snprintf(host, hsize, "%s", hp);
	if (*rest == '?')
		snprintf(path, psize, "/%s", rest);
	else
		snprintf(path, psize, "%s", rest);
	char *hash = strchr(path, '#');
	if (hash)
		*hash = '\0';
	if (strlen(rest) >= psize)
		return -EINVAL;
	return 0;
}
