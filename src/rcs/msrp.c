// SPDX-License-Identifier: GPL-3.0-only
#include "msrp.h"
#include "net.h"
#include "sipmsg.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MSRP_CONNECT_TIMEOUT 20

struct pending {
	char id[40];
	char tid[40];
};

struct msrp {
	const struct rcs_config *cfg;
	char local[256], remote[512];
	char host[256];
	guint16 port;
	int tls;
	struct msrp_cbs cbs;
	void *ud;
	GIOStream *conn;
	GCancellable *cancel;
	GByteArray *rx;
	char buf[16384];
	int up;
	GList *pending;         /* our SENDs waiting for their 200 */
	GHashTable *partial;    /* Message-ID -> GByteArray, chunks so far */
	char bind_tid[40];
};

void msrp_frame_free(struct msrp_frame *f)
{
	if (!f)
		return;
	g_ptr_array_free(f->names, TRUE);
	g_ptr_array_free(f->values, TRUE);
	g_free(f->body);
	g_free(f);
}

const char *msrp_frame_header(const struct msrp_frame *f, const char *name)
{
	for (guint i = 0; i < f->names->len; i++)
		if (!g_ascii_strcasecmp(g_ptr_array_index(f->names, i), name))
			return g_ptr_array_index(f->values, i);
	return NULL;
}

gssize msrp_frame_parse(const char *buf, size_t len, struct msrp_frame **out)
{
	*out = NULL;
	const char *nl = memchr(buf, '\n', len);
	if (!nl)
		return len > 1024 ? -EBADMSG : 0;
	char first[256];
	snprintf(first, sizeof(first), "%.*s", (int)MIN((size_t)(nl - buf), sizeof(first) - 1), buf);
	g_strchomp(first);
	char tid[40], what[32];
	if (sscanf(first, "MSRP %39s %31s", tid, what) != 2)
		return -EBADMSG;
	char endl[64];
	int el = snprintf(endl, sizeof(endl), "-------%s", tid);
	/* The end-line: CRLF "-------" tid flag CRLF, the first one after the start line. */
	const char *p = nl + 1, *found = NULL;
	for (const char *q = p; q + el + 1 <= buf + len; q++) {
		if (!memcmp(q, endl, (size_t)el) && (q == p || q[-1] == '\n')) {
			found = q;
			break;
		}
	}
	if (!found)
		return len > (8u << 20) ? -EMSGSIZE : 0;
	const char *fe = found + el;
	if (fe + 1 > buf + len)
		return 0;
	const char *crlf = fe + 1;
	if (crlf + 2 > buf + len)
		return 0;
	struct msrp_frame *f = g_new0(struct msrp_frame, 1);
	f->names = g_ptr_array_new_with_free_func(g_free);
	f->values = g_ptr_array_new_with_free_func(g_free);
	snprintf(f->tid, sizeof(f->tid), "%s", tid);
	f->flag = *fe;
	if (g_ascii_isdigit(what[0])) {
		f->code = atoi(what);
	} else {
		f->request = 1;
		snprintf(f->method, sizeof(f->method), "%s", what);
	}
	/* Headers up to an empty line (then the body) or the end-line. */
	const char *h = p, *body = NULL;
	while (h < found) {
		const char *e = memchr(h, '\n', (size_t)(found - h));
		if (!e)
			break;
		size_t ll = (size_t)(e - h);
		if (ll && h[ll - 1] == '\r')
			ll--;
		if (!ll) {
			body = e + 1;
			break;
		}
		const char *colon = memchr(h, ':', ll);
		if (colon) {
			g_ptr_array_add(f->names, g_strndup(h, (gsize)(colon - h)));
			g_ptr_array_add(f->values, g_strstrip(g_strndup(colon + 1, (gsize)(h + ll - colon - 1))));
		}
		h = e + 1;
	}
	if (body) {
		/* The body ends with the CRLF before the end-line. */
		const char *be = found;
		if (be > body && be[-1] == '\n')
			be--;
		if (be > body && be[-1] == '\r')
			be--;
		f->body = g_strndup(body, (gsize)(be - body));
		f->blen = (size_t)(be - body);
	}
	*out = f;
	const char *after = crlf;
	if (after < buf + len && *after == '\r')
		after++;
	if (after < buf + len && *after == '\n')
		after++;
	return (gssize)(after - buf);
}

static int wire(struct msrp *m, const char *s, size_t n)
{
	GError *e = NULL;
	if (!m->conn)
		return -ENOTCONN;
	if (!g_output_stream_write_all(g_io_stream_get_output_stream(m->conn), s, n, NULL, NULL, &e)) {
		fprintf(stderr, "imsroha-rcs: MSRP send: %s\n", e->message);
		g_error_free(e);
		return -EIO;
	}
	return 0;
}

static void respond(struct msrp *m, const struct msrp_frame *f, int code, const char *comment)
{
	const char *fr = msrp_frame_header(f, "From-Path");
	GString *s = g_string_new(NULL);
	g_string_append_printf(s, "MSRP %s %d %s\r\nTo-Path: %s\r\nFrom-Path: %s\r\n-------%s$\r\n", f->tid, code,
			       comment, fr ? fr : m->remote, m->local, f->tid);
	wire(m, s->str, s->len);
	g_string_free(s, TRUE);
}

static void report(struct msrp *m, const struct msrp_frame *f)
{
	char tid[17];
	sip_random(tid, 16);
	const char *fr = msrp_frame_header(f, "From-Path"), *id = msrp_frame_header(f, "Message-ID");
	const char *br = msrp_frame_header(f, "Byte-Range");
	GString *s = g_string_new(NULL);
	g_string_append_printf(s, "MSRP %s REPORT\r\nTo-Path: %s\r\nFrom-Path: %s\r\nMessage-ID: %s\r\n"
			       "Byte-Range: %s\r\nStatus: 000 200 OK\r\n-------%s$\r\n",
			       tid, fr ? fr : m->remote, m->local, id ? id : "", br ? br : "1-*/*", tid);
	wire(m, s->str, s->len);
	g_string_free(s, TRUE);
}

static void on_frame(struct msrp *m, struct msrp_frame *f)
{
	if (!f->request) {
		if (!strcmp(f->tid, m->bind_tid)) {
			m->bind_tid[0] = '\0';
			if (f->code == 200 && !m->up) {
				m->up = 1;
				if (m->cbs.state)
					m->cbs.state(m, 1, m->ud);
			}
			return;
		}
		for (GList *l = m->pending; l; l = l->next) {
			struct pending *p = l->data;
			if (strcmp(p->tid, f->tid))
				continue;
			m->pending = g_list_delete_link(m->pending, l);
			if (m->cbs.result)
				m->cbs.result(m, p->id, f->code, m->ud);
			g_free(p);
			return;
		}
		return;
	}
	if (!strcmp(f->method, "REPORT"))
		return;
	if (strcmp(f->method, "SEND")) {
		respond(m, f, 501, "Not Implemented");
		return;
	}
	const char *fr = msrp_frame_header(f, "Failure-Report");
	if (!fr || g_ascii_strcasecmp(fr, "no"))
		respond(m, f, 200, "OK");
	const char *sr = msrp_frame_header(f, "Success-Report");
	if (sr && !g_ascii_strcasecmp(sr, "yes") && f->flag == '$')
		report(m, f);
	/* An empty SEND binds the far end's side of the connection. */
	if (!m->up && !f->blen) {
		m->up = 1;
		if (m->cbs.state)
			m->cbs.state(m, 1, m->ud);
	}
	const char *id = msrp_frame_header(f, "Message-ID");
	const char *ct = msrp_frame_header(f, "Content-Type");
	if (!f->blen && !ct)
		return;
	GByteArray *acc = id ? g_hash_table_lookup(m->partial, id) : NULL;
	if (f->flag == '+' || acc) {
		if (!acc) {
			acc = g_byte_array_new();
			g_hash_table_insert(m->partial, g_strdup(id), acc);
		}
		g_byte_array_append(acc, (const guint8 *)f->body, (guint)f->blen);
		if (f->flag == '+')
			return;
		if (f->flag == '#') {
			g_hash_table_remove(m->partial, id);
			return;
		}
		char *ctype = g_strdup(ct ? ct : "");
		g_byte_array_append(acc, (const guint8 *)"", 1);
		if (m->cbs.message)
			m->cbs.message(m, ctype, (const char *)acc->data, acc->len - 1, m->ud);
		g_free(ctype);
		g_hash_table_remove(m->partial, id);
		return;
	}
	if (f->flag == '$' && m->cbs.message)
		m->cbs.message(m, ct ? ct : "", f->body ? f->body : "", f->blen, m->ud);
}

static void read_more(struct msrp *m);

static void conn_gone(struct msrp *m, const char *why)
{
	fprintf(stderr, "imsroha-rcs: MSRP connection closed: %s\n", why);
	int was = m->conn != NULL;
	if (m->conn) {
		g_io_stream_close(m->conn, NULL, NULL);
		g_object_unref(m->conn);
		m->conn = NULL;
	}
	m->up = 0;
	GList *p = m->pending;
	m->pending = NULL;
	for (GList *l = p; l; l = l->next) {
		struct pending *x = l->data;
		if (m->cbs.result)
			m->cbs.result(m, x->id, 0, m->ud);
		g_free(x);
	}
	g_list_free(p);
	if (was && m->cbs.state)
		m->cbs.state(m, 0, m->ud);
}

static void on_read(GObject *src, GAsyncResult *res, gpointer ud)
{
	GError *e = NULL;
	gssize n = g_input_stream_read_finish(G_INPUT_STREAM(src), res, &e);
	if (n < 0 && g_error_matches(e, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free(e);
		return;
	}
	struct msrp *m = ud;
	if (n <= 0) {
		conn_gone(m, e ? e->message : "closed by the peer");
		g_clear_error(&e);
		return;
	}
	g_byte_array_append(m->rx, (const guint8 *)m->buf, (guint)n);
	for (;;) {
		struct msrp_frame *f = NULL;
		gssize used = msrp_frame_parse((const char *)m->rx->data, m->rx->len, &f);
		if (used < 0) {
			conn_gone(m, "unparsable MSRP");
			return;
		}
		if (!used)
			break;
		g_byte_array_remove_range(m->rx, 0, (guint)used);
		on_frame(m, f);
		msrp_frame_free(f);
		if (!m->conn)
			return;
	}
	read_more(m);
}

static void read_more(struct msrp *m)
{
	g_input_stream_read_async(g_io_stream_get_input_stream(m->conn), m->buf, sizeof(m->buf),
				  G_PRIORITY_DEFAULT, m->cancel, on_read, m);
}

static int send_frame(struct msrp *m, const char *ctype, const char *body, size_t len, int want_report,
		      char *tid_out, char *id_out)
{
	char tid[17], id[25];
	sip_random(tid, 16);
	sip_random(id, 24);
	GString *s = g_string_new(NULL);
	g_string_append_printf(s, "MSRP %s SEND\r\nTo-Path: %s\r\nFrom-Path: %s\r\nMessage-ID: %s\r\n", tid, m->remote,
			       m->local, id);
	if (!want_report)
		g_string_append(s, "Failure-Report: no\r\n");
	g_string_append(s, "Success-Report: no\r\n");
	g_string_append_printf(s, "Byte-Range: 1-%zu/%zu\r\n", len, len);
	if (ctype)
		g_string_append_printf(s, "Content-Type: %s\r\n\r\n", ctype);
	if (len) {
		g_string_append_len(s, body, (gssize)len);
		g_string_append(s, "\r\n");
	}
	g_string_append_printf(s, "-------%s$\r\n", tid);
	int r = wire(m, s->str, s->len);
	g_string_free(s, TRUE);
	if (tid_out)
		snprintf(tid_out, 40, "%s", tid);
	if (id_out)
		snprintf(id_out, 40, "%s", id);
	return r;
}

static void on_connected(GObject *src, GAsyncResult *res, gpointer ud)
{
	(void)src;
	GError *e = NULL;
	GIOStream *s = rcs_net_connect_finish(res, &e);
	if (!s && g_error_matches(e, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free(e);
		return;
	}
	struct msrp *m = ud;
	if (!s) {
		fprintf(stderr, "imsroha-rcs: MSRP %s:%u: %s\n", m->host, m->port, e->message);
		g_error_free(e);
		if (m->cbs.state)
			m->cbs.state(m, 0, m->ud);
		return;
	}
	m->conn = s;
	read_more(m);
	/* The binding SEND (RFC 4975 7.1.1); up once it is answered. */
	send_frame(m, NULL, NULL, 0, 1, m->bind_tid, NULL);
}

struct msrp *msrp_new(const struct rcs_config *cfg, const char *local_path, const char *remote_path,
		      const struct msrp_cbs *cbs, void *ud)
{
	struct msrp *m = g_new0(struct msrp, 1);
	m->cfg = cfg;
	snprintf(m->local, sizeof(m->local), "%s", local_path);
	snprintf(m->remote, sizeof(m->remote), "%s", remote_path);
	m->cbs = *cbs;
	m->ud = ud;
	m->rx = g_byte_array_new();
	m->partial = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_byte_array_unref);
	/* The first hop: msrp[s]://host:port/id;tcp */
	const char *p = remote_path;
	m->tls = !g_ascii_strncasecmp(p, "msrps://", 8);
	p = strstr(p, "://");
	p = p ? p + 3 : remote_path;
	char hp[300];
	size_t n = strcspn(p, "/ ");
	snprintf(hp, sizeof(hp), "%.*s", (int)n, p);
	char *colon = hp[0] == '[' ? strstr(hp, "]:") : strrchr(hp, ':');
	if (hp[0] == '[') {
		char *rb = strchr(hp, ']');
		if (rb)
			*rb = '\0';
		m->port = colon ? (guint16)atoi(colon + 2) : 2855;
		snprintf(m->host, sizeof(m->host), "%s", hp + 1);
	} else {
		if (colon)
			*colon = '\0';
		m->port = colon ? (guint16)atoi(colon + 1) : 2855;
		snprintf(m->host, sizeof(m->host), "%s", hp);
	}
	return m;
}

void msrp_connect(struct msrp *m)
{
	if (!m->cancel)
		m->cancel = g_cancellable_new();
	fprintf(stderr, "imsroha-rcs: MSRP to %s:%u over %s\n", m->host, m->port, m->tls ? "TLS" : "TCP");
	rcs_net_connect_async(m->cfg, m->host, m->port, m->tls, MSRP_CONNECT_TIMEOUT, m->cancel, on_connected, m);
}

int msrp_send(struct msrp *m, const char *ctype, const char *body, size_t len, int want_report,
	      char *msrp_id, size_t idsize)
{
	char tid[40], id[40];
	int r = send_frame(m, ctype, body, len, want_report, tid, id);
	if (r < 0)
		return r;
	if (msrp_id)
		snprintf(msrp_id, idsize, "%s", id);
	if (want_report) {
		struct pending *p = g_new0(struct pending, 1);
		snprintf(p->id, sizeof(p->id), "%s", id);
		snprintf(p->tid, sizeof(p->tid), "%s", tid);
		m->pending = g_list_append(m->pending, p);
	}
	return 0;
}

void msrp_free(struct msrp *m)
{
	if (!m)
		return;
	if (m->cancel) {
		g_cancellable_cancel(m->cancel);
		g_object_unref(m->cancel);
	}
	if (m->conn) {
		g_io_stream_close(m->conn, NULL, NULL);
		g_object_unref(m->conn);
	}
	g_list_free_full(m->pending, g_free);
	g_hash_table_destroy(m->partial);
	g_byte_array_free(m->rx, TRUE);
	g_free(m);
}
