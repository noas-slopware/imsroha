// SPDX-License-Identifier: GPL-3.0-only
#define _GNU_SOURCE
#include "fthttp.h"
#include "http.h"
#include "sipmsg.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FT_TIMEOUT 60 /* s per read or write; the server answers the upload once it has it all */

/* ---- configuration -------------------------------------------------------- */

static const char *xv(const struct acs_xml *x, const char *k)
{
	const char *v = x ? acs_xml_get(x, k) : NULL;
	return v && *v ? v : NULL;
}

static guint64 kbytes(const struct acs_xml *x, const char *k, int *present)
{
	const char *v = xv(x, k);
	if (present)
		*present = v != NULL;
	return v ? g_ascii_strtoull(v, NULL, 10) * 1024 : 0;
}

void ft_config_from_xml(const struct acs_xml *x, struct ft_config *c)
{
	memset(c, 0, sizeof(*c));
	const char *v;
	if ((v = xv(x, "ftHTTPCSURI")))
		g_strlcpy(c->cs_uri, v, sizeof(c->cs_uri));
	/* R9 B.1: the large-file server and its limit are in IM's Ext. */
	if ((v = xv(x, "ftHTTPExtraCSURI")))
		g_strlcpy(c->extra_uri, v, sizeof(c->extra_uri));
	if ((v = xv(x, "ftHTTPCSUser")))
		g_strlcpy(c->user, v, sizeof(c->user));
	if ((v = xv(x, "ftHTTPCSPwd")))
		g_strlcpy(c->pwd, v, sizeof(c->pwd));
	c->max_size = kbytes(x, "MaxSizeFileTr", NULL);
	c->extra_max = kbytes(x, "MaxSizeExtraFileTr", NULL);
	c->warn_size = kbytes(x, "ftWarnSize", NULL);
	c->aut_accept = (v = xv(x, "ftAutAccept")) ? atoi(v) : 0;
	/*
	 * What a peer may send us: the incoming limit when the server gives one
	 * (stock's MaxSizeFileTrIncoming), else the larger of the two upload
	 * limits, since a peer on this network uploads to the same servers.
	 */
	int have;
	guint64 in = kbytes(x, "MaxSizeFileTrIncoming", &have);
	if (have)
		c->incoming_max = in;
	else if (c->extra_uri[0])
		c->incoming_max = c->extra_max ? MAX(c->extra_max, c->max_size) : 0;
	else
		c->incoming_max = c->max_size;
	/* ftAuth: 0 the user may not use file transfer, 1 may (RCC.07 A.1.4). */
	v = xv(x, "ftAuth");
	c->enabled = v && atoi(v) == 1 && c->cs_uri[0] && !strncmp(c->cs_uri, "http", 4);
}

const char *ft_upload_uri(const struct ft_config *c, guint64 size)
{
	if (!c->enabled)
		return NULL;
	if (!c->max_size || size <= c->max_size)
		return c->cs_uri;
	/* R9 B.1 a): above MaxSizeFileTr, ftHTTPExtraCSURI up to MaxSizeExtraFileTr (0: no limit). */
	if (c->extra_uri[0] && (!c->extra_max || size <= c->extra_max))
		return c->extra_uri;
	return NULL;
}

static int same_server(const char *a, const char *b)
{
	char ha[256], hb[256], pa[512], pb[512];
	uint16_t qa, qb;
	int ta, tb;
	if (!a[0] || !b[0] || http_parse_url(a, &ta, ha, sizeof(ha), &qa, pa, sizeof(pa)) < 0 ||
	    http_parse_url(b, &tb, hb, sizeof(hb), &qb, pb, sizeof(pb)) < 0)
		return 0;
	return ta && tb && qa == qb && !g_ascii_strcasecmp(ha, hb);
}

int ft_url_trusted(const struct ft_config *c, const char *url)
{
	return url && (same_server(url, c->cs_uri) || same_server(url, c->extra_uri));
}

/* ---- the file-info document (RCC.07 4.1.x, R9 7.4.1.1.1's example) ------- */

struct info_ctx {
	struct ft_info *f;
	struct ft_part *cur;
	GString *text;
	int in_field;
};

static const char *local(const char *el)
{
	const char *c = strrchr(el, ':');
	return c ? c + 1 : el;
}

static const char *attr(const char **n, const char **v, const char *want)
{
	for (int i = 0; n[i]; i++)
		if (!strcmp(local(n[i]), want))
			return v[i];
	return NULL;
}

static gint64 parse_until(const char *s)
{
	GDateTime *t = s ? g_date_time_new_from_iso8601(s, NULL) : NULL;
	if (!t)
		return 0;
	gint64 u = g_date_time_to_unix(t);
	g_date_time_unref(t);
	return u;
}

static void info_start(GMarkupParseContext *ctx, const char *el, const char **an, const char **av,
		       gpointer ud, GError **error)
{
	(void)ctx; (void)error;
	struct info_ctx *c = ud;
	const char *name = local(el);
	if (!strcmp(name, "file-info")) {
		const char *type = attr(an, av, "type");
		struct ft_part *p = type && !strcmp(type, "thumbnail") ? &c->f->thumb : &c->f->file;
		/* The first of each type counts. */
		c->cur = p->present ? NULL : p;
		if (c->cur)
			c->cur->present = 1;
	} else if (c->cur && !strcmp(name, "data")) {
		const char *u = attr(an, av, "url");
		if (u && !c->cur->url)
			c->cur->url = g_strdup(u);
		c->cur->until = parse_until(attr(an, av, "until"));
	} else if (c->cur && (!strcmp(name, "file-size") || !strcmp(name, "file-name") || !strcmp(name, "content-type"))) {
		c->in_field = 1;
		g_string_truncate(c->text, 0);
	}
}

static void info_text(GMarkupParseContext *ctx, const char *text, gsize len, gpointer ud, GError **error)
{
	(void)ctx; (void)error;
	struct info_ctx *c = ud;
	if (c->in_field && c->text->len < 4096)
		g_string_append_len(c->text, text, (gssize)len);
}

static void info_end(GMarkupParseContext *ctx, const char *el, gpointer ud, GError **error)
{
	(void)ctx; (void)error;
	struct info_ctx *c = ud;
	const char *name = local(el);
	if (!strcmp(name, "file-info")) {
		c->cur = NULL;
		return;
	}
	if (!c->cur || !c->in_field)
		return;
	c->in_field = 0;
	char *v = g_strstrip(g_strdup(c->text->str));
	if (!strcmp(name, "file-size")) {
		c->cur->size = g_ascii_strtoull(v, NULL, 10);
		g_free(v);
	} else if (!strcmp(name, "file-name") && !c->cur->name) {
		c->cur->name = v;
	} else if (!strcmp(name, "content-type") && !c->cur->ctype) {
		c->cur->ctype = v;
	} else {
		g_free(v);
	}
}

void ft_info_clear(struct ft_info *f)
{
	struct ft_part *ps[] = { &f->file, &f->thumb };
	for (size_t i = 0; i < G_N_ELEMENTS(ps); i++) {
		g_free(ps[i]->name);
		g_free(ps[i]->ctype);
		g_free(ps[i]->url);
	}
	memset(f, 0, sizeof(*f));
}

int ft_info_parse(const char *xml, size_t len, struct ft_info *out, GError **error)
{
	static const GMarkupParser parser = { .start_element = info_start, .end_element = info_end,
					      .text = info_text };
	memset(out, 0, sizeof(*out));
	struct info_ctx c = { .f = out, .text = g_string_new(NULL) };
	GMarkupParseContext *ctx = g_markup_parse_context_new(&parser, 0, &c, NULL);
	gboolean ok = g_markup_parse_context_parse(ctx, xml, (gssize)len, error) &&
		      g_markup_parse_context_end_parse(ctx, error);
	g_markup_parse_context_free(ctx);
	g_string_free(c.text, TRUE);
	if (ok && (!out->file.present || !out->file.url)) {
		g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT, "no file-info with a data url");
		ok = FALSE;
	}
	if (!ok) {
		ft_info_clear(out);
		return -EBADMSG;
	}
	return 0;
}

/* ---- names ------------------------------------------------------------------ */

char *ft_form_encode(const char *name)
{
	GString *s = g_string_new(NULL);
	for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
		if (g_ascii_isalnum(*p) || strchr(".-*_", *p))
			g_string_append_c(s, (char)*p);
		else if (*p == ' ')
			g_string_append_c(s, '+');
		else
			g_string_append_printf(s, "%%%02X", *p);
	}
	return g_string_free(s, FALSE);
}

char *ft_safe_name(const char *sent)
{
	if (!sent)
		return NULL;
	/* Stock decodes every file-name as a form (URLDecoder): '+' is a space. */
	char *plus = g_strdup(sent);
	for (char *p = plus; *p; p++)
		if (*p == '+')
			*p = ' ';
	char *dec = g_uri_unescape_string(plus, NULL);
	g_free(plus);
	if (!dec)
		dec = g_strdup(sent);
	char *valid = g_utf8_make_valid(dec, -1);
	g_free(dec);
	/* The last path component, whichever separator the sender's system uses. */
	const char *base = valid;
	for (const char *p = valid; *p; p++)
		if (*p == '/' || *p == '\\')
			base = p + 1;
	GString *s = g_string_new(NULL);
	for (const char *p = base; *p; p++)
		if ((unsigned char)*p >= 0x20 && *p != 0x7f)
			g_string_append_c(s, *p);
	g_free(valid);
	/* No hidden files, no "." or "..". */
	size_t lead = strspn(s->str, ". ");
	g_string_erase(s, 0, (gssize)lead);
	while (s->len && (s->str[s->len - 1] == ' '))
		g_string_truncate(s, s->len - 1);
	if (s->len > 200) {
		const char *dot = strrchr(s->str, '.');
		size_t elen = dot && strlen(dot) <= 16 ? strlen(dot) : 0;
		char *ext = g_strdup(elen ? dot : "");
		/* Cut the stem on a character boundary. */
		size_t limit = 200 - elen, keep = 0;
		for (const char *p = s->str; *p; p = g_utf8_next_char(p)) {
			size_t next = (size_t)(g_utf8_next_char(p) - s->str);
			if (next > limit)
				break;
			keep = next;
		}
		g_string_truncate(s, keep);
		g_string_append(s, ext);
		g_free(ext);
	}
	if (!s->len) {
		g_string_free(s, TRUE);
		return NULL;
	}
	return g_string_free(s, FALSE);
}

/* ---- HTTP Digest (RFC 7616) ------------------------------------------------ */

static char *hash_hex(GChecksumType t, const char *s)
{
	return g_compute_checksum_for_string(t, s, -1);
}

char *ft_digest(const char *challenge, const char *user, const char *pwd, const char *method,
		const char *uri, const char *cn)
{
	if (!challenge || g_ascii_strncasecmp(challenge, "Digest ", 7) || !user || !pwd)
		return NULL;
	if (strchr(user, '"') || strchr(user, '\\'))
		return NULL;
	char realm[256] = "", nonce[256] = "", opaque[256] = "", qop[64] = "", alg[32] = "MD5";
	sip_auth_param(challenge, "realm", realm, sizeof(realm));
	if (sip_auth_param(challenge, "nonce", nonce, sizeof(nonce)) < 0)
		return NULL;
	sip_auth_param(challenge, "opaque", opaque, sizeof(opaque));
	sip_auth_param(challenge, "qop", qop, sizeof(qop));
	sip_auth_param(challenge, "algorithm", alg, sizeof(alg));
	GChecksumType t;
	int sess = 0;
	if (!g_ascii_strcasecmp(alg, "MD5") || (sess = !g_ascii_strcasecmp(alg, "MD5-sess")))
		t = G_CHECKSUM_MD5;
	else if (!g_ascii_strcasecmp(alg, "SHA-256") || (sess = !g_ascii_strcasecmp(alg, "SHA-256-sess")))
		t = G_CHECKSUM_SHA256;
	else
		return NULL;
	int use_qop = 0;
	if (qop[0]) {
		char **q = g_strsplit(qop, ",", -1);
		for (int i = 0; q[i]; i++)
			use_qop |= !g_ascii_strcasecmp(g_strstrip(q[i]), "auth");
		g_strfreev(q);
		if (!use_qop)
			return NULL; /* auth-int only: not implemented */
	}
	char cnonce[64];
	if (cn)
		g_strlcpy(cnonce, cn, sizeof(cnonce));
	else
		sip_random(cnonce, 16);
	const char *nc = "00000001";

	char *s = g_strdup_printf("%s:%s:%s", user, realm, pwd);
	char *ha1 = hash_hex(t, s);
	g_free(s);
	if (sess) {
		s = g_strdup_printf("%s:%s:%s", ha1, nonce, cnonce);
		g_free(ha1);
		ha1 = hash_hex(t, s);
		g_free(s);
	}
	s = g_strdup_printf("%s:%s", method, uri);
	char *ha2 = hash_hex(t, s);
	g_free(s);
	if (use_qop)
		s = g_strdup_printf("%s:%s:%s:%s:auth:%s", ha1, nonce, nc, cnonce, ha2);
	else
		s = g_strdup_printf("%s:%s:%s", ha1, nonce, ha2);
	char *resp = hash_hex(t, s);
	g_free(s);
	GString *h = g_string_new(NULL);
	g_string_append_printf(h, "Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\",response=\"%s\",algorithm=%s",
			       user, realm, nonce, uri, resp, alg);
	if (use_qop)
		g_string_append_printf(h, ",qop=auth,nc=%s,cnonce=\"%s\"", nc, cnonce);
	if (opaque[0])
		g_string_append_printf(h, ",opaque=\"%s\"", opaque);
	/* HA1 is as good as the password for this realm. */
	memset(ha1, 0, strlen(ha1));
	g_free(ha1);
	g_free(ha2);
	g_free(resp);
	return g_string_free(h, FALSE);
}

/* The first Digest challenge of a 401 that we can answer. */
static char *answer_401(const struct http_response *r, const char *user, const char *pwd,
			const char *method, const char *uri)
{
	for (guint i = 0; r->names && i < r->names->len; i++) {
		if (g_ascii_strcasecmp(g_ptr_array_index(r->names, i), "WWW-Authenticate"))
			continue;
		char *a = ft_digest(g_ptr_array_index(r->values, i), user, pwd, method, uri, NULL);
		if (a)
			return a;
	}
	return NULL;
}

/* ---- upload and download ---------------------------------------------------- */

struct target {
	char host[256];
	uint16_t port;
	int tls;
	char path[1024];
	char hosthdr[300];
};

static int target_of(const char *url, struct target *t)
{
	if (http_parse_url(url, &t->tls, t->host, sizeof(t->host), &t->port, t->path, sizeof(t->path)) < 0)
		return -EINVAL;
	if (!t->path[0])
		snprintf(t->path, sizeof(t->path), "/");
	if (t->port == (t->tls ? 443 : 80))
		snprintf(t->hosthdr, sizeof(t->hosthdr), "%s", t->host);
	else
		snprintf(t->hosthdr, sizeof(t->hosthdr), "%s:%u", t->host, t->port);
	return 0;
}

static void wipe_free(char *s)
{
	if (s) {
		memset(s, 0, strlen(s));
		g_free(s);
	}
}

int ft_upload_run(const struct rcs_config *cfg, const struct ft_upload *u, GCancellable *cancel,
		  char **xml, size_t *len, char *err, size_t esize)
{
	struct target t;
	struct http_response r;
	*xml = NULL;
	if (target_of(u->url, &t) < 0) {
		snprintf(err, esize, "unusable content server URL");
		return -EINVAL;
	}
	/* 1. An empty POST: the server says whether it wants credentials (stock
	 *    sendEmptyPostRequest), so the file goes out once. */
	char *req = g_strdup_printf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
				    "Content-Length: 0\r\nConnection: close\r\n\r\n",
				    t.path, t.hosthdr, u->user_agent);
	int e = http_exchange(cfg, t.host, t.port, t.tls, req, FT_TIMEOUT, cancel, &r);
	g_free(req);
	if (e < 0) {
		snprintf(err, esize, "%s: %s", t.host, r.error);
		http_response_clear(&r);
		return e;
	}
	char *auth = NULL;
	if (r.status == 401) {
		auth = u->user ? answer_401(&r, u->user, u->pwd, "POST", t.path) : NULL;
		if (!auth) {
			snprintf(err, esize, "%s: 401 without a Digest challenge we can answer%s", t.host,
				 u->user ? "" : " (no ftHTTPCSUser)");
			http_response_clear(&r);
			return -EACCES;
		}
	} else if (r.status != 200 && r.status != 204) {
		snprintf(err, esize, "%s: empty POST: %d %s", t.host, r.status, r.reason);
		http_response_clear(&r);
		return -EIO;
	}
	http_response_clear(&r);

	/* 2. multipart/form-data: tid, then File (stock UploadFileTask; no Thumbnail). */
	char b[33];
	snprintf(b, sizeof(b), "imsroha");
	sip_random(b + 7, 24);
	char *fname = ft_form_encode(u->name);
	char *pre = g_strdup_printf("--%s\r\nContent-Disposition: form-data; name=\"tid\"\r\nContent-Type: text/plain\r\n\r\n%s"
				    "\r\n--%s\r\nContent-Disposition: form-data; name=\"File\"; filename=\"%s\"\r\n"
				    "Content-Type: %s\r\n\r\n",
				    b, u->tid, b, fname, u->ctype);
	g_free(fname);
	char *tail = g_strdup_printf("\r\n--%s--\r\n", b);
	guint64 clen = strlen(pre) + u->size + strlen(tail);
	GString *head = g_string_new(NULL);
	g_string_append_printf(head, "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n", t.path, t.hosthdr,
			       u->user_agent);
	if (auth)
		g_string_append_printf(head, "Authorization: %s\r\n", auth);
	g_string_append_printf(head, "Content-Type: multipart/form-data; boundary=%s\r\n"
			       "Content-Length: %" G_GUINT64_FORMAT "\r\nConnection: close\r\n\r\n%s",
			       b, clen, pre);
	g_free(pre);
	wipe_free(auth);
	struct http_body body = { .head = head->str, .head_len = head->len, .fd = u->fd, .fd_len = u->size,
				  .tail = tail, .tail_len = strlen(tail) };
	e = http_exchange_body(cfg, t.host, t.port, t.tls, &body, FT_TIMEOUT, cancel, &r);
	g_string_free(head, TRUE);
	g_free(tail);
	if (e < 0) {
		snprintf(err, esize, "%s: %s", t.host, r.error);
		http_response_clear(&r);
		return e;
	}
	if (r.status != 200) {
		snprintf(err, esize, "%s: upload: %d %s", t.host, r.status, r.reason);
		http_response_clear(&r);
		return r.status == 401 || r.status == 403 ? -EACCES : -EIO;
	}
	struct ft_info fi;
	GError *ge = NULL;
	if (ft_info_parse(r.body, r.len, &fi, &ge) < 0) {
		snprintf(err, esize, "%s: the answer is not a file-info: %s", t.host, ge->message);
		g_error_free(ge);
		http_response_clear(&r);
		return -EBADMSG;
	}
	ft_info_clear(&fi);
	*len = r.len;
	*xml = g_strndup(r.body, r.len);
	http_response_clear(&r);
	return 0;
}

int ft_download_run(const struct rcs_config *cfg, const char *url, const char *user, const char *pwd,
		    const char *user_agent, int fd, guint64 max, GCancellable *cancel, char *err,
		    size_t esize)
{
	struct target t;
	if (target_of(url, &t) < 0) {
		snprintf(err, esize, "unusable data URL");
		return -EINVAL;
	}
	char *auth = NULL;
	for (int round = 0;; round++) {
		GString *req = g_string_new(NULL);
		g_string_append_printf(req, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n", t.path, t.hosthdr,
				       user_agent);
		if (auth)
			g_string_append_printf(req, "Authorization: %s\r\n", auth);
		g_string_append(req, "Connection: close\r\n\r\n");
		wipe_free(auth);
		auth = NULL;
		struct http_response r;
		int e = http_download(cfg, t.host, t.port, t.tls, req->str, FT_TIMEOUT, cancel, fd, max, &r);
		/* The request held the Digest answer. */
		memset(req->str, 0, req->len);
		g_string_free(req, TRUE);
		if (e < 0) {
			snprintf(err, esize, "%s: %s", t.host, r.error);
			http_response_clear(&r);
			return e;
		}
		if (r.status == 200) {
			http_response_clear(&r);
			return 0;
		}
		if (r.status == 401 && round == 0 && user)
			auth = answer_401(&r, user, pwd, "GET", t.path);
		if (!auth) {
			snprintf(err, esize, "%s: %d %s%s", t.host, r.status, r.reason,
				 r.status == 401 && !user ? " (not one of our content servers: no credentials)" : "");
			int code = r.status;
			http_response_clear(&r);
			return code == 401 || code == 403 ? -EACCES : code == 404 || code == 410 ? -ENOENT : -EIO;
		}
		http_response_clear(&r);
	}
}

/* ---- whose file it is ------------------------------------------------------ */

int ft_as_user(const struct ft_ident *who, int (*fn)(void *), void *ud)
{
	if (!who || who->uid == geteuid())
		return fn(ud);
	gid_t saved[64];
	int ns = getgroups(G_N_ELEMENTS(saved), saved);
	if (ns < 0)
		return -errno;
	/* glibc's setgroups() changes every thread; the system call only this one. */
	if (syscall(SYS_setgroups, (size_t)who->ngroups, who->groups) < 0)
		return -errno;
	setfsgid(who->gid);
	setfsuid(who->uid);
	/* setfsuid/setfsgid report nothing; asking with -1 returns the current one. */
	int ok = setfsgid((gid_t)-1) == (int)who->gid && setfsuid((uid_t)-1) == (int)who->uid;
	int r = ok ? fn(ud) : -EPERM;
	setfsuid(geteuid());
	setfsgid(getegid());
	if (syscall(SYS_setgroups, (size_t)ns, saved) < 0 || setfsuid((uid_t)-1) != (int)geteuid() ||
	    setfsgid((gid_t)-1) != (int)getegid()) {
		/* A pool thread left with someone else's identity would be worse than no daemon. */
		fprintf(stderr, "imsroha-rcs: cannot restore our filesystem identity\n");
		abort();
	}
	return r;
}
