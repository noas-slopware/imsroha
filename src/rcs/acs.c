// SPDX-License-Identifier: GPL-3.0-only
/*
 * RCS autoconfiguration: GSMA RCC.14 as TTAK.KO-06.0410/R9 6.3 describes it,
 * with the parameters stock Samsung sends (WorkflowSec) and the client fields
 * from [rcs]. Nothing here runs unless [rcs] enable=true, except the one
 * rcs_state=-4 request after it was turned off again.
 */
#include "acs.h"
#include "http.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <gio/gio.h>

#define ACS_TIMEOUT 30 /* stock: 30 s to connect */

/* ---- URLs and the request ---------------------------------------------- */

static int parse_url(const char *url, int *tls, char *host, size_t hsize, uint16_t *port,
		     char *path, size_t psize)
{
	const char *p;
	if (!strncmp(url, "http://", 7)) {
		*tls = 0;
		p = url + 7;
	} else if (!strncmp(url, "https://", 8)) {
		*tls = 1;
		p = url + 8;
	} else {
		return -EINVAL;
	}
	*port = *tls ? 443 : 80;
	const char *slash = strchr(p, '/');
	size_t hl = slash ? (size_t)(slash - p) : strlen(p);
	char hp[256];
	if (!hl || hl >= sizeof(hp))
		return -EINVAL;
	memcpy(hp, p, hl);
	hp[hl] = '\0';
	char *colon = strrchr(hp, ':');
	if (colon && !strchr(hp, ']')) {
		*colon = '\0';
		long v = strtol(colon + 1, NULL, 10);
		if (v <= 0 || v > 65535)
			return -EINVAL;
		*port = (uint16_t)v;
	}
	snprintf(host, hsize, "%s", hp);
	snprintf(path, psize, "%s", slash ? slash : "");
	return 0;
}

/* RFC 3986 unreserved characters stay, everything else is %XX. */
static void pct(GString *s, const char *v)
{
	for (const unsigned char *c = (const unsigned char *)v; *c; c++) {
		if (g_ascii_isalnum(*c) || *c == '-' || *c == '.' || *c == '_' || *c == '~')
			g_string_append_c(s, (char)*c);
		else
			g_string_append_printf(s, "%%%02X", *c);
	}
}

static void param(GString *q, const char *name, const char *value)
{
	if (q->len)
		g_string_append_c(q, '&');
	g_string_append(q, name);
	g_string_append_c(q, '=');
	pct(q, value ? value : "");
}

void acs_request_clear(struct acs_request *r)
{
	g_free(r->text);
	memset(r, 0, sizeof(*r));
}

int acs_build_request(const struct rcs_config *cfg, const struct rcs_identity *id,
		      const struct acs_state *st, enum acs_leg leg, int non_ps,
		      const char *cookie, const char *otp, const char *rcs_state,
		      struct acs_request *out)
{
	char url[260], path[256];
	int tls;

	memset(out, 0, sizeof(*out));
	if (leg == ACS_LEG_HTTP) {
		snprintf(url, sizeof(url), "%s", cfg->acs_url);
	} else if (cfg->acs_https_url[0]) {
		snprintf(url, sizeof(url), "%s", cfg->acs_https_url);
	} else if (!strncmp(cfg->acs_url, "http://", 7)) {
		snprintf(url, sizeof(url), "https://%s", cfg->acs_url + 7);
	} else {
		snprintf(url, sizeof(url), "%s", cfg->acs_url);
	}
	if (parse_url(url, &tls, out->host, sizeof(out->host), &out->port, path, sizeof(path)) < 0)
		return -EINVAL;
	out->tls = tls;

	GString *q = g_string_new(NULL);
	if (leg == ACS_LEG_HTTPS) {
		char num[16];
		snprintf(num, sizeof(num), "%d", st->rcscfg_force ? 0 : st->version);
		param(q, "vers", num);
		if (!rcs_state) {
			snprintf(num, sizeof(num), "%d", st->version > 0 ? st->version : 0);
			rcs_state = num;
		}
		/* num is reused only after rcs_state is appended. */
		param(q, "rcs_state", rcs_state);
		param(q, "IMSI", id->imsi);
		param(q, "IMEI", id->imei);
		param(q, "terminal_model", cfg->base.dev.model);
		param(q, "terminal_vendor", cfg->terminal_vendor);
		param(q, "terminal_sw_version", cfg->base.dev.build);
		param(q, "client_vendor", cfg->client_vendor);
		param(q, "client_version", cfg->client_version);
		param(q, "rcs_profile", cfg->profile);
		param(q, "provisioning_version", cfg->provisioning_version);
		if (cfg->rcs_version[0])
			param(q, "rcs_version", cfg->rcs_version);
		char **apps = g_strsplit(cfg->app, ",", -1);
		for (int i = 0; apps[i]; i++) {
			g_strstrip(apps[i]);
			if (apps[i][0])
				param(q, "app", apps[i]);
		}
		g_strfreev(apps);
		snprintf(num, sizeof(num), "%d", cfg->default_sms_app);
		param(q, "default_sms_app", num);
		if (non_ps) {
			param(q, "msisdn", id->msisdn);
			snprintf(num, sizeof(num), "%u", cfg->otp_port);
			param(q, "SMS_port", num);
			param(q, "token", st->token);
		}
	} else if (leg == ACS_LEG_OTP) {
		param(q, "OTP", otp);
	}

	/* Stock drops a trailing '/' and appends "?": http://host -> GET /?... */
	size_t pl = strlen(path);
	if (pl && path[pl - 1] == '/')
		path[--pl] = '\0';
	GString *r = g_string_new("GET ");
	g_string_append(r, pl ? path : "/");
	if (q->len) {
		if (pl)
			g_string_append_c(r, '?');
		else
			g_string_append_c(r, '?');
		g_string_append(r, q->str);
	}
	g_string_free(q, TRUE);

	char ua[256];
	rcs_config_expand_ua(cfg, cfg->http_user_agent, ua, sizeof(ua));
	int default_port = out->port == (tls ? 443 : 80);
	g_string_append(r, " HTTP/1.1\r\n");
	if (default_port)
		g_string_append_printf(r, "Host: %s\r\n", out->host);
	else
		g_string_append_printf(r, "Host: %s:%u\r\n", out->host, out->port);
	g_string_append(r, "Accept-Encoding: gzip\r\n");
	if (cfg->accept_language[0])
		g_string_append_printf(r, "Accept-Language: %s\r\n", cfg->accept_language);
	g_string_append_printf(r, "User-Agent: %s\r\n", ua);
	if (cookie && *cookie)
		g_string_append_printf(r, "Cookie: %s\r\n", cookie);
	g_string_append(r, "Cache-Control: max-age=0\r\n");
	g_string_append(r, "Connection: close\r\n\r\n");
	out->text = g_string_free(r, FALSE);
	return 0;
}

/* ---- the XML ------------------------------------------------------------ */

struct xml_ctx {
	struct acs_xml *x;
	GPtrArray *stack;
	int other_types; /* characteristics other than VERS and TOKEN */
};

static const char *attr(const char **names, const char **values, const char *want)
{
	for (int i = 0; names[i]; i++)
		if (!g_ascii_strcasecmp(names[i], want))
			return values[i];
	return NULL;
}

static void xml_start(GMarkupParseContext *c, const char *el, const char **an, const char **av,
		      gpointer ud, GError **error)
{
	(void)c; (void)error;
	struct xml_ctx *x = ud;
	if (!g_ascii_strcasecmp(el, "characteristic")) {
		const char *type = attr(an, av, "type");
		g_ptr_array_add(x->stack, g_strdup(type ? type : ""));
		if (type && g_ascii_strcasecmp(type, "VERS") && g_ascii_strcasecmp(type, "TOKEN"))
			x->other_types = 1;
	} else if (!g_ascii_strcasecmp(el, "parm")) {
		const char *name = attr(an, av, "name");
		const char *value = attr(an, av, "value");
		if (!name)
			return;
		GString *p = g_string_new(NULL);
		for (guint i = 0; i < x->stack->len; i++) {
			g_string_append(p, g_ptr_array_index(x->stack, i));
			g_string_append_c(p, '/');
		}
		g_string_append(p, name);
		g_ptr_array_add(x->x->keys, g_string_free(p, FALSE));
		g_ptr_array_add(x->x->values, g_strdup(value ? value : ""));
	}
}

static void xml_end(GMarkupParseContext *c, const char *el, gpointer ud, GError **error)
{
	(void)c; (void)error;
	struct xml_ctx *x = ud;
	if (!g_ascii_strcasecmp(el, "characteristic") && x->stack->len)
		g_ptr_array_remove_index(x->stack, x->stack->len - 1);
}

static int path_ends(const char *path, const char *suffix)
{
	size_t pl = strlen(path), sl = strlen(suffix);
	if (sl > pl || g_ascii_strcasecmp(path + pl - sl, suffix))
		return 0;
	return pl == sl || path[pl - sl - 1] == '/';
}

const char *acs_xml_get(const struct acs_xml *x, const char *suffix)
{
	for (guint i = 0; x && i < x->keys->len; i++)
		if (path_ends(g_ptr_array_index(x->keys, i), suffix))
			return g_ptr_array_index(x->values, i);
	return NULL;
}

const char **acs_xml_get_all(const struct acs_xml *x, const char *suffix)
{
	GPtrArray *a = g_ptr_array_new();
	for (guint i = 0; x && i < x->keys->len; i++)
		if (path_ends(g_ptr_array_index(x->keys, i), suffix))
			g_ptr_array_add(a, g_ptr_array_index(x->values, i));
	g_ptr_array_add(a, NULL);
	return (const char **)g_ptr_array_free(a, FALSE);
}

struct acs_xml *acs_xml_parse(const char *body, size_t len, GError **error)
{
	static const GMarkupParser parser = { .start_element = xml_start, .end_element = xml_end };
	struct acs_xml *x = g_new0(struct acs_xml, 1);
	x->keys = g_ptr_array_new_with_free_func(g_free);
	x->values = g_ptr_array_new_with_free_func(g_free);
	struct xml_ctx c = { .x = x, .stack = g_ptr_array_new_with_free_func(g_free) };

	/* GMarkup does not take the XML declaration's encoding; skip leading space. */
	while (len && g_ascii_isspace(*body)) {
		body++;
		len--;
	}
	GMarkupParseContext *pc = g_markup_parse_context_new(&parser, 0, &c, NULL);
	gboolean ok = g_markup_parse_context_parse(pc, body, (gssize)len, error) &&
		      g_markup_parse_context_end_parse(pc, error);
	g_markup_parse_context_free(pc);
	g_ptr_array_free(c.stack, TRUE);
	if (!ok) {
		acs_xml_free(x);
		return NULL;
	}
	const char *v = acs_xml_get(x, "VERS/version");
	const char *d = acs_xml_get(x, "VERS/validity");
	if (v && d) {
		x->has_vers = 1;
		x->version = (int)strtol(v, NULL, 10);
		x->validity = (int)strtol(d, NULL, 10);
	}
	const char *t = acs_xml_get(x, "TOKEN/token");
	x->token = t ? g_strdup(t) : NULL;
	/* Remember whether there was more than VERS/TOKEN: a full configuration. */
	if (c.other_types)
		g_ptr_array_add(x->keys, g_strdup("\x01full")), g_ptr_array_add(x->values, g_strdup("1"));
	return x;
}

static int xml_is_full(const struct acs_xml *x)
{
	for (guint i = 0; i < x->keys->len; i++)
		if (!strcmp(g_ptr_array_index(x->keys, i), "\x01full"))
			return 1;
	return 0;
}

void acs_xml_free(struct acs_xml *x)
{
	if (!x)
		return;
	g_ptr_array_free(x->keys, TRUE);
	g_ptr_array_free(x->values, TRUE);
	g_free(x->token);
	g_free(x);
}

/* ---- state -------------------------------------------------------------- */

static char *imsi_dir(const struct rcs_config *cfg, const char *imsi)
{
	return g_build_filename(cfg->state_dir, imsi, NULL);
}

static int write_file(const char *dir, const char *name, const char *data, size_t len)
{
	if (g_mkdir_with_parents(dir, 0700) < 0)
		return -errno;
	char *path = g_build_filename(dir, name, NULL);
	char *tmp = g_strconcat(path, ".tmp", NULL);
	int r = 0;
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		r = -errno;
	} else {
		size_t off = 0;
		while (off < len) {
			ssize_t n = write(fd, data + off, len - off);
			if (n < 0) {
				r = -errno;
				break;
			}
			off += (size_t)n;
		}
		if (!r && fsync(fd) < 0)
			r = -errno;
		close(fd);
		if (!r && rename(tmp, path) < 0)
			r = -errno;
		if (r)
			unlink(tmp);
	}
	g_free(tmp);
	g_free(path);
	return r;
}

int acs_state_load(const struct rcs_config *cfg, const char *imsi, struct acs_state *st)
{
	memset(st, 0, sizeof(*st));
	char *dir = imsi_dir(cfg, imsi);
	char *path = g_build_filename(dir, "state", NULL);
	g_free(dir);
	GKeyFile *kf = g_key_file_new();
	gboolean ok = g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, NULL);
	g_free(path);
	if (!ok) {
		g_key_file_free(kf);
		return -ENOENT;
	}
	st->version = g_key_file_get_integer(kf, "acs", "version", NULL);
	st->validity = g_key_file_get_integer(kf, "acs", "validity", NULL);
	char *t = g_key_file_get_string(kf, "acs", "token", NULL);
	snprintf(st->token, sizeof(st->token), "%s", t ? t : "");
	g_free(t);
	st->next_run = g_key_file_get_int64(kf, "acs", "next-run", NULL);
	st->last_status = g_key_file_get_integer(kf, "acs", "last-status", NULL);
	st->permanent = g_key_file_get_boolean(kf, "acs", "permanent", NULL);
	st->contacted = g_key_file_get_boolean(kf, "acs", "contacted", NULL);
	st->disable_sent = g_key_file_get_boolean(kf, "acs", "disable-sent", NULL);
	st->trial = g_key_file_get_integer(kf, "acs", "trial", NULL);
	st->rcscfg_force = g_key_file_get_boolean(kf, "acs", "force", NULL);
	st->last_run = g_key_file_get_int64(kf, "acs", "last-run", NULL);
	g_key_file_free(kf);
	return 0;
}

int acs_state_save(const struct rcs_config *cfg, const char *imsi, const struct acs_state *st)
{
	GKeyFile *kf = g_key_file_new();
	g_key_file_set_integer(kf, "acs", "version", st->version);
	g_key_file_set_integer(kf, "acs", "validity", st->validity);
	g_key_file_set_string(kf, "acs", "token", st->token);
	g_key_file_set_int64(kf, "acs", "next-run", st->next_run);
	g_key_file_set_integer(kf, "acs", "last-status", st->last_status);
	g_key_file_set_boolean(kf, "acs", "permanent", st->permanent);
	g_key_file_set_boolean(kf, "acs", "contacted", st->contacted);
	g_key_file_set_boolean(kf, "acs", "disable-sent", st->disable_sent);
	g_key_file_set_integer(kf, "acs", "trial", st->trial);
	g_key_file_set_boolean(kf, "acs", "force", st->rcscfg_force);
	g_key_file_set_int64(kf, "acs", "last-run", st->last_run);
	gsize len;
	char *data = g_key_file_to_data(kf, &len, NULL);
	g_key_file_free(kf);
	char *dir = imsi_dir(cfg, imsi);
	int r = write_file(dir, "state", data, len);
	g_free(dir);
	g_free(data);
	return r;
}

int acs_config_save(const struct rcs_config *cfg, const char *imsi, const char *xml, size_t len)
{
	char *dir = imsi_dir(cfg, imsi);
	int r = write_file(dir, "config.xml", xml, len);
	g_free(dir);
	return r;
}

char *acs_config_load(const struct rcs_config *cfg, const char *imsi, size_t *len)
{
	char *path = g_build_filename(cfg->state_dir, imsi, "config.xml", NULL);
	char *data = NULL;
	gsize l = 0;
	if (!g_file_get_contents(path, &data, &l, NULL))
		data = NULL;
	g_free(path);
	if (len)
		*len = l;
	return data;
}

void acs_config_remove(const struct rcs_config *cfg, const char *imsi)
{
	char *path = g_build_filename(cfg->state_dir, imsi, "config.xml", NULL);
	unlink(path);
	g_free(path);
}

int acs_any_pending_disable(const struct rcs_config *cfg)
{
	GDir *d = g_dir_open(cfg->state_dir, 0, NULL);
	if (!d)
		return 0;
	const char *name;
	int any = 0;
	while (!any && (name = g_dir_read_name(d))) {
		struct acs_state st;
		if (acs_state_load(cfg, name, &st) == 0 && st.contacted && st.version > 0 &&
		    !st.disable_sent && !st.permanent)
			any = 1;
	}
	g_dir_close(d);
	return any;
}

/* ---- responses ---------------------------------------------------------- */

int acs_retry_delay(int trial)
{
	/* R9 6.3.1.2.3: 20 min, 1, 2, 4, 8 h, then the next start. */
	static const int delay[] = { 1200, 3600, 7200, 14400, 28800 };
	return trial >= 0 && trial < (int)G_N_ELEMENTS(delay) ? delay[trial] : -1;
}

enum acs_outcome acs_apply_vers(const struct rcs_config *cfg, const char *imsi,
				struct acs_state *st, const struct acs_xml *x,
				const char *body, size_t len, int64_t now)
{
	int v = x->version, d = x->validity;

	st->trial = 0;
	st->rcscfg_force = 0;
	if (x->token && x->token[0])
		snprintf(st->token, sizeof(st->token), "%s", x->token);

	if (v > 0) {
		if (xml_is_full(x)) {
			acs_config_save(cfg, imsi, body, len);
		} else {
			size_t l = 0;
			char *have = acs_config_load(cfg, imsi, &l);
			g_free(have);
			if (!have || v != st->version) {
				/* VERS only, but nothing (or another version) stored: ask in full. */
				fprintf(stderr, "imsroha-rcs: ACS: version %d without a configuration, have %d\n",
					v, have ? st->version : 0);
				st->version = 0;
				st->rcscfg_force = 1;
				st->next_run = 0;
				return ACS_NONE;
			}
		}
		st->version = v;
		st->validity = d;
		st->contacted = 1;
		st->disable_sent = 0;
		st->next_run = d > 0 ? now + d : 0;
		fprintf(stderr, "imsroha-rcs: ACS: version %d, valid for %d s\n", v, d);
		return ACS_ACTIVE;
	}
	if (v == 0) {
		acs_config_remove(cfg, imsi);
		st->version = 0;
		st->validity = d;
		st->next_run = d > 0 ? now + d : 0;
		fprintf(stderr, "imsroha-rcs: ACS: version 0 (not provisioned now), %s\n",
			d > 0 ? "retrying after validity" : "retrying at the next start");
		return ACS_NONE;
	}
	if (v == -1) {
		acs_config_remove(cfg, imsi);
		st->version = -1;
		st->validity = d;
		st->permanent = 1;
		st->next_run = 0;
		fprintf(stderr, "imsroha-rcs: ACS: version -1: the carrier refuses RCS for this SIM/device "
				"permanently; no further requests for IMSI %s\n", imsi);
		return ACS_STOPPED;
	}
	if (v == -3) {
		st->version = -3;
		st->validity = d;
		st->next_run = d > 0 ? now + d : 0;
		fprintf(stderr, "imsroha-rcs: ACS: version -3 (dormant)\n");
		return ACS_DORMANT;
	}
	/* -2 and anything else below zero: RCS is off for this client. */
	acs_config_remove(cfg, imsi);
	st->version = v;
	st->validity = d;
	st->next_run = 0;
	fprintf(stderr, "imsroha-rcs: ACS: version %d: RCS disabled by the carrier until the next start\n", v);
	return ACS_STOPPED;
}

/* ---- one run ------------------------------------------------------------ */

static void jar_update(GHashTable *jar, const struct http_response *r)
{
	for (guint i = 0; r->names && i < r->names->len; i++) {
		if (g_ascii_strcasecmp(g_ptr_array_index(r->names, i), "Set-Cookie"))
			continue;
		const char *v = g_ptr_array_index(r->values, i);
		const char *semi = strchr(v, ';');
		char *pair = semi ? g_strndup(v, (gsize)(semi - v)) : g_strdup(v);
		g_strstrip(pair);
		char *eq = strchr(pair, '=');
		if (eq && eq != pair) {
			*eq = '\0';
			g_hash_table_replace(jar, g_strdup(pair), g_strdup(eq + 1));
		}
		g_free(pair);
	}
}

static int has_set_cookie(const struct http_response *r)
{
	return http_header(r, "Set-Cookie") != NULL;
}

static char *jar_header(GHashTable *jar, GPtrArray *order)
{
	GString *s = g_string_new(NULL);
	for (guint i = 0; i < order->len; i++) {
		const char *n = g_ptr_array_index(order, i);
		const char *v = g_hash_table_lookup(jar, n);
		if (!v)
			continue;
		if (s->len)
			g_string_append(s, "; ");
		g_string_append_printf(s, "%s=%s", n, v);
	}
	return g_string_free(s, FALSE);
}

static void jar_order(GPtrArray *order, const struct http_response *r)
{
	for (guint i = 0; r->names && i < r->names->len; i++) {
		if (g_ascii_strcasecmp(g_ptr_array_index(r->names, i), "Set-Cookie"))
			continue;
		const char *v = g_ptr_array_index(r->values, i);
		const char *eq = strchr(v, '=');
		if (!eq)
			continue;
		char *n = g_strndup(v, (gsize)(eq - v));
		g_strstrip(n);
		gboolean seen = FALSE;
		for (guint j = 0; j < order->len; j++)
			if (!strcmp(g_ptr_array_index(order, j), n))
				seen = TRUE;
		if (seen)
			g_free(n);
		else
			g_ptr_array_add(order, n);
	}
}

static int64_t now_s(void)
{
	return (int64_t)time(NULL);
}

static enum acs_outcome retry_later(struct acs_state *st, const char *why)
{
	int d = acs_retry_delay(st->trial);
	st->trial++;
	st->next_run = d < 0 ? 0 : now_s() + d;
	if (d < 0)
		fprintf(stderr, "imsroha-rcs: ACS: %s; retrying at the next start\n", why);
	else
		fprintf(stderr, "imsroha-rcs: ACS: %s; retrying in %d s\n", why, d);
	return ACS_NONE;
}

static enum acs_outcome next_start(struct acs_state *st, const char *why)
{
	st->next_run = 0;
	fprintf(stderr, "imsroha-rcs: ACS: %s; retrying at the next start\n", why);
	return ACS_NONE;
}

static void log_request(const struct acs_request *r)
{
	/* The query carries IMSI, IMEI and the token: only the first line's path and the host. */
	const char *q = strchr(r->text, '?');
	const char *sp = strchr(r->text + 4, ' ');
	fprintf(stderr, "imsroha-rcs: ACS: GET %s://%s:%u%.*s%s\n", r->tls ? "https" : "http", r->host,
		r->port, (int)((q && q < sp ? q : sp) - (r->text + 4)), r->text + 4, q && q < sp ? "?..." : "");
}

static int exchange(const struct rcs_config *cfg, const struct acs_request *rq, GCancellable *cancel,
		    struct http_response *rs)
{
	log_request(rq);
	http_exchange(cfg, rq->host, rq->port, rq->tls, rq->text, ACS_TIMEOUT, cancel, rs);
	if (rs->status)
		fprintf(stderr, "imsroha-rcs: ACS: %d %s\n", rs->status, rs->reason);
	else
		fprintf(stderr, "imsroha-rcs: ACS: no answer: %s\n", rs->error);
	return rs->status;
}

enum acs_outcome acs_run(const struct rcs_config *cfg, const struct rcs_identity *id,
			 struct acs_state *st, int disable, acs_otp_fn otp_fn, void *otp_ud,
			 GCancellable *cancel)
{
	struct acs_request rq;
	struct http_response rs = { 0 };
	GHashTable *jar = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	GPtrArray *order = g_ptr_array_new_with_free_func(g_free);
	enum acs_outcome out = ACS_NONE;
	int non_ps = !cfg->assume_mobile;
	int tries_511 = 0, tries_500 = 0, tries_full = 0;
	const char *state = disable ? "-4" : NULL;

	if (st->permanent) {
		fprintf(stderr, "imsroha-rcs: ACS: IMSI %s was refused permanently (-1); not asking again\n", id->imsi);
		out = ACS_STOPPED;
		goto done;
	}

	/* Written before the first byte goes out, so a crash cannot hide a run. */
	st->last_run = now_s();
	acs_state_save(cfg, id->imsi, st);

	/* 1. HTTP: on the carrier's own network, network-based authentication. */
	if (!non_ps) {
		acs_build_request(cfg, id, st, ACS_LEG_HTTP, 0, NULL, NULL, NULL, &rq);
		int s = exchange(cfg, &rq, cancel, &rs);
		acs_request_clear(&rq);
		st->last_status = s;
		if (s == 200) {
			jar_order(order, &rs);
			jar_update(jar, &rs);
		} else if (s == 511) {
			non_ps = 1;
		} else if (s == 0) {
			out = disable ? ACS_NONE : retry_later(st, "ACS unreachable over HTTP");
			goto done;
		} else if (s == 503) {
			const char *ra = http_header(&rs, "Retry-After");
			int d = ra ? atoi(ra) : 0;
			st->next_run = now_s() + (d > 0 ? d : acs_retry_delay(0));
			out = ACS_NONE;
			goto done;
		} else {
			out = next_start(st, "unexpected answer to the HTTP request");
			goto done;
		}
		http_response_clear(&rs);
	}

https:
	/* 2. HTTPS with the parameters. The non-PS flow names the line: without
	 * an MSISDN it is not sent at all (stock would ask the user for one). */
	if (non_ps && !id->msisdn[0]) {
		out = next_start(st, "the ACS wants the MSISDN (non-PS flow) and none is known; set [rcs] msisdn=");
		goto done;
	}
	{
		char *cookie = jar_header(jar, order);
		acs_build_request(cfg, id, st, ACS_LEG_HTTPS, non_ps, cookie, NULL, state, &rq);
		g_free(cookie);
	}
	int s = exchange(cfg, &rq, cancel, &rs);
	acs_request_clear(&rq);
	st->last_status = s;

	if (disable) {
		/* Whatever came back: the carrier has been told. Only -1 still counts. */
		if (s == 200 && rs.len) {
			struct acs_xml *x = acs_xml_parse(rs.body, rs.len, NULL);
			if (x && x->has_vers && x->version == -1) {
				st->permanent = 1;
				st->version = -1;
			}
			acs_xml_free(x);
		}
		if (s == 200) {
			st->disable_sent = 1;
			fprintf(stderr, "imsroha-rcs: ACS: told the carrier RCS is disabled by the user\n");
		}
		out = ACS_STOPPED;
		goto done;
	}

	switch (s) {
	case 0:
		out = retry_later(st, "ACS unreachable over HTTPS");
		goto done;
	case 200:
		break;
	case 403:
		/* Table 6-2: invalid request; the configuration goes, version 0, next start. */
		acs_config_remove(cfg, id->imsi);
		st->version = 0;
		out = next_start(st, "403 Forbidden");
		goto done;
	case 511:
		st->token[0] = '\0';
		if (tries_511++ < 1) {
			non_ps = 1;
			http_response_clear(&rs);
			goto https;
		}
		out = next_start(st, "511 twice");
		goto done;
	case 500:
		if (tries_500++ < 1) {
			http_response_clear(&rs);
			goto https;
		}
		out = next_start(st, "500 twice");
		goto done;
	case 503: {
		const char *ra = http_header(&rs, "Retry-After");
		int d = ra ? atoi(ra) : 0;
		st->next_run = now_s() + (d > 0 ? d : acs_retry_delay(0));
		fprintf(stderr, "imsroha-rcs: ACS: busy; retrying in %lld s\n", (long long)(st->next_run - now_s()));
		out = ACS_NONE;
		goto done;
	}
	default:
		out = next_start(st, "error answer");
		goto done;
	}

	for (;;) {
		struct acs_xml *x = rs.len ? acs_xml_parse(rs.body, rs.len, NULL) : NULL;
		if (x && x->has_vers) {
			out = acs_apply_vers(cfg, id->imsi, st, x, rs.body, rs.len, now_s());
			acs_xml_free(x);
			if (out == ACS_NONE && st->rcscfg_force && tries_full++ < 1) {
				http_response_clear(&rs);
				goto https;
			}
			goto done;
		}
		acs_xml_free(x);
		if (!has_set_cookie(&rs)) {
			out = retry_later(st, "200 without a configuration or a cookie");
			goto done;
		}

		/* 3. A cookie and no configuration: the OTP comes by SMS. */
		jar_order(order, &rs);
		jar_update(jar, &rs);
		http_response_clear(&rs);
		char otp[64] = "";
		fprintf(stderr, "imsroha-rcs: ACS: waiting up to %u s for the OTP SMS (port %u)\n",
			cfg->otp_timeout, cfg->otp_port);
		if (!otp_fn || otp_fn(otp_ud, otp, sizeof(otp), cfg->otp_timeout) < 0 || !otp[0]) {
			out = retry_later(st, "no OTP SMS");
			goto done;
		}
		char *cookie = jar_header(jar, order);
		acs_build_request(cfg, id, st, ACS_LEG_OTP, 0, cookie, otp, NULL, &rq);
		g_free(cookie);
		s = exchange(cfg, &rq, cancel, &rs);
		acs_request_clear(&rq);
		st->last_status = s;
		if (s != 200) {
			out = s == 0 ? retry_later(st, "ACS unreachable with the OTP") : next_start(st, "OTP refused");
			goto done;
		}
		/* A second cookie-only answer would loop: only once. */
		if (!rs.len) {
			out = retry_later(st, "empty answer to the OTP");
			goto done;
		}
		x = acs_xml_parse(rs.body, rs.len, NULL);
		int vers = x && x->has_vers;
		acs_xml_free(x);
		if (!vers) {
			out = retry_later(st, "no configuration after the OTP");
			goto done;
		}
	}

done:
	http_response_clear(&rs);
	g_hash_table_destroy(jar);
	g_ptr_array_free(order, TRUE);
	acs_state_save(cfg, id->imsi, st);
	return out;
}
