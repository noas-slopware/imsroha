// SPDX-License-Identifier: GPL-3.0-only
/*
 * The RCS SIP user agent: a registration of its own, next to imsroha's
 * VoLTE one and independent of it (TTAK.KO-06.0410/R9 A.3.1), over TLS (or
 * TCP when the ACS says SIPoTCP) on the internet PDN.
 *
 * Everything comes from the ACS configuration: the identities, the P-CSCF
 * (LBO_P-CSCF_Address, never the PCO), Digest credentials, the transport.
 * One connection carries everything: our requests, and the network's
 * requests to us (we never listen).
 */
#include "sipua.h"
#include "rcsd.h"
#include "net.h"

#include <arpa/nameser.h>
#include <errno.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "imei.h"

#define SIP_TIMER_F 32   /* s: RFC 3261 64*T1 */
#define CONNECT_TIMEOUT 20

struct sipua_tx {
	struct sipua *ua;
	char branch[48];
	char method[16];
	sipua_resp_cb cb;
	void *ud;
	guint timer;
};

struct sipua {
	struct rcsd *r;
	/* from the ACS */
	char impi[160], impu[192], domain[128];
	char auth_type[16], realm[128], user[160], pwd[128];
	char host[256];
	uint16_t port;      /* 0: resolve */
	int tls, msrp_tls;
	unsigned timer_idle;
	unsigned retry_base, retry_max;
	char instance[96];
	char contact_user[64];
	char ua_string[256];

	/* the connection */
	GIOStream *conn;
	GCancellable *cancel;
	GByteArray *rx;
	char buf[16384];
	char local_ip[64];
	uint16_t local_port;
	int v6;
	int connecting;

	/* registration */
	int registered;
	struct sipdlg reg;
	unsigned expires;
	char nonce[256], opaque[256], algorithm[32], qop[16];
	unsigned nc;
	int auth_tries;
	char service_route[1024];
	char assoc[256];
	guint reg_timer, retry_timer;
	int retry_n;
	int stopped;
	int dispatching;    /* inside a callback from on_read */
	int presence;       /* PUBLISH our capabilities, anonymous fetch for others' */
	struct sipdlg pub;
	char etag[128];
	guint pub_timer;
	int pub_retry;
	unsigned granted;   /* the registration's expiry, the PUBLISH's too (R9 6.5.1) */
	int dead;           /* stopped while dispatching: on_read frees it */

	GList *txs;
};

int sipua_registered(const struct sipua *ua) { return ua && ua->registered; }
const char *sipua_impu(const struct sipua *ua) { return ua->impu; }
const char *sipua_local_ip(const struct sipua *ua) { return ua->local_ip; }
int sipua_local_v6(const struct sipua *ua) { return ua->v6; }
int sipua_msrp_tls(const struct sipua *ua) { return ua->msrp_tls; }
int sipua_presence(const struct sipua *ua) { return ua->presence; }
unsigned sipua_timer_idle(const struct sipua *ua) { return ua->timer_idle; }

int sipua_e164(const struct sipua *ua, const char *number, char *out, size_t size)
{
	char d[40];
	size_t n = 0;
	int plus = 0;
	for (const char *p = number; *p && n + 1 < sizeof(d); p++) {
		if (*p == '+' && !n)
			plus = 1;
		else if (g_ascii_isdigit(*p))
			d[n++] = *p;
		else if (!strchr(" -().", *p))
			return -EINVAL;
	}
	d[n] = '\0';
	if (n < 3)
		return -EINVAL;
	const char *cc = ua->r->cfg.base.car.country_code;
	if (plus)
		snprintf(out, size, "+%s", d);
	else if (d[0] == '0' && cc[0])
		snprintf(out, size, "+%s%s", cc, d + 1);
	else
		return -EINVAL;
	return 0;
}

/* ---- digest -------------------------------------------------------------- */

static void md5_hex(const char *s, char out[33])
{
	char *h = g_compute_checksum_for_string(G_CHECKSUM_MD5, s, -1);
	snprintf(out, 33, "%s", h);
	g_free(h);
}

static void auth_header(struct sipua *ua, GString *m, const char *method, const char *uri)
{
	if (!ua->nonce[0]) {
		/* The first REGISTER carries an empty one (R9 6.4.3's example). */
		g_string_append_printf(m, "Authorization: Digest username=\"%s\",realm=\"%s\",uri=\"%s\",nonce=\"\",response=\"\"\r\n",
				       ua->user, ua->realm, uri);
		return;
	}
	char ha1[33], ha2[33], resp[33], cnonce[17], nc[9];
	char *s = g_strdup_printf("%s:%s:%s", ua->user, ua->realm, ua->pwd);
	md5_hex(s, ha1);
	g_free(s);
	s = g_strdup_printf("%s:%s", method, uri);
	md5_hex(s, ha2);
	g_free(s);
	if (ua->qop[0]) {
		sip_random(cnonce, 16);
		snprintf(nc, sizeof(nc), "%08x", ++ua->nc);
		s = g_strdup_printf("%s:%s:%s:%s:auth:%s", ha1, ua->nonce, nc, cnonce, ha2);
	} else {
		s = g_strdup_printf("%s:%s:%s", ha1, ua->nonce, ha2);
	}
	md5_hex(s, resp);
	g_free(s);
	g_string_append_printf(m, "Authorization: Digest username=\"%s\",realm=\"%s\",uri=\"%s\",nonce=\"%s\",response=\"%s\",algorithm=MD5",
			       ua->user, ua->realm, uri, ua->nonce, resp);
	if (ua->qop[0])
		g_string_append_printf(m, ",nc=%s,qop=auth,cnonce=\"%s\"", nc, cnonce);
	if (ua->opaque[0])
		g_string_append_printf(m, ",opaque=\"%s\"", ua->opaque);
	g_string_append(m, "\r\n");
}

/* ---- transactions and the wire ------------------------------------------ */

static void tx_free(struct sipua_tx *t)
{
	if (t->timer)
		g_source_remove(t->timer);
	g_free(t);
}

static gboolean on_tx_timeout(gpointer p)
{
	struct sipua_tx *t = p;
	struct sipua *ua = t->ua;
	t->timer = 0;
	ua->txs = g_list_remove(ua->txs, t);
	fprintf(stderr, "imsroha-rcs: SIP %s timed out\n", t->method);
	if (t->cb)
		t->cb(ua, NULL, t->ud);
	tx_free(t);
	return G_SOURCE_REMOVE;
}

void sipua_forget(struct sipua *ua, void *ud)
{
	if (!ua)
		return;
	for (GList *l = ua->txs; l; l = l->next) {
		struct sipua_tx *t = l->data;
		if (t->ud == ud)
			t->cb = NULL;
	}
}

static int wire(struct sipua *ua, const char *data, size_t len)
{
	GError *e = NULL;
	if (!ua->conn)
		return -ENOTCONN;
	if (!g_output_stream_write_all(g_io_stream_get_output_stream(ua->conn), data, len, NULL, NULL, &e)) {
		fprintf(stderr, "imsroha-rcs: SIP send: %s\n", e->message);
		g_error_free(e);
		return -EIO;
	}
	return 0;
}

static void via(struct sipua *ua, GString *m, const char *branch)
{
	g_string_append_printf(m, "Via: SIP/2.0/%s %s%s%s:%u;branch=%s\r\n", ua->tls ? "TLS" : "TCP",
			       ua->v6 ? "[" : "", ua->local_ip, ua->v6 ? "]" : "", ua->local_port, branch);
}

static void contact(struct sipua *ua, GString *m)
{
	g_string_append_printf(m, "Contact: <sip:%s@%s%s%s:%u;transport=%s>", ua->contact_user,
			       ua->v6 ? "[" : "", ua->local_ip, ua->v6 ? "]" : "", ua->local_port,
			       ua->tls ? "tls" : "tcp");
	if (ua->instance[0])
		g_string_append_printf(m, ";+sip.instance=\"%s\"", ua->instance);
	g_string_append(m, ";+g.3gpp.icsi-ref=\"" RCS_ICSI_CHAT "\"");
	/* One iari-ref with every application, comma separated, as R9's examples. */
	const char *dp = ua->presence ? RCS_IARI_DP : NULL;
	const char *ft = ua->r->ft.enabled ? RCS_IARI_FTHTTP : NULL;
	if (dp || ft)
		g_string_append_printf(m, ";+g.3gpp.iari-ref=\"%s%s%s\"", dp ? dp : "", dp && ft ? "," : "",
				       ft ? ft : "");
	g_string_append(m, "\r\n");
}

int sipua_send(struct sipua *ua, struct sipdlg *dlg, const char *method, const char *ruri,
	       const char *extra, const char *ctype, const char *body, size_t blen,
	       sipua_resp_cb cb, void *ud)
{
	if (!ua->conn)
		return -ENOTCONN;
	char branch[48];
	snprintf(branch, sizeof(branch), "z9hG4bK");
	sip_random(branch + 7, 24);
	int ack = !strcmp(method, "ACK");
	if (!dlg->call_id[0]) {
		char id[33];
		sip_random(id, 32);
		snprintf(dlg->call_id, sizeof(dlg->call_id), "%s", id);
		sip_random(dlg->local_tag, 12);
		dlg->cseq = 0;
	}
	if (!ack)
		dlg->cseq++;

	GString *m = g_string_new(NULL);
	g_string_append_printf(m, "%s %s SIP/2.0\r\n", method, ruri);
	via(ua, m, branch);
	g_string_append(m, "Max-Forwards: 70\r\n");
	const char *route = dlg->route[0] ? dlg->route : ua->service_route;
	if (route[0] && strcmp(method, "REGISTER"))
		g_string_append_printf(m, "Route: %s\r\n", route);
	if (dlg->anonymous)
		g_string_append_printf(m, "From: \"Anonymous\"<sip:anonymous@anonymous.invalid>;tag=%s\r\n", dlg->local_tag);
	else
		g_string_append_printf(m, "From: <%s>;tag=%s\r\n", ua->impu, dlg->local_tag);
	g_string_append_printf(m, "To: %s%s%s\r\n", dlg->remote_uri, dlg->remote_tag[0] ? ";tag=" : "",
			       dlg->remote_tag);
	g_string_append_printf(m, "Call-ID: %s\r\n", dlg->call_id);
	g_string_append_printf(m, "CSeq: %u %s\r\n", dlg->cseq, method);
	if (strcmp(method, "BYE") && !ack)
		contact(ua, m);
	if (!strcmp(method, "REGISTER")) {
		g_string_append_printf(m, "Expires: %u\r\n", ua->expires);
		g_string_append(m, "Supported: path\r\n");
		char uri[160];
		snprintf(uri, sizeof(uri), "sip:%s", ua->domain);
		auth_header(ua, m, method, uri);
	} else if (!ack && strcmp(method, "BYE") && !dlg->anonymous) {
		g_string_append_printf(m, "P-Preferred-Identity: <%s>\r\n", ua->impu);
	}
	if (!ack)
		g_string_append(m, "Allow: " RCS_ALLOW "\r\n");
	g_string_append_printf(m, "User-Agent: %s\r\n", ua->ua_string);
	if (extra)
		g_string_append(m, extra);
	if (ctype && body) {
		g_string_append_printf(m, "Content-Type: %s\r\n", ctype);
		g_string_append_printf(m, "Content-Length: %zu\r\n\r\n", blen);
		g_string_append_len(m, body, (gssize)blen);
	} else {
		g_string_append(m, "Content-Length: 0\r\n\r\n");
	}
	int r = wire(ua, m->str, m->len);
	g_string_free(m, TRUE);
	if (r < 0 || ack)
		return r;

	struct sipua_tx *t = g_new0(struct sipua_tx, 1);
	t->ua = ua;
	snprintf(t->branch, sizeof(t->branch), "%s", branch);
	snprintf(t->method, sizeof(t->method), "%s", method);
	t->cb = cb;
	t->ud = ud;
	/* INVITE: Timer B, the answer may take the far end's ringing time; 64*T1 too. */
	t->timer = g_timeout_add_seconds(SIP_TIMER_F, on_tx_timeout, t);
	ua->txs = g_list_append(ua->txs, t);
	return 0;
}

void sipua_respond(struct sipua *ua, const struct sipmsg *req, int code, const char *reason,
		   const char *to_tag, const char *extra, const char *ctype, const char *body)
{
	GString *m = g_string_new(NULL);
	g_string_append_printf(m, "SIP/2.0 %d %s\r\n", code, reason);
	for (guint i = 0; i < req->names->len; i++)
		if (!g_ascii_strcasecmp(g_ptr_array_index(req->names, i), "Via"))
			g_string_append_printf(m, "Via: %s\r\n", (char *)g_ptr_array_index(req->values, i));
	const char *v;
	if ((v = sipmsg_header(req, "From")))
		g_string_append_printf(m, "From: %s\r\n", v);
	if ((v = sipmsg_header(req, "To"))) {
		char t[96];
		if (to_tag && sip_param(v, "tag", t, sizeof(t)) < 0 && code > 100)
			g_string_append_printf(m, "To: %s;tag=%s\r\n", v, to_tag);
		else
			g_string_append_printf(m, "To: %s\r\n", v);
	}
	if ((v = sipmsg_header(req, "Call-ID")))
		g_string_append_printf(m, "Call-ID: %s\r\n", v);
	if ((v = sipmsg_header(req, "CSeq")))
		g_string_append_printf(m, "CSeq: %s\r\n", v);
	for (guint i = 0; i < req->names->len; i++)
		if (code >= 200 && code < 300 && !g_ascii_strcasecmp(g_ptr_array_index(req->names, i), "Record-Route"))
			g_string_append_printf(m, "Record-Route: %s\r\n", (char *)g_ptr_array_index(req->values, i));
	if (code >= 200 && code < 300 && (!strcmp(req->method, "INVITE") || !strcmp(req->method, "OPTIONS")))
		contact(ua, m);
	g_string_append_printf(m, "User-Agent: %s\r\n", ua->ua_string);
	if (extra)
		g_string_append(m, extra);
	if (ctype && body) {
		size_t bl = strlen(body);
		g_string_append_printf(m, "Content-Type: %s\r\nContent-Length: %zu\r\n\r\n%s", ctype, bl, body);
	} else {
		g_string_append(m, "Content-Length: 0\r\n\r\n");
	}
	wire(ua, m->str, m->len);
	g_string_free(m, TRUE);
}

/* ---- registration -------------------------------------------------------- */

static void reg_send(struct sipua *ua);
static void connect_start(struct sipua *ua);
static void publish(struct sipua *ua, unsigned expires);
static void conn_lost(struct sipua *ua, const char *why);

static gboolean on_retry(gpointer p)
{
	struct sipua *ua = p;
	ua->retry_timer = 0;
	if (ua->conn)
		reg_send(ua);
	else
		connect_start(ua);
	return G_SOURCE_REMOVE;
}

static void schedule_retry(struct sipua *ua, unsigned after)
{
	if (ua->stopped || ua->retry_timer)
		return;
	if (!after) {
		/* TS 24.229 / RFC 5626 4.5: base * 2^n, capped (RegRetryBaseTime/MaxTime). */
		unsigned d = ua->retry_base;
		for (int i = 0; i < ua->retry_n && d < ua->retry_max; i++)
			d *= 2;
		after = MIN(d, ua->retry_max);
	}
	ua->retry_n++;
	fprintf(stderr, "imsroha-rcs: registering again in %u s\n", after);
	ua->retry_timer = g_timeout_add_seconds(after, on_retry, ua);
}

static gboolean on_reg_refresh(gpointer p)
{
	struct sipua *ua = p;
	ua->reg_timer = 0;
	reg_send(ua);
	return G_SOURCE_REMOVE;
}

static void set_unregistered(struct sipua *ua)
{
	if (ua->registered) {
		ua->registered = 0;
		chat_on_unregistered(ua->r);
	}
	if (ua->reg_timer)
		g_source_remove(ua->reg_timer);
	ua->reg_timer = 0;
	if (ua->pub_timer)
		g_source_remove(ua->pub_timer);
	ua->pub_timer = 0;
}

static unsigned granted_expires(struct sipua *ua, const struct sipmsg *m)
{
	char **cs = sipmsg_header_all(m, "Contact");
	unsigned e = 0;
	char needle[96];
	snprintf(needle, sizeof(needle), "@%s%s%s:%u", ua->v6 ? "[" : "", ua->local_ip, ua->v6 ? "]" : "",
		 ua->local_port);
	for (int i = 0; cs[i] && !e; i++) {
		char v[16];
		if (strstr(cs[i], needle) && sip_param(cs[i], "expires", v, sizeof(v)) == 0)
			e = (unsigned)strtoul(v, NULL, 10);
	}
	g_strfreev(cs);
	const char *h = sipmsg_header(m, "Expires");
	if (!e && h)
		e = (unsigned)strtoul(h, NULL, 10);
	return e ? e : ua->expires;
}

static void on_reg_resp(struct sipua *ua, const struct sipmsg *m, void *ud)
{
	(void)ud;
	struct rcsd *r = ua->r;
	if (!m) {
		set_unregistered(ua);
		rcsd_set_state(r, RCSD_REGISTERING);
		/* R9 A.5 c: every P-CSCF timing out sends us back to the ACS, after a
		 * wait; once per configuration, then only the back-off. */
		if (ua->retry_n >= 3 && !r->pcscf_reconfigured) {
			r->pcscf_reconfigured = 1;
			fprintf(stderr, "imsroha-rcs: the P-CSCF does not answer; asking the ACS again\n");
			rcsd_ua_stop(r);
			rcsd_reconfigure(r);
			return;
		}
		schedule_retry(ua, 0);
		return;
	}
	if (m->code < 200)
		return;
	if (m->code == 401 && ua->auth_tries++ < 2) {
		char **ch = sipmsg_header_all(m, "WWW-Authenticate");
		for (int i = 0; ch[i]; i++) {
			if (g_ascii_strncasecmp(ch[i], "Digest", 6))
				continue;
			sip_auth_param(ch[i], "nonce", ua->nonce, sizeof(ua->nonce));
			if (sip_auth_param(ch[i], "opaque", ua->opaque, sizeof(ua->opaque)) < 0)
				ua->opaque[0] = '\0';
			char qop[64] = "";
			sip_auth_param(ch[i], "qop", qop, sizeof(qop));
			snprintf(ua->qop, sizeof(ua->qop), "%s", strstr(qop, "auth") ? "auth" : "");
			char realm[128];
			if (sip_auth_param(ch[i], "realm", realm, sizeof(realm)) == 0 && !ua->realm[0])
				snprintf(ua->realm, sizeof(ua->realm), "%s", realm);
			if (sip_auth_param(ch[i], "algorithm", ua->algorithm, sizeof(ua->algorithm)) < 0)
				snprintf(ua->algorithm, sizeof(ua->algorithm), "MD5");
			ua->nc = 0;
			break;
		}
		g_strfreev(ch);
		if (!g_ascii_strncasecmp(ua->algorithm, "AKA", 3)) {
			fprintf(stderr, "imsroha-rcs: the registrar wants %s; only Digest is implemented\n", ua->algorithm);
			set_unregistered(ua);
			rcsd_set_state(r, RCSD_UNREGISTERED);
			return;
		}
		reg_send(ua);
		return;
	}
	ua->auth_tries = 0;
	if (m->code >= 200 && m->code < 300) {
		if (ua->expires == 0)
			return; /* our de-registration */
		unsigned e = granted_expires(ua, m);
		ua->granted = e;
		char **sr = sipmsg_header_all(m, "Service-Route");
		GString *s = g_string_new(NULL);
		for (int i = 0; sr[i]; i++)
			g_string_append_printf(s, "%s%s", s->len ? ", " : "", sr[i]);
		g_strfreev(sr);
		snprintf(ua->service_route, sizeof(ua->service_route), "%s", s->str);
		g_string_free(s, TRUE);
		const char *pau = sipmsg_header(m, "P-Associated-URI");
		if (pau)
			snprintf(ua->assoc, sizeof(ua->assoc), "%s", pau);
		const char *ai = sipmsg_header(m, "Authentication-Info");
		char nn[256];
		if (ai && sip_auth_param(ai, "nextnonce", nn, sizeof(nn)) == 0) {
			snprintf(ua->nonce, sizeof(ua->nonce), "%s", nn);
			ua->nc = 0;
		}
		r->forbidden = 0;
		r->pcscf_reconfigured = 0;
		ua->retry_n = 0;
		unsigned refresh = e > 1200 ? e - 600 : e / 2;
		if (ua->reg_timer)
			g_source_remove(ua->reg_timer);
		ua->reg_timer = g_timeout_add_seconds(refresh ? refresh : 1, on_reg_refresh, ua);
		fprintf(stderr, "imsroha-rcs: registered as %s for %u s\n", ua->impu, e);
		int was = ua->registered;
		ua->registered = 1;
		rcsd_set_state(r, RCSD_REGISTERED);
		if (!was) {
			chat_on_registered(r);
			if (ua->presence) {
				ua->etag[0] = '\0';
				publish(ua, e);
			}
		}
		return;
	}
	set_unregistered(ua);
	fprintf(stderr, "imsroha-rcs: REGISTER: %d %s\n", m->code, m->reason);
	if (m->code == 403) {
		/* R9 A.5 b: the first 403 sends us to the ACS, the second stops RCS until restart. */
		if (++r->forbidden >= 2) {
			fprintf(stderr, "imsroha-rcs: second 403: no RCS until imsroha-rcs restarts\n");
			rcsd_ua_stop(r);
			rcsd_halt(r);
		} else {
			rcsd_ua_stop(r);
			rcsd_reconfigure(r);
		}
		return;
	}
	if (m->code == 423) {
		const char *me = sipmsg_header(m, "Min-Expires");
		if (me)
			ua->expires = (unsigned)strtoul(me, NULL, 10);
		reg_send(ua);
		return;
	}
	const char *ra = sipmsg_header(m, "Retry-After");
	rcsd_set_state(r, RCSD_REGISTERING);
	schedule_retry(ua, ra ? (unsigned)strtoul(ra, NULL, 10) : 0);
}

static void reg_send(struct sipua *ua)
{
	char ruri[160];
	snprintf(ruri, sizeof(ruri), "sip:%s", ua->domain);
	snprintf(ua->reg.remote_uri, sizeof(ua->reg.remote_uri), "<%s>", ua->impu);
	if (!ua->registered)
		rcsd_set_state(ua->r, RCSD_REGISTERING);
	if (sipua_send(ua, &ua->reg, "REGISTER", ruri, NULL, NULL, NULL, 0, on_reg_resp, NULL) < 0)
		conn_lost(ua, "cannot send REGISTER");
}


/* ---- presence: our capabilities (R9 6.5.1) -------------------------------- */

static void publish(struct sipua *ua, unsigned expires);

static gboolean on_pub_timer(gpointer p)
{
	struct sipua *ua = p;
	ua->pub_timer = 0;
	if (ua->registered)
		publish(ua, ua->granted);
	return G_SOURCE_REMOVE;
}

static void pub_later(struct sipua *ua, unsigned s)
{
	if (ua->pub_timer)
		g_source_remove(ua->pub_timer);
	ua->pub_timer = g_timeout_add_seconds(s ? s : 1, on_pub_timer, ua);
}

static void on_pub_resp(struct sipua *ua, const struct sipmsg *m, void *ud)
{
	(void)ud;
	if (!ua->registered)
		return;
	int code = m ? m->code : 708;
	if (code >= 200 && code < 300) {
		const char *et = sipmsg_header(m, "SIP-ETag");
		if (et)
			snprintf(ua->etag, sizeof(ua->etag), "%s", et);
		const char *ex = sipmsg_header(m, "Expires");
		unsigned e = ex ? (unsigned)strtoul(ex, NULL, 10) : ua->expires;
		ua->pub_retry = 0;
		fprintf(stderr, "imsroha-rcs: capabilities published for %u s\n", e);
		pub_later(ua, e > 1200 ? e - 600 : e / 2);
		return;
	}
	fprintf(stderr, "imsroha-rcs: PUBLISH: %d %s\n", code, m ? m->reason : "timed out");
	if (code == 412)
		ua->etag[0] = '\0';
	if (code == 423 && m && sipmsg_header(m, "Min-Expires")) {
		publish(ua, (unsigned)strtoul(sipmsg_header(m, "Min-Expires"), NULL, 10));
		return;
	}
	/* R9 table 6-3: case B retries once at once, then like A; A every 1200 s;
	 * C after Retry-After or 120, 240, 480, 960, 3600 s. */
	int b = code == 400 || code == 403 || code == 412 || code == 423 || code == 489;
	int c = code == 408 || code == 500 || code == 503;
	unsigned after = 1200;
	if (b && ua->pub_retry == 0) {
		after = 1;
	} else if (c) {
		const char *ra = m ? sipmsg_header(m, "Retry-After") : NULL;
		static const unsigned ladder[] = { 120, 240, 480, 960, 3600 };
		after = ra ? (unsigned)strtoul(ra, NULL, 10)
			   : ladder[MIN(ua->pub_retry, (int)G_N_ELEMENTS(ladder) - 1)];
	}
	ua->pub_retry++;
	pub_later(ua, after);
}

static void publish(struct sipua *ua, unsigned expires)
{
	char id1[11], id2[11], id3[11];
	sip_random(id1, 10);
	sip_random(id2, 10);
	sip_random(id3, 10);
	char *body = NULL;
	if (expires) {
		GString *b = g_string_new(NULL);
		g_string_append_printf(b,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
			"<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" xmlns:op=\"urn:oma:xml:prs:pidf:oma-pres\" entity=\"%s\">\r\n"
			" <tuple id=\"SessionModeMessaging%s\"><status><basic>open</basic></status>\r\n"
			"  <op:service-description><op:service-id>org.openmobilealliance:ChatSession</op:service-id>"
			"<op:version>2.0</op:version><op:description>Session Mode Messaging</op:description></op:service-description>\r\n"
			"  <contact>%s</contact></tuple>\r\n", ua->impu, id1, ua->impu);
		/* R9 table 6-4: File Transfer via HTTP, service-id File-Transfer-HTTP, version 1.0. */
		if (ua->r->ft.enabled)
			g_string_append_printf(b,
				" <tuple id=\"FileTransferHTTP%s\"><status><basic>open</basic></status>\r\n"
				"  <op:service-description><op:service-id>org.openmobilealliance:File-Transfer-HTTP</op:service-id>"
				"<op:version>1.0</op:version><op:description>File Transfer HTTP</op:description></op:service-description>\r\n"
				"  <contact>%s</contact></tuple>\r\n", id3, ua->impu);
		g_string_append_printf(b,
			" <tuple id=\"DiscoveryPresence%s\"><status><basic>open</basic></status>\r\n"
			"  <op:service-description><op:service-id>org.3gpp.urn:urn-7:3gpp-application.ims.iari.rcse.dp</op:service-id>"
			"<op:version>1.0</op:version><op:description>DiscoveryPresence</op:description></op:service-description>\r\n"
			"  <contact>%s</contact></tuple>\r\n"
			"</presence>\r\n", id2, ua->impu);
		body = g_string_free(b, FALSE);
	}
	char extra[256];
	snprintf(extra, sizeof(extra), "Event: presence\r\nExpires: %u\r\n%s%s%s", expires,
		 ua->etag[0] ? "SIP-If-Match: " : "", ua->etag, ua->etag[0] ? "\r\n" : "");
	snprintf(ua->pub.remote_uri, sizeof(ua->pub.remote_uri), "<%s>", ua->impu);
	sipua_send(ua, &ua->pub, "PUBLISH", ua->impu, extra, body ? "application/pidf+xml" : NULL, body,
		   body ? strlen(body) : 0, expires ? on_pub_resp : NULL, NULL);
	g_free(body);
}

/* ---- incoming ------------------------------------------------------------ */

static void on_request(struct sipua *ua, const struct sipmsg *m)
{
	if (!strcmp(m->method, "OPTIONS")) {
		/* Capability discovery: what we registered. */
		sipua_respond(ua, m, 200, "OK", "opt", "Accept: application/sdp\r\nAllow: " RCS_ALLOW "\r\n",
			      NULL, NULL);
	} else if (!strcmp(m->method, "NOTIFY")) {
		if (chat_on_notify(ua->r, ua, m) < 0)
			sipua_respond(ua, m, 200, "OK", NULL, NULL, NULL, NULL);
	} else if (!strcmp(m->method, "INVITE") || !strcmp(m->method, "ACK") || !strcmp(m->method, "BYE") ||
		   !strcmp(m->method, "CANCEL") || !strcmp(m->method, "MESSAGE") || !strcmp(m->method, "UPDATE")) {
		chat_on_request(ua->r, ua, m);
	} else {
		sipua_respond(ua, m, 405, "Method Not Allowed", NULL, "Allow: " RCS_ALLOW "\r\n", NULL, NULL);
	}
}

static void on_response(struct sipua *ua, const struct sipmsg *m)
{
	const char *v = sipmsg_header(m, "Via");
	char branch[64];
	if (!v || sip_param(v, "branch", branch, sizeof(branch)) < 0)
		return;
	for (GList *l = ua->txs; l; l = l->next) {
		struct sipua_tx *t = l->data;
		if (strcmp(t->branch, branch))
			continue;
		if (m->code >= 200) {
			ua->txs = g_list_delete_link(ua->txs, l);
			if (t->cb)
				t->cb(ua, m, t->ud);
			tx_free(t);
		} else if (t->cb && !strcmp(t->method, "INVITE")) {
			t->cb(ua, m, t->ud);
		}
		return;
	}
}

static void read_more(struct sipua *ua);
static void ua_free(struct sipua *ua);

static void on_read(GObject *src, GAsyncResult *res, gpointer p)
{
	GError *e = NULL;
	gssize n = g_input_stream_read_finish(G_INPUT_STREAM(src), res, &e);
	if (n < 0 && g_error_matches(e, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free(e);
		return; /* ua may be gone */
	}
	struct sipua *ua = p;
	if (n <= 0) {
		conn_lost(ua, e ? e->message : "closed by the P-CSCF");
		g_clear_error(&e);
		return;
	}
	g_byte_array_append(ua->rx, (const guint8 *)ua->buf, (guint)n);
	for (;;) {
		struct sipmsg *m = NULL;
		gssize used = sipmsg_frame((const char *)ua->rx->data, ua->rx->len, &m);
		if (used < 0) {
			conn_lost(ua, "unparsable SIP");
			return;
		}
		if (used == 0)
			break;
		g_byte_array_remove_range(ua->rx, 0, (guint)used);
		if (!m)
			continue;
		ua->dispatching++;
		if (m->request)
			on_request(ua, m);
		else
			on_response(ua, m);
		ua->dispatching--;
		sipmsg_free(m);
		if (ua->dead) {
			ua_free(ua);
			return;
		}
		if (!ua->conn)
			return;
	}
	read_more(ua);
}

static void read_more(struct sipua *ua)
{
	g_input_stream_read_async(g_io_stream_get_input_stream(ua->conn), ua->buf, sizeof(ua->buf),
				  G_PRIORITY_DEFAULT, ua->cancel, on_read, ua);
}

static void drop_conn(struct sipua *ua)
{
	if (ua->cancel) {
		g_cancellable_cancel(ua->cancel);
		g_object_unref(ua->cancel);
		ua->cancel = NULL;
	}
	if (ua->conn) {
		g_io_stream_close(ua->conn, NULL, NULL);
		g_object_unref(ua->conn);
		ua->conn = NULL;
	}
	g_byte_array_set_size(ua->rx, 0);
	/* Every open transaction fails now. */
	GList *txs = ua->txs;
	ua->txs = NULL;
	for (GList *l = txs; l; l = l->next) {
		struct sipua_tx *t = l->data;
		if (t->cb)
			t->cb(ua, NULL, t->ud);
		tx_free(t);
	}
	g_list_free(txs);
}

static void conn_lost(struct sipua *ua, const char *why)
{
	fprintf(stderr, "imsroha-rcs: SIP connection lost: %s\n", why);
	set_unregistered(ua);
	/* The registration's callback would re-register; this path reconnects instead. */
	for (GList *l = ua->txs; l; l = l->next) {
		struct sipua_tx *t = l->data;
		if (t->cb == on_reg_resp)
			t->cb = NULL;
	}
	drop_conn(ua);
	ua->nonce[0] = '\0';
	ua->reg.call_id[0] = '\0';
	if (!ua->stopped) {
		rcsd_set_state(ua->r, RCSD_REGISTERING);
		schedule_retry(ua, 0);
	}
}

/* ---- connecting: NAPTR, SRV, then the name ------------------------------- */

struct target {
	char host[256];
	uint16_t port;
};

static int naptr(const char *name, int tls, char *repl, size_t size)
{
	unsigned char ans[4096];
	int n = res_query(name, ns_c_in, ns_t_naptr, ans, sizeof(ans));
	if (n < (int)sizeof(HEADER))
		return -ENOENT;
	HEADER *h = (HEADER *)ans;
	const unsigned char *p = ans + sizeof(HEADER), *end = ans + n;
	char tmp[NS_MAXDNAME];
	for (int i = 0; i < ntohs(h->qdcount); i++) {
		int l = dn_expand(ans, end, p, tmp, sizeof(tmp));
		if (l < 0)
			return -EBADMSG;
		p += l + 4;
	}
	int best = 65536 * 2;
	for (int i = 0; i < ntohs(h->ancount) && p < end; i++) {
		int l = dn_expand(ans, end, p, tmp, sizeof(tmp));
		if (l < 0 || p + l + 10 > end)
			return -EBADMSG;
		p += l;
		unsigned type = (unsigned)(p[0] << 8 | p[1]);
		unsigned rdlen = (unsigned)(p[8] << 8 | p[9]);
		p += 10;
		const unsigned char *rd = p;
		p += rdlen;
		if (type != ns_t_naptr || rd + 4 > end)
			continue;
		int order = rd[0] << 8 | rd[1], pref = rd[2] << 8 | rd[3];
		const unsigned char *q = rd + 4;
		char fields[3][64];
		for (int f = 0; f < 3; f++) {
			unsigned fl = *q++;
			snprintf(fields[f], sizeof(fields[f]), "%.*s", (int)MIN(fl, 63u), q);
			q += fl;
		}
		char r2[NS_MAXDNAME];
		if (dn_expand(ans, end, q, r2, sizeof(r2)) < 0)
			continue;
		const char *svc = tls ? "SIPS+D2T" : "SIP+D2T";
		if (g_ascii_strcasecmp(fields[1], svc) || (!strchr(fields[0], 's') && !strchr(fields[0], 'S')))
			continue;
		/* a replacement that does not fit is skipped, not cut short */
		if (order * 65536 + pref < best && strlen(r2) < size) {
			best = order * 65536 + pref;
			g_strlcpy(repl, r2, size);
		}
	}
	return best < 65536 * 2 ? 0 : -ENOENT;
}

static int srv(const char *name, struct target *t)
{
	GResolver *res = g_resolver_get_default();
	GList *recs = g_resolver_lookup_records(res, name, G_RESOLVER_RECORD_SRV, NULL, NULL);
	g_object_unref(res);
	if (!recs)
		return -ENOENT;
	guint16 bp = 65535, port = 0;
	const char *bt = NULL;
	for (GList *l = recs; l; l = l->next) {
		guint16 prio, weight, p;
		const char *target;
		g_variant_get(l->data, "(qqq&s)", &prio, &weight, &p, &target);
		if (prio < bp || !bt) {
			bp = prio;
			bt = target;
			port = p;
		}
	}
	snprintf(t->host, sizeof(t->host), "%s", bt);
	t->port = port;
	g_list_free_full(recs, (GDestroyNotify)g_variant_unref);
	return 0;
}

struct conn_job {
	struct sipua *ua;
	const struct rcs_config *cfg;
	char host[256];
	uint16_t port;
	int tls;
	uint16_t default_port;
};

static void conn_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)src;
	struct conn_job *j = data;
	struct target t = { .port = j->port };
	snprintf(t.host, sizeof(t.host), "%s", j->host);
	if (!j->port) {
		char repl[256];
		char name[300];
		if (naptr(j->host, j->tls, repl, sizeof(repl)) == 0 && srv(repl, &t) == 0) {
			fprintf(stderr, "imsroha-rcs: %s: NAPTR %s, SRV %s:%u\n", j->host, repl, t.host, t.port);
		} else {
			snprintf(name, sizeof(name), "%s.%s", j->tls ? "_sips._tcp" : "_sip._tcp", j->host);
			if (srv(name, &t) == 0) {
				fprintf(stderr, "imsroha-rcs: %s: SRV %s:%u\n", name, t.host, t.port);
			} else {
				snprintf(t.host, sizeof(t.host), "%s", j->host);
				t.port = j->default_port;
			}
		}
	}
	GError *e = NULL;
	fprintf(stderr, "imsroha-rcs: connecting to the P-CSCF %s:%u over %s\n", t.host, t.port, j->tls ? "TLS" : "TCP");
	GIOStream *s = rcs_net_connect(j->cfg, t.host, t.port, j->tls, CONNECT_TIMEOUT, cancel, &e);
	if (s)
		g_task_return_pointer(task, s, g_object_unref);
	else
		g_task_return_error(task, e);
}

static void on_connected(GObject *src, GAsyncResult *res, gpointer p)
{
	(void)src;
	GError *e = NULL;
	GIOStream *s = g_task_propagate_pointer(G_TASK(res), &e);
	if (!s && g_error_matches(e, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_error_free(e);
		return;
	}
	struct sipua *ua = p;
	ua->connecting = 0;
	if (!s) {
		fprintf(stderr, "imsroha-rcs: P-CSCF: %s\n", e->message);
		g_error_free(e);
		rcsd_set_state(ua->r, RCSD_REGISTERING);
		if (ua->retry_n >= 3 && !ua->r->pcscf_reconfigured) {
			struct rcsd *r = ua->r; /* ua is freed by the stop */
			r->pcscf_reconfigured = 1;
			fprintf(stderr, "imsroha-rcs: the P-CSCF is unreachable; asking the ACS again\n");
			rcsd_ua_stop(r);
			rcsd_reconfigure(r);
			return;
		}
		schedule_retry(ua, 0);
		return;
	}
	ua->conn = s;
	rcs_net_local_address(s, ua->local_ip, sizeof(ua->local_ip), &ua->local_port, &ua->v6);
	read_more(ua);
	reg_send(ua);
}

static void connect_start(struct sipua *ua)
{
	if (ua->connecting || ua->conn)
		return;
	ua->connecting = 1;
	if (!ua->cancel)
		ua->cancel = g_cancellable_new();
	struct conn_job *j = g_new0(struct conn_job, 1);
	j->ua = ua;
	j->cfg = &ua->r->cfg;
	snprintf(j->host, sizeof(j->host), "%s", ua->host);
	j->port = ua->port;
	j->tls = ua->tls;
	j->default_port = ua->r->cfg.sip_port;
	GTask *t = g_task_new(NULL, ua->cancel, on_connected, ua);
	g_task_set_task_data(t, j, g_free);
	g_task_run_in_thread(t, conn_thread);
	g_object_unref(t);
}

/* ---- life ---------------------------------------------------------------- */

static const char *xml(const struct acs_xml *x, const char *k, const char *def)
{
	const char *v = acs_xml_get(x, k);
	return v && *v ? v : def;
}

static struct sipua *ua_new(struct rcsd *r)
{
	const struct acs_xml *x = r->xml;
	struct sipua *ua = g_new0(struct sipua, 1);
	ua->r = r;
	ua->rx = g_byte_array_new();
	snprintf(ua->impi, sizeof(ua->impi), "%s", xml(x, "Private_User_Identity", ""));
	const char **pu = acs_xml_get_all(x, "Public_User_Identity");
	/* The sip: one (R9 6.4.1: sip:+82...@domain), else the first. */
	const char *impu = pu[0];
	for (int i = 0; pu[i]; i++)
		if (!g_ascii_strncasecmp(pu[i], "sip:", 4)) {
			impu = pu[i];
			break;
		}
	snprintf(ua->impu, sizeof(ua->impu), "%s", impu ? impu : "");
	g_free(pu);
	snprintf(ua->domain, sizeof(ua->domain), "%s", xml(x, "Home_network_domain_name", ""));
	snprintf(ua->auth_type, sizeof(ua->auth_type), "%s", xml(x, "GSMA/AuthType", "Digest"));
	snprintf(ua->realm, sizeof(ua->realm), "%s", xml(x, "GSMA/Realm", ua->domain));
	snprintf(ua->user, sizeof(ua->user), "%s", xml(x, "GSMA/UserName", ua->impi));
	snprintf(ua->pwd, sizeof(ua->pwd), "%s", xml(x, "GSMA/UserPwd", ""));
	const char *sig = xml(x, "transportProto/psSignalling", "SIPoTLS");
	ua->tls = !g_ascii_strcasecmp(sig, "SIPoTCP") ? 0 : 1;
	const char *media = xml(x, "transportProto/psMedia", "MSRPoTLS");
	ua->msrp_tls = !g_ascii_strcasecmp(media, "MSRP") ? 0 : 1;
	ua->timer_idle = (unsigned)strtoul(xml(x, "Chat/TimerIdle", "300"), NULL, 10);
	ua->retry_base = (unsigned)strtoul(xml(x, "RegRetryBaseTime", "30"), NULL, 10);
	ua->retry_max = (unsigned)strtoul(xml(x, "RegRetryMaxTime", "1800"), NULL, 10);
	if (!ua->retry_base)
		ua->retry_base = 30;
	if (ua->retry_max < ua->retry_base)
		ua->retry_max = ua->retry_base;
	ua->expires = r->cfg.reg_expires;
	ua->presence = strtoul(xml(x, "CAPDISCOVERY/defaultDisc", "0"), NULL, 10) == 1;

	/* LBO_P-CSCF_Address: "name", "name:port", "[v6]:port", an IPv4 address. */
	const char *a = xml(x, "LBO_P-CSCF_Address/NODE/Address", xml(x, "LBO_P-CSCF_Address/Address", ""));
	char hp[256];
	snprintf(hp, sizeof(hp), "%s", a);
	char *colon = hp[0] == '[' ? strstr(hp, "]:") : strrchr(hp, ':');
	if (hp[0] == '[') {
		char *rb = strchr(hp, ']');
		if (rb)
			*rb = '\0';
		if (colon)
			ua->port = (uint16_t)strtoul(colon + 2, NULL, 10);
		snprintf(ua->host, sizeof(ua->host), "%s", hp + 1);
	} else {
		if (colon && strchr(hp, ':') == colon) {
			*colon = '\0';
			ua->port = (uint16_t)strtoul(colon + 1, NULL, 10);
		}
		snprintf(ua->host, sizeof(ua->host), "%s", hp);
	}
	/* An IP literal is not resolved further. */
	GInetAddress *ia = g_inet_address_new_from_string(ua->host);
	if (ia && !ua->port)
		ua->port = r->cfg.sip_port;
	if (ia)
		g_object_unref(ia);

	sip_user_of(ua->impu, ua->contact_user, sizeof(ua->contact_user));
	char urn[64];
	if (imsroha_imei_urn(r->id.imei, urn, sizeof(urn)) == 0)
		snprintf(ua->instance, sizeof(ua->instance), "<%s>", urn);
	rcs_config_expand_ua(&r->cfg, r->cfg.user_agent, ua->ua_string, sizeof(ua->ua_string));

	if (!ua->impu[0] || !ua->domain[0] || !ua->host[0]) {
		fprintf(stderr, "imsroha-rcs: the configuration lacks %s\n",
			!ua->impu[0] ? "Public_User_Identity" : !ua->domain[0] ? "Home_network_domain_name"
									 : "LBO_P-CSCF_Address");
		g_byte_array_free(ua->rx, TRUE);
		g_free(ua);
		return NULL;
	}
	if (g_ascii_strcasecmp(ua->auth_type, "Digest"))
		fprintf(stderr, "imsroha-rcs: AuthType %s: only Digest is implemented; trying anyway\n", ua->auth_type);
	return ua;
}

void rcsd_ua_start(struct rcsd *r)
{
	if (r->ua)
		rcsd_ua_stop(r);
	/* The features we register and publish depend on it. */
	rcsd_ft_load(r);
	r->ua = ua_new(r);
	if (!r->ua) {
		rcsd_set_state(r, RCSD_UNREGISTERED);
		return;
	}
	rcsd_set_state(r, RCSD_REGISTERING);
	connect_start(r->ua);
}

void rcsd_ua_stop(struct rcsd *r)
{
	struct sipua *ua = r->ua;
	if (!ua)
		return;
	ua->stopped = 1;
	if (ua->registered && ua->conn && ua->presence && ua->etag[0])
		publish(ua, 0); /* the published capabilities go too */
	if (ua->registered && ua->conn) {
		/* De-register (R9 A.4); nobody waits for the answer. */
		char ruri[160];
		snprintf(ruri, sizeof(ruri), "sip:%s", ua->domain);
		ua->expires = 0;
		sipua_send(ua, &ua->reg, "REGISTER", ruri, NULL, NULL, NULL, 0, NULL, NULL);
	}
	set_unregistered(ua);
	if (ua->retry_timer)
		g_source_remove(ua->retry_timer);
	ua->retry_timer = 0;
	for (GList *l = ua->txs; l; l = l->next)
		((struct sipua_tx *)l->data)->cb = NULL;
	r->ua = NULL;
	/* From inside on_read's dispatch, on_read frees it when the callback returns. */
	if (ua->dispatching)
		ua->dead = 1;
	else
		ua_free(ua);
}

static void ua_free(struct sipua *ua)
{
	drop_conn(ua);
	g_byte_array_free(ua->rx, TRUE);
	g_free(ua);
}
