// SPDX-License-Identifier: GPL-3.0-only
/*
 * 1-to-1 chat (TTAK.KO-06.0410/R9 7.2, GSMA RCC.07, OMA CPM): one CPM
 * session per peer, MSRP for the messages, CPIM around them, IMDN for
 * delivered/displayed, isComposing. Pager-mode MESSAGEs are taken when they
 * come (and used for IMDNs outside a session); they are sent only where the
 * carrier allows standalone messaging.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpim.h"
#include "msrp.h"
#include "rcsd.h"
#include "sipua.h"

enum chat_state { CHAT_INVITING, CHAT_CONNECTING, CHAT_UP, CHAT_CLOSED };

struct outmsg {
	char id[40];          /* imdn.Message-ID, what the app knows it by */
	char msrp_id[40];
	char *body;
	size_t len;
	int status_only;      /* an IMDN or isComposing: no status signal */
};

struct chat {
	struct rcsd *r;
	char number[32];      /* +E.164 */
	struct sipdlg dlg;
	enum chat_state state;
	char local_path[256], remote_path[512];
	struct msrp *msrp;
	GQueue queue;         /* struct outmsg *, waiting for the session */
	GList *inflight;      /* struct outmsg *, sent, waiting for the MSRP 200 */
	guint idle;
	guint closing;        /* deferred close: the MSRP connection went away under us */
	char conv_id[40], contrib_id[40];
};

/* Received messages that asked for a displayed notification: id -> number. */
static GHashTable *want_display;
static GHashTable *conv_ids; /* number -> Conversation-ID (RCC.07: kept per peer) */
static GList *chats;

static void outmsg_free(struct outmsg *o)
{
	g_free(o->body);
	g_free(o);
}

static struct chat *find(const char *number)
{
	for (GList *l = chats; l; l = l->next) {
		struct chat *c = l->data;
		if (!strcmp(c->number, number) && c->state != CHAT_CLOSED)
			return c;
	}
	return NULL;
}

static struct chat *find_dlg(const char *call_id)
{
	for (GList *l = chats; l; l = l->next) {
		struct chat *c = l->data;
		if (!strcmp(c->dlg.call_id, call_id))
			return c;
	}
	return NULL;
}

static void chat_free(struct chat *c)
{
	if (c->idle)
		g_source_remove(c->idle);
	if (c->closing)
		g_source_remove(c->closing);
	if (c->r->ua)
		sipua_forget(c->r->ua, c);
	msrp_free(c->msrp);
	struct outmsg *o;
	while ((o = g_queue_pop_head(&c->queue))) {
		if (!o->status_only)
			rcsd_dbus_status(c->r, o->id, "failed");
		outmsg_free(o);
	}
	for (GList *l = c->inflight; l; l = l->next) {
		o = l->data;
		if (!o->status_only)
			rcsd_dbus_status(c->r, o->id, "failed");
		outmsg_free(o);
	}
	g_list_free(c->inflight);
	chats = g_list_remove(chats, c);
	g_free(c);
}

static void close_chat(struct chat *c, int send_bye)
{
	if (send_bye && c->state == CHAT_UP && c->r->ua && sipua_registered(c->r->ua)) {
		char ruri[300];
		snprintf(ruri, sizeof(ruri), "%s", c->dlg.remote_target);
		sipua_send(c->r->ua, &c->dlg, "BYE", ruri, NULL, NULL, NULL, 0, NULL, NULL);
	}
	c->state = CHAT_CLOSED;
	chat_free(c);
}

static gboolean on_idle(gpointer p)
{
	struct chat *c = p;
	c->idle = 0;
	fprintf(stderr, "imsroha-rcs: chat with %s idle, closing it\n", c->number);
	close_chat(c, 1);
	return G_SOURCE_REMOVE;
}

static void touch(struct chat *c)
{
	if (c->idle)
		g_source_remove(c->idle);
	unsigned t = c->r->ua ? sipua_timer_idle(c->r->ua) : 300;
	c->idle = g_timeout_add_seconds(t ? t : 300, on_idle, c);
}

/* ---- SDP ----------------------------------------------------------------- */

static char *sdp(struct chat *c)
{
	struct sipua *ua = c->r->ua;
	const char *ip = sipua_local_ip(ua);
	int v6 = sipua_local_v6(ua);
	char *s = g_strdup_printf(
		"v=0\r\n"
		"o=- %u %u IN %s %s\r\n"
		"s=-\r\n"
		"c=IN %s %s\r\n"
		"t=0 0\r\n"
		"m=message 9 %s *\r\n"
		"a=path:%s\r\n"
		"a=accept-types:message/cpim application/im-iscomposing+xml\r\n"
		"a=accept-wrapped-types:text/plain message/imdn+xml application/im-iscomposing+xml\r\n"
		"a=setup:active\r\n"
		"a=sendrecv\r\n",
		g_random_int(), 1u, v6 ? "IP6" : "IP4", ip, v6 ? "IP6" : "IP4", ip,
		sipua_msrp_tls(ua) ? "TCP/TLS/MSRP" : "TCP/MSRP", c->local_path);
	return s;
}

static int sdp_path(const char *body, char *out, size_t size)
{
	const char *p = body ? strstr(body, "a=path:") : NULL;
	if (!p)
		return -ENOENT;
	p += 7;
	size_t n = strcspn(p, "\r\n");
	snprintf(out, size, "%.*s", (int)n, p);
	return 0;
}

static void local_path(struct chat *c)
{
	struct sipua *ua = c->r->ua;
	char id[17];
	sip_random(id, 16);
	/* We are active and never listen: port 9, the discard port (RFC 4145 4.1). */
	snprintf(c->local_path, sizeof(c->local_path), "%s://%s%s%s:9/%s;tcp", sipua_msrp_tls(ua) ? "msrps" : "msrp",
		 sipua_local_v6(ua) ? "[" : "", sipua_local_ip(ua), sipua_local_v6(ua) ? "]" : "", id);
}

/* ---- MSRP ---------------------------------------------------------------- */

static void flush(struct chat *c)
{
	struct outmsg *o;
	while (c->state == CHAT_UP && (o = g_queue_pop_head(&c->queue))) {
		int r = msrp_send(c->msrp, "message/cpim", o->body, o->len, !o->status_only, o->msrp_id,
				  sizeof(o->msrp_id));
		if (r < 0 || o->status_only) {
			if (r < 0 && !o->status_only)
				rcsd_dbus_status(c->r, o->id, "failed");
			outmsg_free(o);
			continue;
		}
		c->inflight = g_list_append(c->inflight, o);
	}
}

static void send_imdn(struct rcsd *r, const char *number, const char *orig, const char *status);

static void on_text(struct chat *c, const struct cpim *m)
{
	if (!g_ascii_strcasecmp(m->ctype, "text/plain")) {
		char id[64];
		snprintf(id, sizeof(id), "%s", m->msg_id ? m->msg_id : "");
		fprintf(stderr, "imsroha-rcs: chat message from %s (%s)\n", c->number, id);
		rcsd_dbus_message_received(c->r, c->number, id, m->body, cpim_time_ms(m->datetime));
		if (m->msg_id && m->disposition) {
			if (strstr(m->disposition, "display"))
				g_hash_table_replace(want_display, g_strdup(m->msg_id), g_strdup(c->number));
			if (strstr(m->disposition, "positive-delivery"))
				send_imdn(c->r, c->number, m->msg_id, "delivered");
		}
	} else if (!g_ascii_strcasecmp(m->ctype, "message/imdn+xml")) {
		char id[64], st[32];
		if (imdn_parse(m->body, m->blen, id, sizeof(id), st, sizeof(st)) == 0) {
			fprintf(stderr, "imsroha-rcs: %s: %s\n", id, st);
			rcsd_dbus_status(c->r, id, st);
		}
	} else if (!g_ascii_strcasecmp(m->ctype, "application/im-iscomposing+xml")) {
		int a = iscomposing_parse(m->body, m->blen);
		if (a >= 0)
			rcsd_dbus_composing(c->r, c->number, a);
	}
}

static void on_msrp_message(struct msrp *m, const char *ctype, const char *body, size_t len, void *ud)
{
	(void)m;
	struct chat *c = ud;
	touch(c);
	char *ct = g_strdup(ctype);
	char *semi = strchr(ct, ';');
	if (semi)
		*semi = '\0';
	g_strstrip(ct);
	if (!g_ascii_strcasecmp(ct, "message/cpim")) {
		struct cpim cp;
		if (cpim_parse(body, len, &cp) == 0)
			on_text(c, &cp);
		cpim_clear(&cp);
	} else if (!g_ascii_strcasecmp(ct, "application/im-iscomposing+xml")) {
		int a = iscomposing_parse(body, len);
		if (a >= 0)
			rcsd_dbus_composing(c->r, c->number, a);
	}
	g_free(ct);
}

static void on_msrp_result(struct msrp *m, const char *msrp_id, int code, void *ud)
{
	(void)m;
	struct chat *c = ud;
	for (GList *l = c->inflight; l; l = l->next) {
		struct outmsg *o = l->data;
		if (strcmp(o->msrp_id, msrp_id))
			continue;
		c->inflight = g_list_delete_link(c->inflight, l);
		rcsd_dbus_status(c->r, o->id, code == 200 ? "sent" : "failed");
		outmsg_free(o);
		return;
	}
}

static gboolean deferred_close(gpointer p)
{
	struct chat *c = p;
	c->closing = 0;
	close_chat(c, 1);
	return G_SOURCE_REMOVE;
}

static void on_msrp_state(struct msrp *m, int up, void *ud)
{
	(void)m;
	struct chat *c = ud;
	if (up) {
		if (c->state == CHAT_CONNECTING) {
			c->state = CHAT_UP;
			fprintf(stderr, "imsroha-rcs: chat with %s is up\n", c->number);
		}
		flush(c);
		return;
	}
	/* The MSRP connection is gone: the session is over (R9 7.2.2). Not from
	 * inside the MSRP callback, which still holds the connection. */
	if (!c->closing)
		c->closing = g_idle_add(deferred_close, c);
}

static const struct msrp_cbs msrp_cbs = {
	.message = on_msrp_message,
	.result = on_msrp_result,
	.state = on_msrp_state,
};

static void start_msrp(struct chat *c)
{
	c->state = CHAT_CONNECTING;
	c->msrp = msrp_new(&c->r->cfg, c->local_path, c->remote_path, &msrp_cbs, c);
	msrp_connect(c->msrp);
	touch(c);
}

/* ---- sessions ------------------------------------------------------------ */

static void route_from(struct sipdlg *d, const struct sipmsg *m, int reverse)
{
	char **rr = sipmsg_header_all(m, "Record-Route");
	int n = (int)g_strv_length(rr);
	GString *s = g_string_new(NULL);
	for (int i = 0; i < n; i++) {
		const char *v = rr[reverse ? n - 1 - i : i];
		g_string_append_printf(s, "%s%s", s->len ? ", " : "", v);
	}
	snprintf(d->route, sizeof(d->route), "%s", s->str);
	g_string_free(s, TRUE);
	g_strfreev(rr);
}

static void target_from(struct sipdlg *d, const struct sipmsg *m)
{
	const char *ct = sipmsg_header(m, "Contact");
	if (ct)
		sip_uri_of(ct, d->remote_target, sizeof(d->remote_target));
}

static void on_invite_resp(struct sipua *ua, const struct sipmsg *m, void *ud)
{
	struct chat *c = ud;
	if (m && m->code < 200)
		return;
	if (!m || m->code >= 300) {
		fprintf(stderr, "imsroha-rcs: chat INVITE to %s: %s\n", c->number,
			m ? m->reason : "no answer");
		close_chat(c, 0);
		return;
	}
	const char *to = sipmsg_header(m, "To");
	if (to)
		sip_param(to, "tag", c->dlg.remote_tag, sizeof(c->dlg.remote_tag));
	target_from(&c->dlg, m);
	route_from(&c->dlg, m, 1);
	if (!c->dlg.remote_target[0])
		snprintf(c->dlg.remote_target, sizeof(c->dlg.remote_target), "%s", c->dlg.remote_uri);
	/* ACK reuses the INVITE's CSeq. */
	sipua_send(ua, &c->dlg, "ACK", c->dlg.remote_target, NULL, NULL, NULL, 0, NULL, NULL);
	if (sdp_path(m->body, c->remote_path, sizeof(c->remote_path)) < 0) {
		fprintf(stderr, "imsroha-rcs: chat answer from %s without a=path\n", c->number);
		close_chat(c, 1);
		return;
	}
	start_msrp(c);
}

static const char *conv_id(const char *number)
{
	const char *v = g_hash_table_lookup(conv_ids, number);
	if (v)
		return v;
	char id[33];
	sip_random(id, 32);
	g_hash_table_insert(conv_ids, g_strdup(number), g_strdup(id));
	return g_hash_table_lookup(conv_ids, number);
}

static struct chat *new_chat(struct rcsd *r, const char *number)
{
	struct chat *c = g_new0(struct chat, 1);
	c->r = r;
	snprintf(c->number, sizeof(c->number), "%s", number);
	g_queue_init(&c->queue);
	snprintf(c->conv_id, sizeof(c->conv_id), "%s", conv_id(number));
	sip_random(c->contrib_id, 32);
	chats = g_list_append(chats, c);
	return c;
}

static struct chat *invite(struct rcsd *r, const char *number)
{
	struct chat *c = new_chat(r, number);
	c->state = CHAT_INVITING;
	snprintf(c->dlg.remote_uri, sizeof(c->dlg.remote_uri), "<tel:%s>", number);
	local_path(c);
	char *body = sdp(c);
	char extra[768];
	snprintf(extra, sizeof(extra),
		 "Accept-Contact: *;+g.3gpp.icsi-ref=\"%s\"\r\n"
		 "P-Preferred-Service: %s\r\n"
		 "Accept: application/sdp\r\n"
		 "Conversation-ID: %s\r\nContribution-ID: %s\r\n",
		 RCS_ICSI_CHAT, RCS_ICSI_CHAT_RAW, c->conv_id, c->contrib_id);
	char ruri[64];
	snprintf(ruri, sizeof(ruri), "tel:%s", number);
	fprintf(stderr, "imsroha-rcs: opening a chat with %s\n", number);
	int e = sipua_send(r->ua, &c->dlg, "INVITE", ruri, extra, "application/sdp", body, strlen(body),
			   on_invite_resp, c);
	g_free(body);
	if (e < 0) {
		close_chat(c, 0);
		return NULL;
	}
	return c;
}

/* ---- IMDN outside a session: a SIP MESSAGE ------------------------------- */

static void send_message(struct rcsd *r, const char *number, const char *body, size_t len)
{
	struct sipdlg d = { 0 };
	char ruri[64];
	snprintf(ruri, sizeof(ruri), "tel:%s", number);
	snprintf(d.remote_uri, sizeof(d.remote_uri), "<%s>", ruri);
	char extra[512];
	snprintf(extra, sizeof(extra), "Accept-Contact: *;+g.3gpp.icsi-ref=\"%s\"\r\n"
		 "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.oma.cpm.msg\r\n"
		 "Conversation-ID: %s\r\n", RCS_ICSI_MSG, conv_id(number));
	sipua_send(r->ua, &d, "MESSAGE", ruri, extra, "message/cpim", body, len, NULL, NULL);
}

static void send_imdn(struct rcsd *r, const char *number, const char *orig, const char *status)
{
	size_t len;
	char *body = cpim_imdn(orig, status, &len);
	struct chat *c = find(number);
	if (c && c->state == CHAT_UP) {
		struct outmsg *o = g_new0(struct outmsg, 1);
		o->body = body;
		o->len = len;
		o->status_only = 1;
		g_queue_push_tail(&c->queue, o);
		flush(c);
		return;
	}
	if (r->ua && sipua_registered(r->ua))
		send_message(r, number, body, len);
	g_free(body);
}

/* ---- the network's requests ---------------------------------------------- */

static int caller(struct sipua *ua, const struct sipmsg *m, char *out, size_t size)
{
	/* R9 6.4.1: P-Asserted-Identity before From. */
	char **pai = sipmsg_header_all(m, "P-Asserted-Identity");
	char uri[256] = "";
	for (int i = 0; pai[i] && !uri[0]; i++)
		sip_uri_of(pai[i], uri, sizeof(uri));
	g_strfreev(pai);
	if (!uri[0]) {
		const char *f = sipmsg_header(m, "From");
		if (f)
			sip_uri_of(f, uri, sizeof(uri));
	}
	char user[64];
	sip_user_of(uri, user, sizeof(user));
	return sipua_e164(ua, user, out, size);
}

static void on_invite(struct rcsd *r, struct sipua *ua, const struct sipmsg *m)
{
	char number[32];
	if (!m->body || !strstr(m->body, "m=message") || caller(ua, m, number, sizeof(number)) < 0) {
		sipua_respond(ua, m, 488, "Not Acceptable Here", "x", NULL, NULL, NULL);
		return;
	}
	const char *cid = sipmsg_header(m, "Call-ID");
	if (cid && find_dlg(cid))
		return; /* a retransmission */
	sipua_respond(ua, m, 100, "Trying", NULL, NULL, NULL, NULL);
	/* A new session from the same peer replaces the old one. */
	struct chat *old = find(number);
	struct chat *c = new_chat(r, number);
	if (old) {
		/* Messages still waiting move to the new session. */
		struct outmsg *o;
		while ((o = g_queue_pop_head(&old->queue)))
			g_queue_push_tail(&c->queue, o);
		close_chat(old, 1);
	}
	c->dlg.uas = 1;
	snprintf(c->dlg.call_id, sizeof(c->dlg.call_id), "%s", cid ? cid : "");
	sip_random(c->dlg.local_tag, 12);
	const char *from = sipmsg_header(m, "From");
	if (from) {
		sip_param(from, "tag", c->dlg.remote_tag, sizeof(c->dlg.remote_tag));
		char u[256];
		sip_uri_of(from, u, sizeof(u));
		snprintf(c->dlg.remote_uri, sizeof(c->dlg.remote_uri), "<%s>", u);
	}
	const char *cseq = sipmsg_header(m, "CSeq");
	c->dlg.cseq = 0;
	(void)cseq;
	target_from(&c->dlg, m);
	route_from(&c->dlg, m, 0);
	const char *conv = sipmsg_header(m, "Conversation-ID");
	if (conv) {
		g_hash_table_replace(conv_ids, g_strdup(number), g_strdup(conv));
		snprintf(c->conv_id, sizeof(c->conv_id), "%s", conv);
	}
	const char *contrib = sipmsg_header(m, "Contribution-ID");
	if (contrib)
		snprintf(c->contrib_id, sizeof(c->contrib_id), "%s", contrib);
	if (sdp_path(m->body, c->remote_path, sizeof(c->remote_path)) < 0) {
		sipua_respond(ua, m, 488, "Not Acceptable Here", c->dlg.local_tag, NULL, NULL, NULL);
		close_chat(c, 0);
		return;
	}
	local_path(c);
	char *body = sdp(c);
	char extra[256];
	snprintf(extra, sizeof(extra), "Conversation-ID: %s\r\nContribution-ID: %s\r\n", c->conv_id, c->contrib_id);
	/* AutAccept (R9 7.2.1): answered at once. */
	sipua_respond(ua, m, 200, "OK", c->dlg.local_tag, extra, "application/sdp", body);
	g_free(body);
	fprintf(stderr, "imsroha-rcs: chat from %s accepted\n", number);
	start_msrp(c);
}

static void on_message(struct rcsd *r, struct sipua *ua, const struct sipmsg *m)
{
	char number[32];
	const char *ct = sipmsg_header(m, "Content-Type");
	if (caller(ua, m, number, sizeof(number)) < 0 || !ct || g_ascii_strncasecmp(ct, "message/cpim", 12)) {
		sipua_respond(ua, m, 415, "Unsupported Media Type", "x", "Accept: message/cpim\r\n", NULL, NULL);
		return;
	}
	sipua_respond(ua, m, 200, "OK", "m", NULL, NULL, NULL);
	struct cpim cp;
	if (cpim_parse(m->body, m->blen, &cp) == 0) {
		struct chat tmp = { .r = r };
		snprintf(tmp.number, sizeof(tmp.number), "%s", number);
		on_text(&tmp, &cp);
	}
	cpim_clear(&cp);
}

void chat_on_request(struct rcsd *r, struct sipua *ua, const struct sipmsg *m)
{
	if (!want_display) {
		want_display = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
		conv_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	}
	const char *cid = sipmsg_header(m, "Call-ID");
	struct chat *c = cid ? find_dlg(cid) : NULL;

	if (!strcmp(m->method, "INVITE")) {
		if (c && c->state != CHAT_CLOSED) {
			/* A re-INVITE: keep the session as it is. */
			char *body = sdp(c);
			sipua_respond(ua, m, 200, "OK", c->dlg.local_tag, NULL, "application/sdp", body);
			g_free(body);
			return;
		}
		on_invite(r, ua, m);
	} else if (!strcmp(m->method, "ACK")) {
		/* Our 200 was taken; MSRP is already on its way. */
	} else if (!strcmp(m->method, "BYE")) {
		sipua_respond(ua, m, c ? 200 : 481, c ? "OK" : "Call/Transaction Does Not Exist", NULL, NULL, NULL, NULL);
		if (c) {
			fprintf(stderr, "imsroha-rcs: chat with %s ended by the network\n", c->number);
			close_chat(c, 0);
		}
	} else if (!strcmp(m->method, "CANCEL")) {
		sipua_respond(ua, m, 200, "OK", NULL, NULL, NULL, NULL);
	} else if (!strcmp(m->method, "UPDATE")) {
		sipua_respond(ua, m, 200, "OK", c ? c->dlg.local_tag : NULL, NULL, NULL, NULL);
	} else if (!strcmp(m->method, "MESSAGE")) {
		on_message(r, ua, m);
	}
}

void chat_on_registered(struct rcsd *r)
{
	(void)r;
	if (!want_display) {
		want_display = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
		conv_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	}
}

static void caps_drop_all(struct rcsd *r);

void chat_on_unregistered(struct rcsd *r)
{
	caps_drop_all(r);
	while (chats)
		close_chat(chats->data, 0);
}

/* ---- the D-Bus side ------------------------------------------------------ */

static gboolean ready(struct rcsd *r, GError **error)
{
	if (r->ua && sipua_registered(r->ua))
		return TRUE;
	g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_CONNECTED, "RCS is not registered (%s)",
		    rcsd_state_name(r->state));
	return FALSE;
}

gboolean rcsd_chat_send(struct rcsd *r, const char *number, const char *text, char *id, size_t size,
			GError **error)
{
	char e164[32];
	if (!ready(r, error))
		return FALSE;
	if (sipua_e164(r->ua, number, e164, sizeof(e164)) < 0) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "not a phone number: %s", number);
		return FALSE;
	}
	chat_on_registered(r);
	struct chat *c = find(e164);
	if (!c && !(c = invite(r, e164))) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "cannot open a chat with %s", e164);
		return FALSE;
	}
	struct outmsg *o = g_new0(struct outmsg, 1);
	cpim_msg_id(o->id, sizeof(o->id));
	o->body = cpim_text(o->id, text, &o->len);
	snprintf(id, size, "%s", o->id);
	g_queue_push_tail(&c->queue, o);
	flush(c);
	if (c->state == CHAT_UP)
		touch(c);
	return TRUE;
}

gboolean rcsd_chat_composing(struct rcsd *r, const char *number, gboolean active, GError **error)
{
	char e164[32];
	if (!ready(r, error))
		return FALSE;
	if (sipua_e164(r->ua, number, e164, sizeof(e164)) < 0) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "not a phone number: %s", number);
		return FALSE;
	}
	/* Only inside a session: no session is opened for it, nothing is stored (R9 7.2.3). */
	struct chat *c = find(e164);
	if (!c || c->state != CHAT_UP)
		return TRUE;
	size_t len;
	int wrap = r->cfg.iscomposing_cpim;
	char *body = iscomposing(active, wrap, &len);
	msrp_send(c->msrp, wrap ? "message/cpim" : "application/im-iscomposing+xml", body, len, 0, NULL, 0);
	g_free(body);
	return TRUE;
}

gboolean rcsd_chat_displayed(struct rcsd *r, const char *number, const char *id, GError **error)
{
	(void)number;
	if (!ready(r, error))
		return FALSE;
	const char *from = want_display ? g_hash_table_lookup(want_display, id) : NULL;
	if (!from)
		return TRUE; /* no displayed notification was asked for */
	char *n = g_strdup(from);
	g_hash_table_remove(want_display, id);
	send_imdn(r, n, id, "displayed");
	g_free(n);
	return TRUE;
}

/* ---- capabilities: presence anonymous fetch (R9 6.5), or OPTIONS ----------- */

struct capq {
	struct rcsd *r;
	GDBusMethodInvocation *inv;
	struct sipdlg dlg;
	guint timer;
	int replied, tx_done;
};

static GList *capqs;

static void cap_reply(struct capq *q, int known, int chat, int ft, int code)
{
	if (q->replied)
		return;
	q->replied = 1;
	if (q->timer)
		g_source_remove(q->timer);
	q->timer = 0;
	GVariantBuilder b;
	g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(&b, "{sv}", "known", g_variant_new_boolean(known));
	g_variant_builder_add(&b, "{sv}", "chat", g_variant_new_boolean(chat));
	g_variant_builder_add(&b, "{sv}", "ft-http", g_variant_new_boolean(ft));
	if (code)
		g_variant_builder_add(&b, "{sv}", "sip-status", g_variant_new_int32(code));
	g_dbus_method_invocation_return_value(q->inv, g_variant_new("(a{sv})", &b));
}

static void cap_maybe_free(struct capq *q)
{
	if (!q->replied || !q->tx_done)
		return;
	capqs = g_list_remove(capqs, q);
	g_free(q);
}

/* A tuple with this service-id whose basic status is open. */
static int pidf_has(const char *body, const char *service)
{
	const char *p = body;
	while (p && (p = strstr(p, service))) {
		const char *t = g_strrstr_len(body, p - body, "<tuple");
		const char *e = strstr(p, "</tuple>");
		if (t && e) {
			char *tuple = g_strndup(t, (gsize)(e - t));
			int open = strstr(tuple, "<basic>open</basic>") != NULL;
			g_free(tuple);
			if (open)
				return 1;
		}
		p += strlen(service);
	}
	return 0;
}

static gboolean on_cap_timeout(gpointer p)
{
	struct capq *q = p;
	q->timer = 0;
	cap_reply(q, 0, 0, 0, 0);
	cap_maybe_free(q);
	return G_SOURCE_REMOVE;
}

static void on_options(struct sipua *ua, const struct sipmsg *m, void *ud)
{
	(void)ua;
	struct capq *q = ud;
	if (m && m->code < 200)
		return;
	q->tx_done = 1;
	int chat = 0, ft = 0;
	if (m && m->code >= 200 && m->code < 300) {
		char **cs = sipmsg_header_all(m, "Contact");
		for (int i = 0; cs[i]; i++) {
			chat |= strstr(cs[i], "oma.cpm.session") != NULL;
			ft |= strstr(cs[i], "rcs.fthttp") != NULL;
		}
		g_strfreev(cs);
	}
	cap_reply(q, m != NULL, chat, ft, m ? m->code : 0);
	cap_maybe_free(q);
}

static void on_subscribe(struct sipua *ua, const struct sipmsg *m, void *ud)
{
	(void)ua;
	struct capq *q = ud;
	if (m && m->code < 200)
		return;
	q->tx_done = 1;
	if (!m) {
		cap_reply(q, 0, 0, 0, 0);
	} else if (m->code < 300) {
		/* The answer is the NOTIFY that follows. */
		if (!q->replied && !q->timer)
			q->timer = g_timeout_add_seconds(32, on_cap_timeout, q);
	} else {
		/* No such RCS user (404, 410, 480, 603, 604), or we do not know. */
		int no = m->code == 404 || m->code == 410 || m->code == 480 || m->code == 603 || m->code == 604;
		cap_reply(q, no, 0, 0, m->code);
	}
	cap_maybe_free(q);
}

int chat_on_notify(struct rcsd *r, struct sipua *ua, const struct sipmsg *m)
{
	(void)r;
	const char *cid = sipmsg_header(m, "Call-ID");
	struct capq *q = NULL;
	for (GList *l = capqs; cid && l; l = l->next)
		if (!strcmp(((struct capq *)l->data)->dlg.call_id, cid))
			q = l->data;
	if (!q)
		return -1;
	sipua_respond(ua, m, 200, "OK", NULL, NULL, NULL, NULL);
	const char *body = m->body ? m->body : "";
	int chat = pidf_has(body, "org.openmobilealliance:ChatSession");
	int ft = pidf_has(body, "org.openmobilealliance:File-Transfer-HTTP");
	cap_reply(q, 1, chat, ft, 0);
	cap_maybe_free(q);
	return 0;
}

static void caps_drop_all(struct rcsd *r)
{
	while (capqs) {
		struct capq *q = capqs->data;
		if (r->ua)
			sipua_forget(r->ua, q);
		q->tx_done = 1;
		cap_reply(q, 0, 0, 0, 0);
		cap_maybe_free(q);
	}
}

void rcsd_capabilities(struct rcsd *r, const char *number, GDBusMethodInvocation *inv)
{
	GError *e = NULL;
	char e164[32];
	if (!ready(r, &e)) {
		g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_NOT_READY, e->message);
		g_error_free(e);
		return;
	}
	if (sipua_e164(r->ua, number, e164, sizeof(e164)) < 0) {
		g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_FAILED, "not a phone number");
		return;
	}
	struct capq *q = g_new0(struct capq, 1);
	q->r = r;
	q->inv = inv;
	char ruri[64];
	snprintf(ruri, sizeof(ruri), "tel:%s", e164);
	snprintf(q->dlg.remote_uri, sizeof(q->dlg.remote_uri), "<%s>", ruri);
	int err;
	if (sipua_presence(r->ua)) {
		/* R9 6.5.1's anonymous fetch: one NOTIFY with the peer's PIDF. */
		q->dlg.anonymous = 1;
		err = sipua_send(r->ua, &q->dlg, "SUBSCRIBE", ruri,
				 "Expires: 0\r\nAccept: application/pidf+xml, multipart/related\r\nEvent: presence\r\n"
				 "Accept-Contact: *;+g.oma.sip-im;explicit;require\r\nPrivacy: id\r\n",
				 NULL, NULL, 0, on_subscribe, q);
	} else {
		err = sipua_send(r->ua, &q->dlg, "OPTIONS", ruri, "Accept: application/sdp\r\n", NULL, NULL, 0,
				 on_options, q);
	}
	if (err < 0) {
		g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_FAILED, "cannot ask");
		g_free(q);
		return;
	}
	capqs = g_list_append(capqs, q);
}
