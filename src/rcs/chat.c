// SPDX-License-Identifier: GPL-3.0-only
/*
 * 1-to-1 chat (TTAK.KO-06.0410/R9 7.2, GSMA RCC.07, OMA CPM): one CPM
 * session per peer, MSRP for the messages, CPIM around them, IMDN for
 * delivered/displayed, isComposing. Pager-mode MESSAGEs are taken when they
 * come (and used for IMDNs outside a session); they are sent only where the
 * carrier allows standalone messaging.
 *
 * Chatbots and RCS A2P (RCC.07 3.6, R9 7.7) ride the same paths: a peer is
 * a phone number (+E.164; an A2P sender with a tel URI lands in that
 * number's thread, R9 7.7.3.1) or a chatbot's SIP URI. They come in a
 * session, in pager mode, or in large message mode (an MSRP session for one
 * message, R9 7.7.3.3), as rich cards, extended bot messages and
 * multipart/mixed with suggestions.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bot.h"
#include "cpim.h"
#include "cert.h"
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
	char number[256];     /* the peer: +E.164, or a chatbot's sip: URI */
	char bot_id[256];     /* the chatbot service id, when the peer is one */
	int bot;              /* a chatbot session: bot types in the SDP */
	int large;            /* large message mode: one message in, never ours to send in */
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
/*
 * Messages whose sender asked for a displayed notification, message-id ->
 * number, until the app says they were read (MarkDisplayed). Kept in
 * <state-dir>/<IMSI>/want-display ("id<TAB>number<TAB>unix time" lines),
 * so a restart between receipt and reading does not lose the report.
 * Entries older than WANT_DISPLAY_MAX_AGE are dropped when it is loaded.
 */
static GHashTable *want_display;
static char *want_display_path;
#define WANT_DISPLAY_MAX_AGE (30 * 24 * 3600)

static void want_display_save(void)
{
	if (!want_display_path)
		return;
	GString *s = g_string_new(NULL);
	GHashTableIter it;
	gpointer k, v;
	g_hash_table_iter_init(&it, want_display);
	while (g_hash_table_iter_next(&it, &k, &v))
		g_string_append_printf(s, "%s\t%s\n", (const char *)k, (const char *)v);
	GError *e = NULL;
	if (!g_file_set_contents_full(want_display_path, s->str, (gssize)s->len,
				      G_FILE_SET_CONTENTS_CONSISTENT, 0600, &e)) {
		fprintf(stderr, "imsroha-rcs: %s\n", e->message);
		g_error_free(e);
	}
	g_string_free(s, TRUE);
}

/* value: "number\tunix-time" */
static void want_display_load(struct rcsd *r)
{
	g_free(want_display_path);
	want_display_path = g_build_filename(r->cfg.state_dir, r->id.imsi, "want-display", NULL);
	char *data = NULL;
	if (!g_file_get_contents(want_display_path, &data, NULL, NULL))
		return;
	gint64 now = g_get_real_time() / G_USEC_PER_SEC;
	char **lines = g_strsplit(data, "\n", -1);
	for (char **l = lines; *l; l++) {
		char **f = g_strsplit(*l, "\t", 3);
		if (f[0] && f[1] && f[2] && *f[0] && now - g_ascii_strtoll(f[2], NULL, 10) < WANT_DISPLAY_MAX_AGE)
			g_hash_table_replace(want_display, g_strdup(f[0]), g_strdup_printf("%s\t%s", f[1], f[2]));
		g_strfreev(f);
	}
	g_strfreev(lines);
	g_free(data);
}
static GHashTable *conv_ids; /* number -> Conversation-ID (RCC.07: kept per peer) */
static GHashTable *bot_ids;  /* +E.164 -> chatbot service id, from capability discovery (R9 7.7.3.2) */
static GHashTable *sent_ids; /* imdn.Message-IDs we sent this run */
static GList *chats;

static void tables(void)
{
	if (want_display)
		return;
	want_display = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	conv_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	bot_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	sent_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
}

/* The request URI of a peer: tel:+82... or the bot's sip: URI. */
static void key_uri(const char *key, char *out, size_t size)
{
	snprintf(out, size, "%s%s", key[0] == '+' ? "tel:" : "", key);
}

static int sip_key(const char *key)
{
	return key[0] != '+';
}

static void outmsg_free(struct outmsg *o)
{
	g_free(o->body);
	g_free(o);
}

static struct chat *find(const char *number)
{
	for (GList *l = chats; l; l = l->next) {
		struct chat *c = l->data;
		if (!strcmp(c->number, number) && c->state != CHAT_CLOSED && !c->large)
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
	int tls = sipua_msrp_tls(ua);
	char fp[96] = "";
	if (tls) {
		/* MSRPoTLS: the client certificate's hash (RFC 4975 14.1, RFC 8122) */
		char *dir = g_build_filename(c->r->cfg.state_dir, c->r->id.imsi, NULL);
		GError *e = NULL;
		if (rcs_cert_ensure(dir, sipua_impu(ua), &e) == 0)
			snprintf(fp, sizeof(fp), "a=fingerprint:%s\r\n", rcs_cert_fingerprint());
		else
			fprintf(stderr, "imsroha-rcs: %s\n", e->message);
		g_clear_error(&e);
		g_free(dir);
	}
	/*
	 * With a chatbot, what it may send us (R9 7.7.4.17.3: the platform reads
	 * accept-wrapped-types before it sends an open rich card): the bot
	 * content types stock libsec-ims.so knows, the extended ones only when we
	 * advertise xbotmessage.
	 */
	const char *bot = "", *xbot = "";
	if (c->bot && bot_on(&c->r->bot)) {
		bot = " multipart/mixed " BOT_CT_MESSAGE " " BOT_CT_SUGGESTION;
		if (c->r->bot.xbot)
			xbot = " " BOT_CT_XBOT " " BOT_CT_OPENRICH;
	}
	char *s = g_strdup_printf(
		"v=0\r\n"
		"o=- %u %u IN %s %s\r\n"
		"s=-\r\n"
		"c=IN %s %s\r\n"
		"t=0 0\r\n"
		"m=message 9 %s *\r\n"
		"a=path:%s\r\n"
		"a=accept-types:message/cpim application/im-iscomposing+xml\r\n"
		"a=accept-wrapped-types:text/plain message/imdn+xml application/im-iscomposing+xml%s%s%s\r\n"
		"a=setup:active\r\n"
		"%s"
		"a=%s\r\n",
		g_random_int(), 1u, v6 ? "IP6" : "IP4", ip, v6 ? "IP6" : "IP4", ip,
		tls ? "TCP/TLS/MSRP" : "TCP/MSRP", c->local_path,
		/* R9's INVITE example: a file-info rides the chat as a wrapped type. */
		c->r->ft.enabled ? " " FT_HTTP_CTYPE : "", bot, xbot, fp,
		/* Large message mode: the sender's offer is sendonly. */
		c->large ? "recvonly" : "sendrecv");
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

/* An IMDN for one of our messages. R9 7.7.3.3.1: before a standalone
 * message the platform may probe with a delivered IMDN for an id that never
 * existed (R9's example ends in "-bodiless"); that one gets its 200 and
 * nothing else. Other ids we did not send this run may be from before a
 * restart, and the app knows them. */
static void imdn_status(struct rcsd *r, const char *id, const char *st)
{
	if (!g_hash_table_contains(sent_ids, id) && g_str_has_suffix(id, "-bodiless")) {
		fprintf(stderr, "imsroha-rcs: network check (IMDN for %s), nothing to report\n", id);
		return;
	}
	fprintf(stderr, "imsroha-rcs: %s: %s\n", id, st);
	rcsd_dbus_status(r, id, st);
}

static const char *peer_bot_id(const struct chat *c)
{
	if (c->bot_id[0])
		return c->bot_id;
	const char *v = !sip_key(c->number) ? g_hash_table_lookup(bot_ids, c->number) : NULL;
	return v ? v : "";
}

/* A bot payload: a rich card, an extended bot message, text with suggestions. 0 when it was one. */
static int on_bot_payload(struct chat *c, const struct cpim *m, const char *id, gint64 ts)
{
	char *pct = NULL, *part = NULL, *sugg = NULL;
	size_t plen = 0;
	int r = -1;
	if (!g_ascii_strcasecmp(m->ctype, "multipart/mixed")) {
		if (bot_multipart_split(m->ctype_full, m->body, m->blen, &pct, &part, &plen, &sugg) < 0) {
			fprintf(stderr, "imsroha-rcs: chat %s from %s: unreadable multipart/mixed, dropped\n", id, c->number);
			return 0;
		}
	} else if (bot_kind_of(m->ctype) != BOT_KIND_NONE) {
		pct = g_strdup(m->ctype);
		part = g_strndup(m->body, m->blen);
		plen = m->blen;
	} else {
		return -1;
	}
	const char *bot_id = peer_bot_id(c);
	if (!g_ascii_strcasecmp(pct, "text/plain") && !sugg) {
		/* Bot text without suggestions stays a plain message. */
		rcsd_dbus_message_received(c->r, c->number, id, part, ts);
		r = 0;
	} else if (!g_ascii_strcasecmp(pct, "text/plain") || bot_kind_of(pct) != BOT_KIND_NONE) {
		fprintf(stderr, "imsroha-rcs: chat %s from %s: %s%s (bot %s)\n", id, c->number, pct,
			sugg ? " with suggestions" : "", bot_id[0] ? bot_id : "unknown");
		rcsd_dbus_rich_received(c->r, c->number, id, !g_ascii_strcasecmp(pct, "text/plain") ? "text/plain" : pct,
					part, sugg ? sugg : "", bot_id, ts);
		r = 0;
	} else {
		fprintf(stderr, "imsroha-rcs: chat %s from %s: %s inside multipart/mixed, dropped\n", id, c->number, pct);
		r = 0;
	}
	(void)plen;
	g_free(pct);
	g_free(part);
	g_free(sugg);
	return r;
}

static void on_text(struct chat *c, const struct cpim *m)
{
	int text = !g_ascii_strcasecmp(m->ctype, "text/plain");
	int ft = !g_ascii_strcasecmp(m->ctype, FT_HTTP_CTYPE);
	int bot = !text && !ft && bot_on(&c->r->bot) &&
		  (!g_ascii_strcasecmp(m->ctype, "multipart/mixed") || bot_kind_of(m->ctype) != BOT_KIND_NONE);
	if (text || ft || bot) {
		char id[64];
		snprintf(id, sizeof(id), "%s", m->msg_id ? m->msg_id : "");
		gint64 ts = cpim_time_ms(m->datetime);
		if (bot) {
			on_bot_payload(c, m, id, ts);
		} else {
			fprintf(stderr, "imsroha-rcs: chat %s from %s (%s)\n", text ? "message" : "file", c->number, id);
			if (text)
				rcsd_dbus_message_received(c->r, c->number, id, m->body, ts);
			else
				rcsd_ft_received(c->r, c->number, id, m->body, m->blen, ts);
		}
		/* A file-info is a chat message like any other: delivered now, as
		 * stock does (it marks it delivered before the download), and
		 * displayed when the app says so. So is a bot's message. */
		if (m->msg_id && m->disposition) {
			if (strstr(m->disposition, "display"))
			{
				g_hash_table_replace(want_display, g_strdup(m->msg_id),
						     g_strdup_printf("%s\t%" G_GINT64_FORMAT, c->number,
								     g_get_real_time() / G_USEC_PER_SEC));
				want_display_save();
			}
			if (strstr(m->disposition, "positive-delivery"))
				send_imdn(c->r, c->number, m->msg_id, "delivered");
		}
	} else if (!g_ascii_strcasecmp(m->ctype, "message/imdn+xml")) {
		char id[64], st[32];
		if (imdn_parse(m->body, m->blen, id, sizeof(id), st, sizeof(st)) == 0)
			imdn_status(c->r, id, st);
	} else if (!g_ascii_strcasecmp(m->ctype, "application/im-iscomposing+xml")) {
		int a = iscomposing_parse(m->body, m->blen);
		if (a >= 0)
			rcsd_dbus_composing(c->r, c->number, a);
	} else if (bot_kind_of(m->ctype) != BOT_KIND_NONE || !g_ascii_strcasecmp(m->ctype, "multipart/mixed")) {
		fprintf(stderr, "imsroha-rcs: chat from %s: %s, but chatbots are off; dropped\n", c->number, m->ctype);
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
	if (!c->msrp) {
		g_warning("chat %s: the peer's MSRP path is unusable, ending the session", c->number);
		c->state = CHAT_UP; /* the SIP dialog is up: end it with a BYE */
		close_chat(c, 1);
		return;
	}
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
	char ruri[260];
	key_uri(number, ruri, sizeof(ruri));
	snprintf(c->dlg.remote_uri, sizeof(c->dlg.remote_uri), "<%s>", ruri);
	/* A chatbot: its SIP URI, or a number capability discovery found one behind. */
	if (bot_on(&r->bot) && (sip_key(number) || g_hash_table_contains(bot_ids, number))) {
		c->bot = 1;
		snprintf(c->bot_id, sizeof(c->bot_id), "%s", sip_key(number) ? number : "");
	}
	local_path(c);
	char *body = sdp(c);
	char extra[1024];
	/* To a chatbot, the chatbot IARI and botversion too (RCC.07 3.6.8, as
	 * remembered: stock's Accept-Contact is built in libsec-ims.so, which has
	 * these tags but not the header as a string). */
	snprintf(extra, sizeof(extra),
		 "Accept-Contact: *;+g.3gpp.icsi-ref=\"%s\"%s\r\n"
		 "P-Preferred-Service: %s\r\n"
		 "Accept: application/sdp\r\n"
		 "Conversation-ID: %s\r\nContribution-ID: %s\r\n",
		 RCS_ICSI_CHAT, c->bot ? ";+g.3gpp.iari-ref=\"" BOT_IARI_SESSION "\";" BOT_VERSION_TAG : "",
		 RCS_ICSI_CHAT_RAW, c->conv_id, c->contrib_id);
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
	char ruri[260];
	key_uri(number, ruri, sizeof(ruri));
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

static int header_has(const struct sipmsg *m, const char *name, const char *what)
{
	char **v = sipmsg_header_all(m, name);
	int hit = 0;
	for (int i = 0; v[i] && !hit; i++)
		hit = strstr(v[i], what) != NULL;
	g_strfreev(v);
	return hit;
}

/* The request is a chatbot's: its Contact has the bot role, or it asks for
 * the chatbot application (stock libsec-ims.so: IsChatbotRole on Contact). */
static int botish(const struct sipmsg *m)
{
	return header_has(m, "Contact", BOT_ROLE_TAG) || header_has(m, "Accept-Contact", "iari.rcs.chatbot") ||
	       header_has(m, "P-Asserted-Service", "iari.rcs.chatbot");
}

struct peer {
	char key[256];        /* +E.164, or a chatbot's sip: URI */
	char bot_id[256];     /* "" unless a chatbot */
	int bot;              /* the request came from a chatbot */
};

/*
 * Who sent m. R9 6.4.1: P-Asserted-Identity before From. R9 7.7.3.1: a tel
 * URI makes it that number's conversation, A2P included; a chatbot known
 * only by its SIP URI is a conversation of its own. A SIP URI on another
 * domain than ours next to the tel URI is the chatbot's service id.
 */
static int peer_of(struct sipua *ua, const struct sipmsg *m, struct peer *p)
{
	memset(p, 0, sizeof(*p));
	p->bot = botish(m);
	GPtrArray *uris = g_ptr_array_new_with_free_func(g_free);
	char **pai = sipmsg_header_all(m, "P-Asserted-Identity");
	for (int i = 0; pai[i]; i++) {
		char u[256];
		if (sip_uri_of(pai[i], u, sizeof(u)))
			g_ptr_array_add(uris, g_strdup(u));
	}
	g_strfreev(pai);
	const char *f = sipmsg_header(m, "From");
	char fu[256];
	if (f && sip_uri_of(f, fu, sizeof(fu)))
		g_ptr_array_add(uris, g_strdup(fu));

	const char *domain = sipua_domain(ua);
	for (guint i = 0; i < uris->len && !p->bot_id[0]; i++) {
		const char *u = g_ptr_array_index(uris, i);
		char k[256];
		if (bot_uri_key(u, k, sizeof(k)) < 0)
			continue;
		/* Not a person on another network: sip:+82...@their.domain is a number. */
		const char *host = strchr(k, '@') + 1;
		char user[64], e[32];
		sip_user_of(k, user, sizeof(user));
		if (p->bot || (g_ascii_strcasecmp(host, domain) && sipua_e164(ua, user, e, sizeof(e)) < 0))
			snprintf(p->bot_id, sizeof(p->bot_id), "%s", k);
	}
	int found = 0;
	for (guint i = 0; i < uris->len && !found; i++) {
		const char *u = g_ptr_array_index(uris, i);
		char user[64];
		if (g_ascii_strncasecmp(u, "tel:", 4))
			continue;
		sip_user_of(u, user, sizeof(user));
		found = sipua_e164(ua, user, p->key, sizeof(p->key)) == 0;
	}
	for (guint i = 0; i < uris->len && !found; i++) {
		const char *u = g_ptr_array_index(uris, i);
		char user[64];
		if (g_ascii_strncasecmp(u, "sip", 3))
			continue;
		/* A person's sip:+82...@domain is their number; never a chatbot's.
		 * Anything else is a chatbot's own conversation (refused when
		 * chatbots are off). */
		char k[256];
		int is_key = bot_uri_key(u, k, sizeof(k)) == 0;
		sip_user_of(u, user, sizeof(user));
		if (!p->bot && !(p->bot_id[0] && is_key && !strcmp(k, p->bot_id)) &&
		    sipua_e164(ua, user, p->key, sizeof(p->key)) == 0) {
			found = 1;
		} else if (is_key) {
			found = 1;
			p->bot = 1;
			snprintf(p->key, sizeof(p->key), "%s", k);
			snprintf(p->bot_id, sizeof(p->bot_id), "%s", k);
		}
	}
	g_ptr_array_free(uris, TRUE);
	if (p->bot_id[0])
		p->bot = 1;
	return found ? 0 : -ENOENT;
}

static void on_invite(struct rcsd *r, struct sipua *ua, const struct sipmsg *m)
{
	struct peer p;
	if (!m->body || !strstr(m->body, "m=message") || peer_of(ua, m, &p) < 0) {
		sipua_respond(ua, m, 488, "Not Acceptable Here", "x", NULL, NULL, NULL);
		return;
	}
	if (p.bot && !bot_on(&r->bot)) {
		/* Nothing chatbot is advertised: stock's "chat bot sessions not allowed". */
		fprintf(stderr, "imsroha-rcs: chat INVITE from chatbot %s refused: chatbots are off\n", p.key);
		sipua_respond(ua, m, 606, "Not Acceptable", "x", NULL, NULL, NULL);
		return;
	}
	const char *number = p.key;
	const char *cid = sipmsg_header(m, "Call-ID");
	if (cid && find_dlg(cid))
		return; /* a retransmission */
	const char *from = sipmsg_header(m, "From");
	char from_uri[sizeof(((struct sipdlg *)0)->remote_uri) - 2] = "";
	if (from && !sip_uri_of(from, from_uri, sizeof(from_uri))) {
		sipua_respond(ua, m, 400, "Bad Request", "x", NULL, NULL, NULL);
		return;
	}
	/* Large message mode (R9 7.7.3.3): a session for one message. */
	int large = header_has(m, "Accept-Contact", "cpm.largemsg") ||
		    header_has(m, "P-Asserted-Service", "cpm.largemsg");
	sipua_respond(ua, m, 100, "Trying", NULL, NULL, NULL, NULL);
	struct chat *c;
	if (large) {
		c = new_chat(r, number);
		c->large = 1;
	} else {
		/* A new session from the same peer replaces the old one. */
		struct chat *old = find(number);
		c = new_chat(r, number);
		if (old) {
			/* Messages still waiting move to the new session. */
			struct outmsg *o;
			while ((o = g_queue_pop_head(&old->queue)))
				g_queue_push_tail(&c->queue, o);
			close_chat(old, 1);
		}
	}
	c->bot = p.bot;
	snprintf(c->bot_id, sizeof(c->bot_id), "%s", p.bot_id);
	c->dlg.uas = 1;
	snprintf(c->dlg.call_id, sizeof(c->dlg.call_id), "%s", cid ? cid : "");
	sip_random(c->dlg.local_tag, 12);
	if (from) {
		sip_param(from, "tag", c->dlg.remote_tag, sizeof(c->dlg.remote_tag));
		snprintf(c->dlg.remote_uri, sizeof(c->dlg.remote_uri), "<%s>", from_uri);
	}
	c->dlg.cseq = 0;
	target_from(&c->dlg, m);
	route_from(&c->dlg, m, 0);
	const char *conv = sipmsg_header(m, "Conversation-ID");
	if (conv) {
		if (!large)
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
	fprintf(stderr, "imsroha-rcs: %s from %s accepted%s\n", large ? "large message" : "chat", number,
		p.bot ? " (chatbot)" : "");
	start_msrp(c);
}

/* An extended bot message we may not take: R9 7.7.4.17.2 (stock answers 606). */
static int xbot_refused(struct rcsd *r, const struct cpim *cp)
{
	char *pct = NULL, *part = NULL, *sugg = NULL;
	size_t plen;
	const char *ct = cp->ctype;
	if (!g_ascii_strcasecmp(ct, "multipart/mixed") &&
	    bot_multipart_split(cp->ctype_full, cp->body, cp->blen, &pct, &part, &plen, &sugg) == 0)
		ct = pct;
	enum bot_kind k = bot_kind_of(ct);
	int refuse = (k == BOT_KIND_XBOT || k == BOT_KIND_OPENRICH) && (!r->bot.xbot || !bot_xbot_version_ok(ct));
	g_free(pct);
	g_free(part);
	g_free(sugg);
	return refuse;
}

static void on_message(struct rcsd *r, struct sipua *ua, const struct sipmsg *m)
{
	const char *ct = sipmsg_header(m, "Content-Type");
	if (!ct || g_ascii_strncasecmp(ct, "message/cpim", 12)) {
		sipua_respond(ua, m, 415, "Unsupported Media Type", "x", "Accept: message/cpim\r\n", NULL, NULL);
		return;
	}
	struct cpim cp;
	int parsed = cpim_parse(m->body ? m->body : "", m->blen, &cp) == 0;
	struct peer p;
	if (peer_of(ua, m, &p) < 0) {
		/* An IMDN needs no peer: R9 7.7.3.3.1's network check gets its 200
		 * whoever it claims to be from (and however its XML looks). */
		if (parsed && !g_ascii_strcasecmp(cp.ctype, "message/imdn+xml")) {
			sipua_respond(ua, m, 200, "OK", "m", NULL, NULL, NULL);
			struct chat tmp = { .r = r };
			on_text(&tmp, &cp);
		} else {
			sipua_respond(ua, m, 415, "Unsupported Media Type", "x", "Accept: message/cpim\r\n", NULL, NULL);
		}
		cpim_clear(&cp);
		return;
	}
	int bot_payload = parsed && (bot_kind_of(cp.ctype) != BOT_KIND_NONE || !g_ascii_strcasecmp(cp.ctype, "multipart/mixed"));
	if ((p.bot || bot_payload) && !bot_on(&r->bot) && !(parsed && !g_ascii_strcasecmp(cp.ctype, "message/imdn+xml"))) {
		/* Stock's "chat bot slm not allowed". */
		fprintf(stderr, "imsroha-rcs: standalone message from %s refused: chatbots are off\n", p.key);
		sipua_respond(ua, m, 606, "Not Acceptable", "x", NULL, NULL, NULL);
		cpim_clear(&cp);
		return;
	}
	if (parsed && bot_on(&r->bot) && xbot_refused(r, &cp)) {
		fprintf(stderr, "imsroha-rcs: standalone %s from %s refused (no such xbotmessage here)\n", cp.ctype, p.key);
		sipua_respond(ua, m, 606, "Not Acceptable", "x", NULL, NULL, NULL);
		cpim_clear(&cp);
		return;
	}
	sipua_respond(ua, m, 200, "OK", "m", NULL, NULL, NULL);
	if (parsed) {
		struct chat tmp = { .r = r, .bot = p.bot };
		snprintf(tmp.number, sizeof(tmp.number), "%s", p.key);
		snprintf(tmp.bot_id, sizeof(tmp.bot_id), "%s", p.bot_id);
		on_text(&tmp, &cp);
	}
	cpim_clear(&cp);
}

void chat_on_request(struct rcsd *r, struct sipua *ua, const struct sipmsg *m)
{
	chat_on_registered(r); /* the tables, want-display loaded once */
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
	if (!want_display) {
		tables();
		want_display_load(r);
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

/* The conversation key of what the app calls a number: +E.164, or a
 * chatbot's sip: URI (parameters dropped) while chatbots are on. */
static gboolean key_of(struct rcsd *r, const char *number, char *key, size_t size, GError **error)
{
	if (!g_ascii_strncasecmp(number, "sip:", 4) || !g_ascii_strncasecmp(number, "sips:", 5)) {
		if (!bot_on(&r->bot)) {
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "chatbots are off or not provisioned");
			return FALSE;
		}
		if (bot_uri_key(number, key, size) == 0)
			return TRUE;
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "not a chatbot URI: %s", number);
		return FALSE;
	}
	if (sipua_e164(r->ua, number, key, size) < 0) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "not a phone number: %s", number);
		return FALSE;
	}
	return TRUE;
}

gboolean rcsd_chat_enqueue(struct rcsd *r, const char *e164, const char *id, char *body, size_t len,
			   GError **error)
{
	if (!ready(r, error)) {
		g_free(body);
		return FALSE;
	}
	chat_on_registered(r);
	struct chat *c = find(e164);
	if (!c && !(c = invite(r, e164))) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "cannot open a chat with %s", e164);
		g_free(body);
		return FALSE;
	}
	/* What imdn_status() knows as ours; a long run starts over rather than grow. */
	if (g_hash_table_size(sent_ids) > 8192)
		g_hash_table_remove_all(sent_ids);
	g_hash_table_add(sent_ids, g_strdup(id));
	struct outmsg *o = g_new0(struct outmsg, 1);
	snprintf(o->id, sizeof(o->id), "%s", id);
	o->body = body;
	o->len = len;
	g_queue_push_tail(&c->queue, o);
	flush(c);
	if (c->state == CHAT_UP)
		touch(c);
	return TRUE;
}

gboolean rcsd_chat_send(struct rcsd *r, const char *number, const char *text, char *id, size_t size,
			GError **error)
{
	char key[256], mid[40];
	if (!ready(r, error) || !key_of(r, number, key, sizeof(key), error))
		return FALSE;
	cpim_msg_id(mid, sizeof(mid));
	size_t len;
	char *body = cpim_text(mid, text, &len);
	if (!rcsd_chat_enqueue(r, key, mid, body, len, error))
		return FALSE;
	snprintf(id, size, "%s", mid);
	return TRUE;
}

gboolean rcsd_chat_suggestion_response(struct rcsd *r, const char *number, const char *in_reply_to,
				       const char *json, char *id, size_t size, GError **error)
{
	char key[256], mid[40];
	if (!ready(r, error))
		return FALSE;
	if (!bot_on(&r->bot)) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "chatbots are off or not provisioned");
		return FALSE;
	}
	if (!key_of(r, number, key, sizeof(key), error))
		return FALSE;
	if (!*json) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "empty response");
		return FALSE;
	}
	/*
	 * RCC.07 3.6.10: the response is a chat message of its own content type
	 * whose JSON carries the postback data. Stock sends it like any message
	 * (Samsung Messages ActionsFactory: content_type botsuggestion.response,
	 * no reference to the message it answers), so in_reply_to stays here.
	 */
	cpim_msg_id(mid, sizeof(mid));
	size_t len;
	char *body = cpim_message(mid, BOT_CT_RESPONSE, json, &len);
	fprintf(stderr, "imsroha-rcs: suggestion response %s to %s (for %s)\n", mid, key, in_reply_to);
	if (!rcsd_chat_enqueue(r, key, mid, body, len, error))
		return FALSE;
	snprintf(id, size, "%s", mid);
	return TRUE;
}

gboolean rcsd_chat_composing(struct rcsd *r, const char *number, gboolean active, GError **error)
{
	char key[256];
	if (!ready(r, error) || !key_of(r, number, key, sizeof(key), error))
		return FALSE;
	/* Only inside a session: no session is opened for it, nothing is stored (R9 7.2.3). */
	struct chat *c = find(key);
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
	const char *v = want_display ? g_hash_table_lookup(want_display, id) : NULL;
	if (!v) {
		fprintf(stderr, "imsroha-rcs: %s read; no displayed notification was asked for\n", id);
		return TRUE;
	}
	char *n = g_strndup(v, strcspn(v, "\t"));
	g_hash_table_remove(want_display, id);
	want_display_save();
	fprintf(stderr, "imsroha-rcs: %s read; sending displayed\n", id);
	send_imdn(r, n, id, "displayed");
	g_free(n);
	return TRUE;
}

/* ---- capabilities: presence anonymous fetch (R9 6.5), or OPTIONS ----------- */

struct capq {
	struct rcsd *r;
	GDBusMethodInvocation *inv;
	struct sipdlg dlg;
	char key[256];
	guint timer;
	int replied, tx_done;
};

static GList *capqs;

struct caps {
	int known, chat, ft, chatbot, code;
	char bot_id[256];
};

static void cap_reply(struct capq *q, const struct caps *k)
{
	if (q->replied)
		return;
	q->replied = 1;
	if (q->timer)
		g_source_remove(q->timer);
	q->timer = 0;
	int bots = bot_on(&q->r->bot);
	/* R9 7.7.3.2: the service id behind a number, for its A2P messages. */
	if (bots && k->chatbot && k->bot_id[0] && !sip_key(q->key)) {
		chat_on_registered(q->r); /* the tables, want-display loaded once */
		g_hash_table_replace(bot_ids, g_strdup(q->key), g_strdup(k->bot_id));
	}
	GVariantBuilder b;
	g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(&b, "{sv}", "known", g_variant_new_boolean(k->known));
	g_variant_builder_add(&b, "{sv}", "chat", g_variant_new_boolean(k->chat));
	g_variant_builder_add(&b, "{sv}", "ft-http", g_variant_new_boolean(k->ft));
	/* The peer is a chatbot (it has the bot role, RCC.07's isbot); phones
	 * that merely talk to chatbots are not. */
	g_variant_builder_add(&b, "{sv}", "chatbot", g_variant_new_boolean(bots && k->chatbot));
	if (bots && k->chatbot && k->bot_id[0])
		g_variant_builder_add(&b, "{sv}", "bot-id", g_variant_new_string(k->bot_id));
	if (k->code)
		g_variant_builder_add(&b, "{sv}", "sip-status", g_variant_new_int32(k->code));
	g_dbus_method_invocation_return_value(q->inv, g_variant_new("(a{sv})", &b));
}

static void cap_maybe_free(struct capq *q)
{
	if (!q->replied || !q->tx_done)
		return;
	capqs = g_list_remove(capqs, q);
	g_free(q);
}

/* A tuple whose service-id is exactly this and whose basic status is open. */
static int pidf_has(const char *body, const char *service)
{
	char *want = g_strdup_printf(">%s<", service);
	int hit = 0;
	const char *p = body;
	while (!hit && p && (p = strstr(p, want))) {
		const char *t = g_strrstr_len(body, p - body, "<tuple");
		const char *e = strstr(p, "</tuple>");
		if (t && e) {
			char *tuple = g_strndup(t, (gsize)(e - t));
			hit = strstr(tuple, "<basic>open</basic>") != NULL;
			g_free(tuple);
		}
		p += strlen(want);
	}
	g_free(want);
	return hit;
}

static gboolean on_cap_timeout(gpointer p)
{
	struct capq *q = p;
	q->timer = 0;
	struct caps k = { 0 };
	cap_reply(q, &k);
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
	struct caps k = { .known = m != NULL, .code = m ? m->code : 0 };
	if (m && m->code >= 200 && m->code < 300) {
		char **cs = sipmsg_header_all(m, "Contact");
		for (int i = 0; cs[i]; i++) {
			k.chat |= strstr(cs[i], "oma.cpm.session") != NULL;
			k.ft |= strstr(cs[i], "rcs.fthttp") != NULL;
			k.chatbot |= strstr(cs[i], BOT_ROLE_TAG) != NULL;
		}
		g_strfreev(cs);
		/* Stock OptionsRequestController: a bot's service id is the SIP
		 * URI in the answer's P-Asserted-Identity. */
		char **pai = sipmsg_header_all(m, "P-Asserted-Identity");
		for (int i = 0; k.chatbot && pai[i] && !k.bot_id[0]; i++) {
			char u[256];
			if (sip_uri_of(pai[i], u, sizeof(u)) && bot_uri_key(u, k.bot_id, sizeof(k.bot_id)) < 0)
				k.bot_id[0] = '\0';
		}
		g_strfreev(pai);
		if (k.chatbot && !k.bot_id[0] && sip_key(q->key))
			snprintf(k.bot_id, sizeof(k.bot_id), "%s", q->key);
	}
	cap_reply(q, &k);
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
		struct caps k = { 0 };
		cap_reply(q, &k);
	} else if (m->code < 300) {
		/* The answer is the NOTIFY that follows. */
		if (!q->replied && !q->timer)
			q->timer = g_timeout_add_seconds(32, on_cap_timeout, q);
	} else {
		/* No such RCS user (404, 410, 480, 603, 604), or we do not know. */
		int no = m->code == 404 || m->code == 410 || m->code == 480 || m->code == 603 || m->code == 604;
		struct caps k = { .known = no, .code = m->code };
		cap_reply(q, &k);
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
	struct caps k = { .known = 1 };
	k.chat = pidf_has(body, "org.openmobilealliance:ChatSession");
	k.ft = pidf_has(body, "org.openmobilealliance:File-Transfer-HTTP");
	k.chatbot = pidf_has(body, BOT_SID_ROLE);
	/* R9 7.7.3.2, stock PresenceUpdate: a chatbot's service id is the PIDF's entity. */
	const char *ent = strstr(body, "entity=\"");
	if (k.chatbot && ent) {
		ent += 8;
		char u[256];
		snprintf(u, sizeof(u), "%.*s", (int)strcspn(ent, "\""), ent);
		if (bot_uri_key(u, k.bot_id, sizeof(k.bot_id)) < 0)
			k.bot_id[0] = '\0';
	}
	if (k.chatbot && !k.bot_id[0] && sip_key(q->key))
		snprintf(k.bot_id, sizeof(k.bot_id), "%s", q->key);
	cap_reply(q, &k);
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
		struct caps k = { 0 };
		cap_reply(q, &k);
		cap_maybe_free(q);
	}
}

void rcsd_capabilities(struct rcsd *r, const char *number, GDBusMethodInvocation *inv)
{
	GError *e = NULL;
	char key[256];
	if (!ready(r, &e)) {
		g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_NOT_READY, e->message);
		g_error_free(e);
		return;
	}
	if (!key_of(r, number, key, sizeof(key), &e)) {
		g_dbus_method_invocation_return_dbus_error(
			inv, g_error_matches(e, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED) ? RCSD_ERROR_NOT_AVAILABLE : RCSD_ERROR_FAILED,
			e->message);
		g_error_free(e);
		return;
	}
	struct capq *q = g_new0(struct capq, 1);
	q->r = r;
	q->inv = inv;
	snprintf(q->key, sizeof(q->key), "%s", key);
	char ruri[260];
	key_uri(key, ruri, sizeof(ruri));
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
