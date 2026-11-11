// SPDX-License-Identifier: GPL-3.0-only
/*
 * GetBotInfo: the chatbot information (RCC.07 3.6.4.1, R9 7.7.2 and
 * 7.7.3.2) from BotinfoFQDNRoot, or the bot's own domain when the
 * configuration names none. The JSON goes to the app as the server sent it,
 * R9's extra fields (bot-a2p-cd, uri-entry, subTitle, menus...) included.
 *
 * HTTPS with the certificate checked against the system store (stock's bot
 * client can trust any CA for some hosts; this does not). Kept in memory per
 * service id as long as Cache-Control's max-age says, revalidated with
 * If-None-Match when the server gave an ETag. The request blocks, so it runs
 * in a worker thread and answers on the main loop.
 */
#include <stdio.h>
#include <string.h>

#include "bot.h"
#include "http.h"
#include "rcsd.h"

#define BOTINFO_TIMEOUT 20
/* RCC.07 profile version of stock's bot API for Korea: globalsettings.json
 * bot_rcc07_version 11.0 -> Samsung Messages BotVersion.V11, profile 3. */
#define BOTINFO_V 3

struct entry {
	char *json;
	char *etag;
	gint64 fresh_until;     /* monotonic µs */
};

struct job {
	struct rcsd *r;
	GDBusMethodInvocation *inv;
	GCancellable *cancel;
	char key[256];
	char host[256];
	uint16_t port;
	char *req;
	struct http_response resp;
	int rc;
};

static GHashTable *cache; /* service id -> struct entry */
static GList *jobs;

static void entry_free(gpointer p)
{
	struct entry *e = p;
	g_free(e->json);
	g_free(e->etag);
	g_free(e);
}

static void job_free(struct job *j)
{
	jobs = g_list_remove(jobs, j);
	g_clear_object(&j->cancel);
	g_free(j->req);
	http_response_clear(&j->resp);
	g_free(j);
}

static void fail(GDBusMethodInvocation *inv, const char *fmt, const char *arg)
{
	char *m = g_strdup_printf(fmt, arg);
	g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_NOT_AVAILABLE, m);
	g_free(m);
}

static void freshness(struct entry *e, const struct http_response *resp)
{
	long age = bot_max_age(http_header(resp, "Cache-Control"));
	/* No max-age: nothing to go by, so the next call asks again (with the ETag). */
	e->fresh_until = g_get_monotonic_time() + (age > 0 ? (gint64)age * G_USEC_PER_SEC : 0);
}

static void fetch_thread(GTask *t, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)src;
	struct job *j = data;
	j->rc = http_exchange(&j->r->cfg, j->host, j->port, 1, j->req, BOTINFO_TIMEOUT, cancel, &j->resp);
	g_task_return_boolean(t, TRUE);
}

static void fetch_done(GObject *src, GAsyncResult *res, gpointer p)
{
	(void)src; (void)res;
	struct job *j = p;
	struct entry *old = g_hash_table_lookup(cache, j->key);
	int st = j->resp.status;
	if (st == 200) {
		if (!g_utf8_validate(j->resp.body, (gssize)j->resp.len, NULL) || strlen(j->resp.body) != j->resp.len) {
			fail(j->inv, "botinfo for %s: the answer is not UTF-8 text", j->key);
		} else {
			struct entry *e = g_new0(struct entry, 1);
			e->json = g_strdup(j->resp.body);
			const char *tag = http_header(&j->resp, "ETag");
			e->etag = tag ? g_strdup(tag) : NULL;
			freshness(e, &j->resp);
			g_hash_table_replace(cache, g_strdup(j->key), e);
			fprintf(stderr, "imsroha-rcs: botinfo for %s: %zu bytes\n", j->key, j->resp.len);
			g_dbus_method_invocation_return_value(j->inv, g_variant_new("(s)", e->json));
		}
	} else if (st == 304 && old) {
		freshness(old, &j->resp);
		fprintf(stderr, "imsroha-rcs: botinfo for %s: not modified\n", j->key);
		g_dbus_method_invocation_return_value(j->inv, g_variant_new("(s)", old->json));
	} else if (st) {
		char code[16];
		snprintf(code, sizeof(code), "%d", st);
		fprintf(stderr, "imsroha-rcs: botinfo for %s: HTTP %d\n", j->key, st);
		fail(j->inv, "botinfo: HTTP %s", code);
	} else {
		fprintf(stderr, "imsroha-rcs: botinfo for %s: %s\n", j->key, j->resp.error);
		fail(j->inv, "botinfo: %s", j->resp.error[0] ? j->resp.error : "no answer");
	}
	job_free(j);
}

void rcsd_botinfo(struct rcsd *r, const char *bot_id, GDBusMethodInvocation *inv)
{
	if (!bot_on(&r->bot)) {
		g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_NOT_AVAILABLE,
							   "chatbots are off or not provisioned");
		return;
	}
	if (!cache)
		cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, entry_free);
	struct job *j = g_new0(struct job, 1);
	if (bot_uri_key(bot_id, j->key, sizeof(j->key)) < 0) {
		g_free(j);
		g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_NOT_AVAILABLE, "not a chatbot service id");
		return;
	}
	struct entry *e = g_hash_table_lookup(cache, j->key);
	if (e && g_get_monotonic_time() < e->fresh_until) {
		g_dbus_method_invocation_return_value(inv, g_variant_new("(s)", e->json));
		g_free(j);
		return;
	}
	char ua[256];
	rcs_config_expand_ua(&r->cfg, r->cfg.http_user_agent, ua, sizeof(ua));
	j->req = bot_info_request(r->bot.root, j->key, r->cfg.accept_language, r->id.mcc, r->id.mnc, BOTINFO_V, ua,
				  e ? e->etag : NULL, j->host, sizeof(j->host), &j->port);
	if (!j->req) {
		g_free(j);
		g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_NOT_AVAILABLE,
							   "no botinfo server for this service id");
		return;
	}
	j->r = r;
	j->inv = inv;
	j->cancel = g_cancellable_new();
	jobs = g_list_prepend(jobs, j);
	fprintf(stderr, "imsroha-rcs: botinfo for %s from %s\n", j->key, j->host);
	GTask *t = g_task_new(NULL, j->cancel, fetch_done, j);
	g_task_set_task_data(t, j, NULL);
	g_task_run_in_thread(t, fetch_thread);
	g_object_unref(t);
}

void rcsd_botinfo_shutdown(struct rcsd *r)
{
	(void)r;
	for (GList *l = jobs; l; l = l->next)
		g_cancellable_cancel(((struct job *)l->data)->cancel);
}
