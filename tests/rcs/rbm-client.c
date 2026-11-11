// SPDX-License-Identifier: GPL-3.0-only
/*
 * The chatbot half of the app contract (codes.noa.IMSroha.Rcs), against
 * tests/rcs/fake-pcscf.py --rbm on and fake-botinfo.py:
 *   capabilities of two bots, an A2P number and a phone ("chatbot", "bot-id");
 *   A2P in pager and large message mode into the number's thread, and no
 *   status for R9 7.7.3.3.1's network check;
 *   a chat to sip:bot@...: a rich card, an extended bot message, a carousel
 *   with suggestions, and our SendSuggestionResponse, sent and delivered;
 *   a chat from sip:bot2@...: text with suggestions, plain text;
 *   GetBotInfo: fetched, cached, revalidated, unknown.
 * Every signal's arguments are checked exactly. "off": [rcs] chatbot=false,
 * every chatbot method refused. $RBM_DIR holds the JSON the network sends.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gio/gio.h>

#define NAME "codes.noa.IMSroha.Rcs"
#define PATH "/codes/noa/IMSroha/Rcs"
#define IFACE "codes.noa.IMSroha.Rcs"
/* 2026-11-11T12:00:00.000Z, the CPIM DateTime of everything the fake network sends */
#define TS 1794398400000LL

static GDBusConnection *bus;
static GMainLoop *loop;
static char state[32];
static int timed_out, fails;
static GHashTable *events; /* "status <id> <st>", "rich <id>", "text <id>" -> the signal's arguments */

#define CHECK(c, ...) do { if (!(c)) { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; } } while (0)

static char *payload(const char *name)
{
	char *path = g_build_filename(getenv("RBM_DIR"), name, NULL), *s = NULL;
	if (!g_file_get_contents(path, &s, NULL, NULL))
		printf("FAIL: cannot read %s\n", path);
	g_free(path);
	return s ? s : g_strdup("");
}

static void on_signal(GDBusConnection *c, const char *sender, const char *path, const char *iface,
		      const char *sig, GVariant *p, gpointer ud)
{
	(void)c; (void)sender; (void)path; (void)iface; (void)ud;
	if (!strcmp(sig, "StateChanged")) {
		const char *s;
		g_variant_get(p, "(&s)", &s);
		snprintf(state, sizeof(state), "%s", s);
	} else if (!strcmp(sig, "MessageStatusChanged")) {
		const char *id, *st;
		g_variant_get(p, "(&s&s)", &id, &st);
		printf("status %s %s\n", id, st);
		g_hash_table_replace(events, g_strdup_printf("status %s %s", id, st), g_variant_ref(p));
	} else if (!strcmp(sig, "RichMessageReceived")) {
		const char *n, *id, *ct, *body, *sugg, *bot;
		gint64 ts;
		g_variant_get(p, "(&s&s&s&s&s&sx)", &n, &id, &ct, &body, &sugg, &bot, &ts);
		printf("rich from %s id %s: %s, %zu bytes, suggestions %zu bytes, bot %s\n", n, id, ct, strlen(body),
		       strlen(sugg), bot);
		g_hash_table_replace(events, g_strdup_printf("rich %s", id), g_variant_ref(p));
	} else if (!strcmp(sig, "MessageReceived")) {
		const char *n, *id, *t;
		gint64 ts;
		g_variant_get(p, "(&s&s&sx)", &n, &id, &t, &ts);
		printf("text from %s id %s: %s\n", n, id, t);
		g_hash_table_replace(events, g_strdup_printf("text %s", id), g_variant_ref(p));
	}
	g_main_loop_quit(loop);
}

static gboolean on_deadline(gpointer ud)
{
	(void)ud;
	timed_out = 1;
	g_main_loop_quit(loop);
	return G_SOURCE_REMOVE;
}

static GVariant *wait_event(const char *ev)
{
	timed_out = 0;
	guint t = g_timeout_add_seconds(20, on_deadline, NULL);
	while (!timed_out && !g_hash_table_contains(events, ev))
		g_main_loop_run(loop);
	if (!timed_out)
		g_source_remove(t);
	else
		printf("FAIL: no %s\n", ev);
	return g_hash_table_lookup(events, ev);
}

static int wait_registered(void)
{
	GVariant *st = g_dbus_connection_call_sync(bus, NAME, PATH, "org.freedesktop.DBus.Properties", "Get",
						   g_variant_new("(ss)", IFACE, "State"), G_VARIANT_TYPE("(v)"),
						   G_DBUS_CALL_FLAGS_NONE, 5000, NULL, NULL);
	if (st) {
		GVariant *v;
		g_variant_get(st, "(v)", &v);
		snprintf(state, sizeof(state), "%s", g_variant_get_string(v, NULL));
		g_variant_unref(v);
		g_variant_unref(st);
	}
	timed_out = 0;
	guint t = g_timeout_add_seconds(20, on_deadline, NULL);
	while (!timed_out && strcmp(state, "registered"))
		g_main_loop_run(loop);
	if (!timed_out)
		g_source_remove(t);
	else
		printf("FAIL: never registered\n");
	return timed_out ? -1 : 0;
}

/* A call; *err gets the D-Bus error name when it fails. */
static GVariant *call(const char *method, GVariant *args, const char *rtype, char **err)
{
	GError *e = NULL;
	GVariant *v = g_dbus_connection_call_sync(bus, NAME, PATH, IFACE, method, args,
						  rtype ? G_VARIANT_TYPE(rtype) : NULL, G_DBUS_CALL_FLAGS_NONE,
						  40000, NULL, &e);
	if (!v) {
		if (err)
			*err = g_dbus_error_get_remote_error(e);
		else
			printf("FAIL: %s: %s\n", method, e->message);
		g_error_free(e);
	}
	return v;
}

static void rich_is(const char *id, const char *number, const char *ctype, const char *body, const char *sugg,
		    const char *bot)
{
	char *ev = g_strdup_printf("rich %s", id);
	GVariant *p = wait_event(ev);
	g_free(ev);
	if (!p)
		return;
	const char *n, *i, *ct, *b, *s, *bt;
	gint64 ts;
	g_variant_get(p, "(&s&s&s&s&s&sx)", &n, &i, &ct, &b, &s, &bt, &ts);
	CHECK(!strcmp(n, number), "%s: number %s, not %s", id, n, number);
	CHECK(!strcmp(ct, ctype), "%s: content type %s, not %s", id, ct, ctype);
	CHECK(!strcmp(b, body), "%s: the body is not what the network sent:\n%s", id, b);
	CHECK(!strcmp(s, sugg), "%s: suggestions are not what the network sent:\n%s", id, s);
	CHECK(!strcmp(bt, bot), "%s: bot_id %s, not %s", id, bt, bot);
	CHECK(ts == TS, "%s: timestamp %lld", id, (long long)ts);
}

static void caps_are(const char *number, int chatbot, const char *bot_id)
{
	GVariant *r = call("GetCapabilities", g_variant_new("(s)", number), "(a{sv})", NULL);
	if (!r) {
		fails++;
		return;
	}
	GVariant *c = g_variant_get_child_value(r, 0);
	gboolean cb = FALSE, chat = FALSE;
	const char *id = "";
	g_variant_lookup(c, "chatbot", "b", &cb);
	g_variant_lookup(c, "chat", "b", &chat);
	g_variant_lookup(c, "bot-id", "&s", &id);
	printf("capabilities of %s: chat %d chatbot %d bot-id %s\n", number, chat, cb, id);
	CHECK(chat, "%s: no chat", number);
	CHECK(cb == chatbot, "%s: chatbot %d", number, cb);
	CHECK(!strcmp(id, bot_id), "%s: bot-id %s, not %s", number, id, bot_id);
	g_variant_unref(c);
	g_variant_unref(r);
}

static void botinfo_is(const char *bot, const char *file)
{
	GVariant *r = call("GetBotInfo", g_variant_new("(s)", bot), "(s)", NULL);
	if (!r) {
		fails++;
		return;
	}
	char *want = payload(file);
	const char *got;
	g_variant_get(r, "(&s)", &got);
	CHECK(!strcmp(got, want), "GetBotInfo %s: not the server's JSON:\n%s", bot, got);
	g_free(want);
	g_variant_unref(r);
}

static void refused(const char *method, GVariant *args, const char *want)
{
	char *err = NULL;
	GVariant *r = call(method, args, NULL, &err);
	CHECK(!r && err && !strcmp(err, want), "%s: %s, not %s", method, r ? "taken" : err ? err : "?", want);
	printf("%s refused: %s\n", method, err ? err : "-");
	if (r)
		g_variant_unref(r);
	g_free(err);
}

static int off(void)
{
	const char *na = "codes.noa.IMSroha.Rcs.Error.NotAvailable";
	refused("SendMessage", g_variant_new("(ss)", "sip:bot@botplatform.test", "hi"), na);
	refused("SendSuggestionResponse", g_variant_new("(sss)", "sip:bot@botplatform.test", "x", "{}"), na);
	refused("GetBotInfo", g_variant_new("(s)", "sip:bot@botplatform.test"), na);
	refused("GetCapabilities", g_variant_new("(s)", "sip:bot@botplatform.test"), na);
	/* A person's message still comes. */
	GVariant *p = wait_event("text off2");
	CHECK(p, "no message from the person");
	CHECK(!g_hash_table_contains(events, "rich off1"), "a chatbot message came through");
	return fails ? 1 : 0;
}

int main(int argc, char **argv)
{
	GError *e = NULL;
	bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &e);
	if (!bus)
		return 2;
	loop = g_main_loop_new(NULL, FALSE);
	events = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_variant_unref);
	g_dbus_connection_signal_subscribe(bus, NULL, IFACE, NULL, PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
					   on_signal, NULL, NULL);
	if (wait_registered())
		return 1;
	if (argc > 1 && !strcmp(argv[1], "off")) {
		int rc = off();
		printf(rc ? "client: FAILED\n" : "client: all steps passed\n");
		return rc;
	}

	/* ---- capabilities: "chatbot" is the bot role, not the chatbot tuple a phone has too ---- */
	caps_are("sip:bot@botplatform.test;tk=on", 1, "sip:bot@botplatform.test");
	caps_are("+821000000001", 0, "");
	/* R9 7.7.3.2: the service id behind an A2P number, from the NOTIFY's entity.
	 * The fake network sends that number's A2P traffic after this. */
	caps_are("015-8800-00", 1, "sip:a2p@botplatform.test");

	/* ---- A2P from tel:+8215880000: its number's thread (R9 7.7.3.1) ---- */
	char *open_card = payload("openrichcard.json"), *card = payload("richcard.json");
	rich_is("rbm6", "+8215880000", "application/vnd.gsma.openrichcard.v1.0+json", open_card, "",
		"sip:a2p@botplatform.test");
	rich_is("rbm7", "+8215880000", "application/vnd.gsma.botmessage.v1.0+json", card, "", "sip:a2p@botplatform.test");
	GVariant *r = call("MarkDisplayed", g_variant_new("(ss)", "+8215880000", "rbm6"), NULL, NULL);
	if (r)
		g_variant_unref(r);

	/* ---- a chat to a chatbot ---- */
	if (!(r = call("SendMessage", g_variant_new("(ss)", "sip:bot@botplatform.test", "hello bot"), "(s)", NULL)))
		return 1;
	const char *mid;
	g_variant_get(r, "(&s)", &mid);
	char *sent = g_strdup_printf("status %s sent", mid), *dlv = g_strdup_printf("status %s delivered", mid);
	g_variant_unref(r);
	CHECK(wait_event(sent) && wait_event(dlv), "our message to the bot");
	g_free(sent);
	g_free(dlv);
	char *xbot = payload("xbotmessage.json"), *carousel = payload("carousel.json"), *sugg = payload("suggestions.json");
	rich_is("rbm1", "sip:bot@botplatform.test", "application/vnd.gsma.botmessage.v1.0+json", card, "",
		"sip:bot@botplatform.test");
	rich_is("rbm2", "sip:bot@botplatform.test", "application/vnd.gsma.xbotmessage.v1.0+json", xbot, "",
		"sip:bot@botplatform.test");
	rich_is("rbm3", "sip:bot@botplatform.test", "application/vnd.gsma.botmessage.v1.0+json", carousel, sugg,
		"sip:bot@botplatform.test");
	char *resp = payload("response.json");
	if (!(r = call("SendSuggestionResponse", g_variant_new("(sss)", "sip:bot@botplatform.test", "rbm3", resp), "(s)",
			NULL)))
		return 1;
	g_variant_get(r, "(&s)", &mid);
	sent = g_strdup_printf("status %s sent", mid);
	dlv = g_strdup_printf("status %s delivered", mid);
	g_variant_unref(r);
	CHECK(wait_event(sent) && wait_event(dlv), "the suggestion response's status");
	g_free(sent);
	g_free(dlv);

	/* ---- a chat from a chatbot (the network opens it after our response) ---- */
	rich_is("rbm4", "sip:bot2@botplatform.test", "text/plain", "무엇을 도와드릴까요?", sugg, "sip:bot2@botplatform.test");
	GVariant *t = wait_event("text rbm5");
	if (t) {
		const char *n, *id, *txt;
		gint64 ts;
		g_variant_get(t, "(&s&s&sx)", &n, &id, &txt, &ts);
		CHECK(!strcmp(n, "sip:bot2@botplatform.test") && !strcmp(txt, "just text") && ts == TS,
		      "rbm5: %s %s %lld", n, txt, (long long)ts);
	}

	/* ---- botinfo: fetched, cached (max-age), revalidated (no-cache + ETag), unknown ---- */
	botinfo_is("sip:bot@botplatform.test", "botinfo-bot.json");
	botinfo_is("sip:bot@botplatform.test;tk=on", "botinfo-bot.json");
	botinfo_is("sip:bot2@botplatform.test", "botinfo-bot2.json");
	botinfo_is("sip:bot2@botplatform.test", "botinfo-bot2.json");
	refused("GetBotInfo", g_variant_new("(s)", "sip:nobody@botplatform.test"), "codes.noa.IMSroha.Rcs.Error.NotAvailable");
	refused("GetBotInfo", g_variant_new("(s)", "tel:+8215880000"), "codes.noa.IMSroha.Rcs.Error.NotAvailable");

	/* The network check (R9 7.7.3.3.1) came before all of the A2P traffic: no status for it. */
	GHashTableIter it;
	gpointer k;
	g_hash_table_iter_init(&it, events);
	while (g_hash_table_iter_next(&it, &k, NULL))
		CHECK(!strstr(k, "bodiless"), "a status for the network check: %s", (char *)k);
	CHECK(!g_hash_table_contains(events, "rich rbm-x13"), "an xbotmessage v1.3 came through");

	g_free(open_card);
	g_free(card);
	g_free(xbot);
	g_free(carousel);
	g_free(sugg);
	g_free(resp);
	printf(fails ? "client: FAILED\n" : "client: all steps passed\n");
	return fails ? 1 : 0;
}
