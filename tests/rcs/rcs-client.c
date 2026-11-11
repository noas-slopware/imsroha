// SPDX-License-Identifier: GPL-3.0-only
/*
 * Drives imsroha-rcs over codes.noa.IMSroha.Rcs on the test's session bus,
 * the way Spacebar would, against tests/rcs/fake-pcscf.py:
 *   registered -> SendMessage -> sent, delivered -> SetComposing ->
 *   MessageReceived from the second number -> MarkDisplayed -> GetCapabilities,
 * then file transfer: FileReceived for the file-info the network sent with
 * that chat, FileReceiveFailed for the three it must refuse, and SendFile
 * ($RCS_FT_SMALL to the content server, $RCS_FT_LARGE to the large one, sent
 * and delivered; $RCS_FT_HUGE, /dev/null and a relative path refused).
 * Every wait has a deadline; a missed one fails the test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gio/gio.h>

#define NAME "codes.noa.IMSroha.Rcs"
#define PATH "/codes/noa/IMSroha/Rcs"
#define IFACE "codes.noa.IMSroha.Rcs"

static GDBusConnection *bus;
static GMainLoop *loop;
static char state[32];
static char sent_id[64];
static int got_sent, got_delivered, got_message, composing_seen;
static char mt_number[32], mt_id[64], mt_text[128];
static int timed_out;
static GHashTable *events; /* "status <id> <status>", "file <id>", "file-failed <id> <reason>" */
static void event(char *s)
{
	g_hash_table_add(events, s);
}

static void on_signal(GDBusConnection *c, const char *sender, const char *path, const char *iface,
		      const char *sig, GVariant *p, gpointer ud)
{
	(void)c; (void)sender; (void)path; (void)iface; (void)ud;
	if (!strcmp(sig, "StateChanged")) {
		const char *s;
		g_variant_get(p, "(&s)", &s);
		snprintf(state, sizeof(state), "%s", s);
		printf("state %s\n", s);
	} else if (!strcmp(sig, "MessageStatusChanged")) {
		const char *id, *st;
		g_variant_get(p, "(&s&s)", &id, &st);
		printf("status %s %s\n", !strcmp(id, sent_id) ? "<ours>" : id, st);
		if (!strcmp(id, sent_id) && !strcmp(st, "sent"))
			got_sent = 1;
		if (!strcmp(id, sent_id) && !strcmp(st, "delivered"))
			got_delivered = 1;
		event(g_strdup_printf("status %s %s", id, st));
	} else if (!strcmp(sig, "MessageReceived")) {
		const char *n, *id, *t;
		gint64 ts;
		g_variant_get(p, "(&s&s&sx)", &n, &id, &t, &ts);
		printf("received from %s id %s: %s (ts %lld)\n", n, id, t, (long long)ts);
		snprintf(mt_number, sizeof(mt_number), "%s", n);
		snprintf(mt_id, sizeof(mt_id), "%s", id);
		snprintf(mt_text, sizeof(mt_text), "%s", t);
		got_message = 1;
	} else if (!strcmp(sig, "FileReceived")) {
		const char *n, *id, *path, *ct, *thumb;
		guint64 size;
		gint64 ts;
		g_variant_get(p, "(&s&s&s&st&sx)", &n, &id, &path, &ct, &size, &thumb, &ts);
		printf("file-received from %s id %s: %s (%s, %llu bytes) thumbnail %s\n", n, id, path, ct,
		       (unsigned long long)size, thumb);
		event(g_strdup_printf("file %s", id));
	} else if (!strcmp(sig, "FileReceiveFailed")) {
		const char *n, *id, *why;
		g_variant_get(p, "(&s&s&s)", &n, &id, &why);
		printf("file-failed from %s id %s: %s\n", n, id, why);
		event(g_strdup_printf("file-failed %s %s", id, why));
	} else if (!strcmp(sig, "ComposingChanged")) {
		composing_seen = 1;
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

/* Runs the loop until *flag (or the state) is what we want, or 20 s pass. */
static int wait_for(int *flag, const char *want_state, const char *what)
{
	timed_out = 0;
	guint t = g_timeout_add_seconds(20, on_deadline, NULL);
	while (!timed_out && !(flag ? *flag : !strcmp(state, want_state)))
		g_main_loop_run(loop);
	if (!timed_out)
		g_source_remove(t);
	if (timed_out)
		printf("FAIL: no %s\n", what);
	return timed_out ? -1 : 0;
}

/* Runs the loop until the event is in, or 20 s pass. */
static int wait_event(const char *ev)
{
	timed_out = 0;
	guint t = g_timeout_add_seconds(20, on_deadline, NULL);
	while (!timed_out && !g_hash_table_contains(events, ev))
		g_main_loop_run(loop);
	if (!timed_out)
		g_source_remove(t);
	else
		printf("FAIL: no %s\n", ev);
	return timed_out ? -1 : 0;
}

static GVariant *call(const char *method, GVariant *args, const char *rtype)
{
	GError *e = NULL;
	GVariant *v = g_dbus_connection_call_sync(bus, NAME, PATH, IFACE, method, args,
						  rtype ? G_VARIANT_TYPE(rtype) : NULL, G_DBUS_CALL_FLAGS_NONE,
						  30000, NULL, &e);
	if (!v) {
		printf("FAIL: %s: %s\n", method, e->message);
		g_error_free(e);
	}
	return v;
}

int main(void)
{
	GError *e = NULL;
	bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &e);
	if (!bus)
		return 2;
	loop = g_main_loop_new(NULL, FALSE);
	events = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	g_dbus_connection_signal_subscribe(bus, NULL, IFACE, NULL, PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
					   on_signal, NULL, NULL);
	/* The daemon may already be registered: ask once, then follow the signals. */
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
	if (wait_for(NULL, "registered", "registration"))
		return 1;

	GVariant *r = call("SendMessage", g_variant_new("(ss)", "010-0000-0001", "hello"), "(s)");
	if (!r)
		return 1;
	const char *id;
	g_variant_get(r, "(&s)", &id);
	snprintf(sent_id, sizeof(sent_id), "%s", id);
	g_variant_unref(r);
	printf("sent id %s\n", sent_id[0] ? "<ours>" : "none");
	if (wait_for(&got_sent, NULL, "\"sent\"") || wait_for(&got_delivered, NULL, "\"delivered\""))
		return 1;

	if (!(r = call("SetComposing", g_variant_new("(sb)", "01000000001", TRUE), NULL)))
		return 1;
	g_variant_unref(r);
	if (wait_for(&got_message, NULL, "message from the second number"))
		return 1;
	if (strcmp(mt_number, "+821000000002") || strcmp(mt_text, "hi from 2") || strcmp(mt_id, "mt1")) {
		printf("FAIL: wrong message\n");
		return 1;
	}
	if (!(r = call("MarkDisplayed", g_variant_new("(ss)", mt_number, mt_id), NULL)))
		return 1;
	g_variant_unref(r);

	if (!(r = call("GetCapabilities", g_variant_new("(s)", "+821000000001"), "(a{sv})")))
		return 1;
	GVariant *caps = g_variant_get_child_value(r, 0);
	gboolean chat = FALSE, known = FALSE;
	g_variant_lookup(caps, "chat", "b", &chat);
	g_variant_lookup(caps, "known", "b", &known);
	printf("capabilities of +821000000001: known %d chat %d\n", known, chat);
	g_variant_unref(caps);
	g_variant_unref(r);
	if (!chat)
		return 1;

	/* ---- file transfer ---- */
	if (wait_event("file mtft1") || wait_event("file-failed mtft2 expired") ||
	    wait_event("file-failed mtft3 too-large") || wait_event("file-failed mtft4 unauthorized"))
		return 1;
	const char *sends[] = { "RCS_FT_SMALL", "RCS_FT_LARGE" };
	for (size_t i = 0; i < G_N_ELEMENTS(sends); i++) {
		const char *path = getenv(sends[i]);
		if (!path || !(r = call("SendFile", g_variant_new("(ss)", "010-0000-0001", path), "(s)")))
			return 1;
		const char *fid;
		g_variant_get(r, "(&s)", &fid);
		char *sent = g_strdup_printf("status %s sent", fid), *dlv = g_strdup_printf("status %s delivered", fid);
		g_variant_unref(r);
		int bad = wait_event(sent) || wait_event(dlv);
		printf("%s: sent and delivered\n", sends[i]);
		g_free(sent);
		g_free(dlv);
		if (bad)
			return 1;
	}
	/* Refused at once: too large for either server, not a regular file, not absolute. */
	const char *refuse[] = { getenv("RCS_FT_HUGE"), "/dev/null", "relative/file" };
	for (size_t i = 0; i < G_N_ELEMENTS(refuse); i++) {
		e = NULL;
		GVariant *v = g_dbus_connection_call_sync(bus, NAME, PATH, IFACE, "SendFile",
							  g_variant_new("(ss)", "010-0000-0001", refuse[i] ? refuse[i] : ""),
							  G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE, 30000, NULL, &e);
		if (v) {
			printf("FAIL: SendFile %s was taken\n", refuse[i]);
			return 1;
		}
		printf("SendFile %s refused: %s\n", refuse[i], e->message);
		g_error_free(e);
	}

	/* Not registered yet errors are tested by the daemon test itself. */
	printf("client: all steps passed\n");
	return 0;
}
