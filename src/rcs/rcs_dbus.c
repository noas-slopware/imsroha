// SPDX-License-Identifier: GPL-3.0-only
/* codes.noa.IMSroha.Rcs: what apps (Spacebar) see of RCS. */
#include <stdio.h>
#include <string.h>
#include "rcsd.h"

#define RCS_BUS_NAME "codes.noa.IMSroha.Rcs"
#define RCS_BUS_PATH "/codes/noa/IMSroha/Rcs"
#define RCS_IFACE "codes.noa.IMSroha.Rcs"

static const char introspection[] =
	"<node>"
	" <interface name='" RCS_IFACE "'>"
	"  <property name='State' type='s' access='read'/>"
	"  <method name='SendMessage'>"
	"   <arg name='number' type='s' direction='in'/>"
	"   <arg name='text' type='s' direction='in'/>"
	"   <arg name='message_id' type='s' direction='out'/>"
	"  </method>"
	"  <method name='SetComposing'>"
	"   <arg name='number' type='s' direction='in'/>"
	"   <arg name='active' type='b' direction='in'/>"
	"  </method>"
	"  <method name='MarkDisplayed'>"
	"   <arg name='number' type='s' direction='in'/>"
	"   <arg name='message_id' type='s' direction='in'/>"
	"  </method>"
	"  <method name='SendFile'>"
	"   <arg name='number' type='s' direction='in'/>"
	"   <arg name='path' type='s' direction='in'/>"
	"   <arg name='message_id' type='s' direction='out'/>"
	"  </method>"
	"  <method name='SendSuggestionResponse'>"
	"   <arg name='number' type='s' direction='in'/>"
	"   <arg name='in_reply_to_message_id' type='s' direction='in'/>"
	"   <arg name='response_json' type='s' direction='in'/>"
	"   <arg name='message_id' type='s' direction='out'/>"
	"  </method>"
	"  <method name='GetBotInfo'>"
	"   <arg name='bot_id' type='s' direction='in'/>"
	"   <arg name='json' type='s' direction='out'/>"
	"  </method>"
	"  <method name='GetCapabilities'>"
	"   <arg name='number' type='s' direction='in'/>"
	"   <arg name='capabilities' type='a{sv}' direction='out'/>"
	"  </method>"
	"  <signal name='MessageReceived'>"
	"   <arg name='number' type='s'/><arg name='message_id' type='s'/>"
	"   <arg name='text' type='s'/><arg name='timestamp_ms' type='x'/>"
	"  </signal>"
	"  <signal name='RichMessageReceived'>"
	"   <arg name='number' type='s'/><arg name='message_id' type='s'/>"
	"   <arg name='content_type' type='s'/><arg name='body' type='s'/>"
	"   <arg name='suggestions' type='s'/><arg name='bot_id' type='s'/>"
	"   <arg name='timestamp_ms' type='x'/>"
	"  </signal>"
	"  <signal name='MessageStatusChanged'>"
	"   <arg name='message_id' type='s'/><arg name='status' type='s'/>"
	"  </signal>"
	"  <signal name='ComposingChanged'>"
	"   <arg name='number' type='s'/><arg name='active' type='b'/>"
	"  </signal>"
	"  <signal name='FileReceived'>"
	"   <arg name='number' type='s'/><arg name='message_id' type='s'/>"
	"   <arg name='path' type='s'/><arg name='content_type' type='s'/><arg name='size' type='t'/>"
	"   <arg name='thumbnail_path' type='s'/><arg name='timestamp_ms' type='x'/>"
	"  </signal>"
	"  <signal name='FileReceiveFailed'>"
	"   <arg name='number' type='s'/><arg name='message_id' type='s'/><arg name='reason' type='s'/>"
	"  </signal>"
	"  <signal name='StateChanged'><arg name='state' type='s'/></signal>"
	" </interface>"
	"</node>";

static void reply_error(GDBusMethodInvocation *inv, GError *e)
{
	const char *name = e->domain != G_IO_ERROR ? RCSD_ERROR_FAILED
			   : e->code == G_IO_ERROR_NOT_CONNECTED ? RCSD_ERROR_NOT_READY
			   : e->code == G_IO_ERROR_NOT_SUPPORTED ? RCSD_ERROR_NOT_AVAILABLE
								 : RCSD_ERROR_FAILED;
	g_dbus_method_invocation_return_dbus_error(inv, name, e->message);
	g_error_free(e);
}

static void on_call(GDBusConnection *c, const char *sender, const char *path, const char *iface,
		    const char *method, GVariant *params, GDBusMethodInvocation *inv, gpointer ud)
{
	(void)c; (void)path; (void)iface;
	struct rcsd *r = ud;
	GError *e = NULL;

	if (!strcmp(method, "SendMessage")) {
		const char *num, *text;
		char id[64];
		g_variant_get(params, "(&s&s)", &num, &text);
		if (rcsd_chat_send(r, num, text, id, sizeof(id), &e))
			g_dbus_method_invocation_return_value(inv, g_variant_new("(s)", id));
		else
			reply_error(inv, e);
	} else if (!strcmp(method, "SetComposing")) {
		const char *num;
		gboolean on;
		g_variant_get(params, "(&sb)", &num, &on);
		if (rcsd_chat_composing(r, num, on, &e))
			g_dbus_method_invocation_return_value(inv, NULL);
		else
			reply_error(inv, e);
	} else if (!strcmp(method, "MarkDisplayed")) {
		const char *num, *id;
		g_variant_get(params, "(&s&s)", &num, &id);
		if (rcsd_chat_displayed(r, num, id, &e))
			g_dbus_method_invocation_return_value(inv, NULL);
		else
			reply_error(inv, e);
	} else if (!strcmp(method, "SendFile")) {
		const char *num, *fpath;
		g_variant_get(params, "(&s&s)", &num, &fpath);
		rcsd_ft_send(r, sender, num, fpath, inv);
	} else if (!strcmp(method, "SendSuggestionResponse")) {
		const char *num, *reply_to, *json;
		char id[64];
		g_variant_get(params, "(&s&s&s)", &num, &reply_to, &json);
		if (rcsd_chat_suggestion_response(r, num, reply_to, json, id, sizeof(id), &e))
			g_dbus_method_invocation_return_value(inv, g_variant_new("(s)", id));
		else
			reply_error(inv, e);
	} else if (!strcmp(method, "GetBotInfo")) {
		const char *bot;
		g_variant_get(params, "(&s)", &bot);
		rcsd_botinfo(r, bot, inv);
	} else if (!strcmp(method, "GetCapabilities")) {
		const char *num;
		g_variant_get(params, "(&s)", &num);
		rcsd_capabilities(r, num, inv);
	}
}

static GVariant *on_get(GDBusConnection *c, const char *sender, const char *path, const char *iface,
			const char *prop, GError **error, gpointer ud)
{
	(void)c; (void)sender; (void)path; (void)iface; (void)error;
	struct rcsd *r = ud;
	if (!strcmp(prop, "State"))
		return g_variant_new_string(rcsd_state_name(r->state));
	return NULL;
}

static const GDBusInterfaceVTable vtable = { .method_call = on_call, .get_property = on_get };

int rcsd_dbus_init(struct rcsd *r)
{
	GError *e = NULL;
	GDBusNodeInfo *info = g_dbus_node_info_new_for_xml(introspection, &e);
	if (!info) {
		fprintf(stderr, "imsroha-rcs: %s\n", e->message);
		g_error_free(e);
		return -1;
	}
	r->bus_obj = g_dbus_connection_register_object(r->bus, RCS_BUS_PATH, info->interfaces[0], &vtable,
						       r, NULL, &e);
	g_dbus_node_info_unref(info);
	if (!r->bus_obj) {
		fprintf(stderr, "imsroha-rcs: %s\n", e->message);
		g_error_free(e);
		return -1;
	}
	r->bus_owner = g_bus_own_name_on_connection(r->bus, RCS_BUS_NAME, G_BUS_NAME_OWNER_FLAGS_NONE,
						    NULL, NULL, NULL, NULL);
	return 0;
}

static void emit(struct rcsd *r, const char *name, GVariant *v)
{
	if (r->bus && r->bus_obj)
		g_dbus_connection_emit_signal(r->bus, NULL, RCS_BUS_PATH, RCS_IFACE, name, v, NULL);
	else
		g_variant_unref(g_variant_ref_sink(v));
}

void rcsd_dbus_state_changed(struct rcsd *r)
{
	if (!r->bus || !r->bus_obj)
		return;
	emit(r, "StateChanged", g_variant_new("(s)", rcsd_state_name(r->state)));
	GVariantBuilder b;
	g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(&b, "{sv}", "State", g_variant_new_string(rcsd_state_name(r->state)));
	g_dbus_connection_emit_signal(r->bus, NULL, RCS_BUS_PATH, "org.freedesktop.DBus.Properties",
				      "PropertiesChanged", g_variant_new("(sa{sv}as)", RCS_IFACE, &b, NULL), NULL);
}

/* Network bytes: a D-Bus string must be UTF-8 (invalid sequences become U+FFFD). */
static char *utf8(const char *s)
{
	return g_utf8_make_valid(s ? s : "", -1);
}

void rcsd_dbus_message_received(struct rcsd *r, const char *number, const char *id, const char *text,
				gint64 ts_ms)
{
	char *n = utf8(number), *i = utf8(id), *t = utf8(text);
	emit(r, "MessageReceived", g_variant_new("(sssx)", n, i, t, ts_ms));
	g_free(n);
	g_free(i);
	g_free(t);
}

void rcsd_dbus_rich_received(struct rcsd *r, const char *number, const char *id, const char *ctype,
			     const char *body, const char *suggestions, const char *bot_id, gint64 ts_ms)
{
	char *v[6] = { utf8(number), utf8(id), utf8(ctype), utf8(body), utf8(suggestions), utf8(bot_id) };
	emit(r, "RichMessageReceived", g_variant_new("(ssssssx)", v[0], v[1], v[2], v[3], v[4], v[5], ts_ms));
	for (int k = 0; k < 6; k++)
		g_free(v[k]);
}

void rcsd_dbus_status(struct rcsd *r, const char *id, const char *status)
{
	char *i = utf8(id), *st = utf8(status);
	emit(r, "MessageStatusChanged", g_variant_new("(ss)", i, st));
	g_free(i);
	g_free(st);
}

void rcsd_dbus_composing(struct rcsd *r, const char *number, gboolean active)
{
	emit(r, "ComposingChanged", g_variant_new("(sb)", number, active));
}

void rcsd_dbus_file_received(struct rcsd *r, const char *number, const char *id, const char *path,
			     const char *ctype, guint64 size, const char *thumb, gint64 ts_ms)
{
	emit(r, "FileReceived", g_variant_new("(sssstsx)", number, id, path, ctype, size, thumb ? thumb : "", ts_ms));
}

void rcsd_dbus_file_failed(struct rcsd *r, const char *number, const char *id, const char *reason)
{
	emit(r, "FileReceiveFailed", g_variant_new("(sss)", number, id, reason));
}
