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
	"  <method name='GetCapabilities'>"
	"   <arg name='number' type='s' direction='in'/>"
	"   <arg name='capabilities' type='a{sv}' direction='out'/>"
	"  </method>"
	"  <signal name='MessageReceived'>"
	"   <arg name='number' type='s'/><arg name='message_id' type='s'/>"
	"   <arg name='text' type='s'/><arg name='timestamp_ms' type='x'/>"
	"  </signal>"
	"  <signal name='MessageStatusChanged'>"
	"   <arg name='message_id' type='s'/><arg name='status' type='s'/>"
	"  </signal>"
	"  <signal name='ComposingChanged'>"
	"   <arg name='number' type='s'/><arg name='active' type='b'/>"
	"  </signal>"
	"  <signal name='StateChanged'><arg name='state' type='s'/></signal>"
	" </interface>"
	"</node>";

static void reply_error(GDBusMethodInvocation *inv, GError *e)
{
	const char *name = e->domain == G_IO_ERROR && e->code == G_IO_ERROR_NOT_CONNECTED
				   ? RCSD_ERROR_NOT_READY : RCSD_ERROR_FAILED;
	g_dbus_method_invocation_return_dbus_error(inv, name, e->message);
	g_error_free(e);
}

static void on_call(GDBusConnection *c, const char *sender, const char *path, const char *iface,
		    const char *method, GVariant *params, GDBusMethodInvocation *inv, gpointer ud)
{
	(void)c; (void)sender; (void)path; (void)iface;
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

void rcsd_dbus_message_received(struct rcsd *r, const char *number, const char *id, const char *text,
				gint64 ts_ms)
{
	emit(r, "MessageReceived", g_variant_new("(sssx)", number, id, text, ts_ms));
}

void rcsd_dbus_status(struct rcsd *r, const char *id, const char *status)
{
	emit(r, "MessageStatusChanged", g_variant_new("(ss)", id, status));
}

void rcsd_dbus_composing(struct rcsd *r, const char *number, gboolean active)
{
	emit(r, "ComposingChanged", g_variant_new("(sb)", number, active));
}
