// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <gio/gio.h>
#include "acs.h"
#include "rcs_config.h"

enum rcsd_state {
	RCSD_CONFIGURING,
	RCSD_WAITING_OTP,
	RCSD_REGISTERING,
	RCSD_REGISTERED,
	RCSD_UNREGISTERED,
	RCSD_DISABLED,
};

struct sipua;

struct rcsd {
	GMainLoop *loop;
	struct rcs_config cfg;
	struct rcs_identity id;
	struct acs_state st;
	struct acs_xml *xml;      /* the stored configuration, when there is one */
	GDBusConnection *bus;
	guint bus_owner, bus_obj;
	GAsyncQueue *otp_q;
	int waiting_otp;          /* atomic: the ACS thread waits for the OTP */
	int acs_running;
	guint acs_timer;
	enum rcsd_state state;
	struct sipua *ua;
	int forbidden;            /* 403s to REGISTER this run (R9 A.5 b) */
};

const char *rcsd_state_name(enum rcsd_state s);
void rcsd_set_state(struct rcsd *r, enum rcsd_state s);
void rcsd_reconfigure(struct rcsd *r);

/* rcs_dbus.c: codes.noa.IMSroha.Rcs */
int rcsd_dbus_init(struct rcsd *r);
void rcsd_dbus_state_changed(struct rcsd *r);
void rcsd_dbus_message_received(struct rcsd *r, const char *number, const char *id,
				const char *text, gint64 ts_ms);
void rcsd_dbus_status(struct rcsd *r, const char *id, const char *status);
void rcsd_dbus_composing(struct rcsd *r, const char *number, gboolean active);

/* The SIP side, from the stored configuration (sipua.c). */
void rcsd_ua_start(struct rcsd *r);
void rcsd_ua_stop(struct rcsd *r);

/* Messaging (chat.c), called from D-Bus. Errors set *error. */
gboolean rcsd_chat_send(struct rcsd *r, const char *number, const char *text, char *id, size_t size,
			GError **error);
gboolean rcsd_chat_composing(struct rcsd *r, const char *number, gboolean active, GError **error);
gboolean rcsd_chat_displayed(struct rcsd *r, const char *number, const char *id, GError **error);
/* Answers inv with (a{sv}) once the OPTIONS exchange is done. */
void rcsd_capabilities(struct rcsd *r, const char *number, GDBusMethodInvocation *inv);

#define RCSD_ERROR_NOT_READY "codes.noa.IMSroha.Rcs.Error.NotReady"
#define RCSD_ERROR_FAILED "codes.noa.IMSroha.Rcs.Error.Failed"
