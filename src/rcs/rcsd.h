// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <gio/gio.h>
#include "acs.h"
#include "fthttp.h"
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
	int pcscf_reconfigured;   /* the P-CSCF failed and the ACS was asked once already */
	struct ft_config ft;      /* from the stored configuration, at registration */
};

const char *rcsd_state_name(enum rcsd_state s);
void rcsd_set_state(struct rcsd *r, enum rcsd_state s);
void rcsd_reconfigure(struct rcsd *r);
/* No ACS run and no registration until imsroha-rcs restarts. */
void rcsd_halt(struct rcsd *r);

/* rcs_dbus.c: codes.noa.IMSroha.Rcs */
int rcsd_dbus_init(struct rcsd *r);
void rcsd_dbus_state_changed(struct rcsd *r);
void rcsd_dbus_message_received(struct rcsd *r, const char *number, const char *id,
				const char *text, gint64 ts_ms);
void rcsd_dbus_status(struct rcsd *r, const char *id, const char *status);
void rcsd_dbus_composing(struct rcsd *r, const char *number, gboolean active);
void rcsd_dbus_file_received(struct rcsd *r, const char *number, const char *id, const char *path,
			     const char *ctype, guint64 size, const char *thumb, gint64 ts_ms);
void rcsd_dbus_file_failed(struct rcsd *r, const char *number, const char *id, const char *reason);

/* The SIP side, from the stored configuration (sipua.c). */
void rcsd_ua_start(struct rcsd *r);
void rcsd_ua_stop(struct rcsd *r);

/* Messaging (chat.c), called from D-Bus. Errors set *error. */
gboolean rcsd_chat_send(struct rcsd *r, const char *number, const char *text, char *id, size_t size,
			GError **error);
gboolean rcsd_chat_composing(struct rcsd *r, const char *number, gboolean active, GError **error);
gboolean rcsd_chat_displayed(struct rcsd *r, const char *number, const char *id, GError **error);
/* Hands a CPIM body to the chat with number (+E.164), opening one if needed;
 * the status signals for id follow as for text. Takes body. */
gboolean rcsd_chat_enqueue(struct rcsd *r, const char *e164, const char *id, char *body, size_t len,
			   GError **error);
/* Answers inv with (a{sv}) once the OPTIONS exchange is done. */
void rcsd_capabilities(struct rcsd *r, const char *number, GDBusMethodInvocation *inv);

/* File transfer over HTTP (ft.c). */
void rcsd_ft_load(struct rcsd *r);
/* SendFile: answers inv with the message id once the file is open and fits. */
void rcsd_ft_send(struct rcsd *r, const char *sender, const char *number, const char *path,
		  GDBusMethodInvocation *inv);
/* A file-info that came in a chat: fetch the file (and its thumbnail). */
void rcsd_ft_received(struct rcsd *r, const char *number, const char *id, const char *xml, size_t len,
		      gint64 ts_ms);
void rcsd_ft_shutdown(struct rcsd *r);

#define RCSD_ERROR_NOT_READY "codes.noa.IMSroha.Rcs.Error.NotReady"
#define RCSD_ERROR_FAILED "codes.noa.IMSroha.Rcs.Error.Failed"
