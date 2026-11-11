// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stdint.h>
#include <gio/gio.h>
#include "sipmsg.h"

struct rcsd;
struct sipua;

/* RCS feature tags: only what is implemented (chat). */
#define RCS_ICSI_CHAT "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"
#define RCS_ICSI_CHAT_RAW "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session"
#define RCS_ICSI_MSG "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg"
#define RCS_IARI_FTHTTP "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp"
#define RCS_IARI_DP "urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.dp"
#define RCS_ALLOW "INVITE, ACK, CANCEL, BYE, MESSAGE, OPTIONS, NOTIFY, UPDATE"

/* A dialog as the chat code keeps it. */
struct sipdlg {
	char call_id[96];
	char local_tag[24];
	char remote_tag[96];
	char remote_uri[256];    /* To of our requests: <tel:+82...> */
	char remote_target[256]; /* the peer's Contact URI */
	char route[1024];        /* Route set, comma separated <...>, "" = the service route */
	uint32_t cseq;
	int uas;                 /* we answered the INVITE */
	int anonymous;           /* From: anonymous (presence anonymous fetch, R9 6.5) */
};

/* resp is NULL when the request timed out or the connection went away. */
typedef void (*sipua_resp_cb)(struct sipua *ua, const struct sipmsg *resp, void *ud);

int sipua_registered(const struct sipua *ua);
const char *sipua_impu(const struct sipua *ua);
const char *sipua_local_ip(const struct sipua *ua);
int sipua_local_v6(const struct sipua *ua);
int sipua_msrp_tls(const struct sipua *ua);
unsigned sipua_timer_idle(const struct sipua *ua);
/* Capability discovery by presence (CAPDISCOVERY defaultDisc 1), else OPTIONS. */
int sipua_presence(const struct sipua *ua);
/* "010-1234-5678", "+82 10 1234 5678" -> "+821012345678". 0 or -EINVAL. */
int sipua_e164(const struct sipua *ua, const char *number, char *out, size_t size);

/*
 * A request in dlg (new: call_id empty, filled in here), with our Via,
 * Max-Forwards, Route, From, To, Call-ID, CSeq, Contact and User-Agent,
 * then extra (CRLF-terminated lines) and the body. method ACK reuses cseq.
 */
int sipua_send(struct sipua *ua, struct sipdlg *dlg, const char *method, const char *ruri,
	       const char *extra, const char *ctype, const char *body, size_t blen,
	       sipua_resp_cb cb, void *ud);
/* A response to req; to_tag added to To when the request had none. */
void sipua_respond(struct sipua *ua, const struct sipmsg *req, int code, const char *reason,
		   const char *to_tag, const char *extra, const char *ctype, const char *body);
/* Drops the callbacks registered with ud (its owner is going away). */
void sipua_forget(struct sipua *ua, void *ud);

/* chat.c */
void chat_on_request(struct rcsd *r, struct sipua *ua, const struct sipmsg *m);
void chat_on_registered(struct rcsd *r);
void chat_on_unregistered(struct rcsd *r);
/* A presence NOTIFY: 0 when it answered one of our anonymous fetches. */
int chat_on_notify(struct rcsd *r, struct sipua *ua, const struct sipmsg *m);
