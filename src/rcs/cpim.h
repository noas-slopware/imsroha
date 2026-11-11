// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>
#include <glib.h>

/* CPIM (RFC 3862) with IMDN (RFC 5438), and isComposing (RFC 3994). */

struct cpim {
	char *ctype;        /* the inner Content-Type, parameters stripped */
	char *ctype_full;   /* as received, with its parameters (a multipart boundary) */
	char *msg_id;       /* imdn.Message-ID */
	char *datetime;
	char *disposition;  /* imdn.Disposition-Notification */
	char *body;
	size_t blen;
};

/* A chat message: anonymous From/To (RCC.07 1-to-1 chat), positive-delivery and display. */
char *cpim_text(const char *msg_id, const char *text, size_t *len);
/* The same around another content type (a file-info: application/vnd.gsma.rcs-ft-http+xml). */
char *cpim_message(const char *msg_id, const char *ctype, const char *body, size_t *len);
/* A delivered/displayed notification for orig_id. */
char *cpim_imdn(const char *orig_id, const char *status, size_t *len);
/* isComposing, wrapped in CPIM or bare. */
char *iscomposing(int active, int wrap, size_t *len);

int cpim_parse(const char *buf, size_t len, struct cpim *out);
void cpim_clear(struct cpim *c);
/* The message-id and status (delivered, displayed, failed, ...) of an IMDN. */
int imdn_parse(const char *xml, size_t len, char *id, size_t idsize, char *status, size_t ssize);
/* 1 active, 0 idle, <0 not isComposing. */
int iscomposing_parse(const char *xml, size_t len);
/* ms since the epoch from a CPIM DateTime, or now. */
gint64 cpim_time_ms(const char *datetime);
void cpim_msg_id(char *out, size_t size);
