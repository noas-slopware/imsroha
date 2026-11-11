// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>
#include <glib.h>

/* A parsed SIP message (RFC 3261 7), compact header names expanded. */
struct sipmsg {
	int request;
	char method[16];
	char ruri[512];
	int code;
	char reason[96];
	GPtrArray *names, *values;
	char *body;
	size_t blen;
};

/*
 * Frames one message off a stream buffer: returns the bytes it used (0 when
 * the message is not complete yet, <0 when the stream is broken). Leading
 * CRLFs (keepalive pings and pongs) are skipped and counted.
 */
gssize sipmsg_frame(const char *buf, size_t len, struct sipmsg **out);
void sipmsg_free(struct sipmsg *m);
const char *sipmsg_header(const struct sipmsg *m, const char *name);
/* Every value of a header, comma-separated lists split (Via, Route...). NULL-terminated. */
char **sipmsg_header_all(const struct sipmsg *m, const char *name);
/* ;name=value of a header value, unquoted. 0 when found. */
int sip_param(const char *hval, const char *name, char *out, size_t size);
/* The <uri> or bare URI of a name-addr. */
void sip_uri_of(const char *hval, char *out, size_t size);
/* A Digest challenge's param= (quoted or not). */
int sip_auth_param(const char *hval, const char *name, char *out, size_t size);
/* The user part of a sip: or tel: URI ("+821012345678"). */
void sip_user_of(const char *uri, char *out, size_t size);
void sip_random(char *out, size_t len); /* len alphanumerics + NUL */
