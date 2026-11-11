// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <gio/gio.h>
#include "rcs_config.h"

/*
 * One HTTP/1.1 exchange on its own connection. The request is sent exactly as
 * given; the response is read to Content-Length, the last chunk or EOF, and a
 * gzip body is inflated. No redirects, no cookies kept here.
 */
struct http_response {
	int status;         /* 0: no response (unreachable, timeout, TLS failure) */
	char reason[64];
	GPtrArray *names;   /* header names as received */
	GPtrArray *values;
	char *body;         /* NUL-terminated; len excludes the NUL */
	size_t len;
	char error[256];    /* why status is 0 */
};

int http_exchange(const struct rcs_config *cfg, const char *host, uint16_t port, int tls,
		  const char *request, unsigned timeout_s, GCancellable *cancel,
		  struct http_response *out);
void http_response_clear(struct http_response *r);
/* The first header of that name (case-insensitive), or NULL. */
const char *http_header(const struct http_response *r, const char *name);

/* Parses a raw response (also used by the tests). 0 or -EBADMSG. */
int http_parse_response(const char *raw, size_t len, struct http_response *out);
