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

/*
 * A request with a body that does not fit a C string: head (request line,
 * headers, the start of the body), then fd_len bytes read from fd (none when
 * fd < 0), then tail. File transfer uploads stream the file this way.
 */
struct http_body {
	const char *head;
	size_t head_len;
	int fd;
	guint64 fd_len;
	const char *tail;
	size_t tail_len;
};
int http_exchange_body(const struct rcs_config *cfg, const char *host, uint16_t port, int tls,
		       const struct http_body *req, unsigned timeout_s, GCancellable *cancel,
		       struct http_response *out);

/*
 * A GET whose 200 body goes to out_fd as it arrives, at most max bytes
 * (0: no limit): more is -EFBIG, whatever Content-Length said. Any other
 * status is read like http_exchange(), for its headers (a 401's challenge).
 * For a 200, out->len is the number of bytes written and out->body is empty.
 */
int http_download(const struct rcs_config *cfg, const char *host, uint16_t port, int tls,
		  const char *request, unsigned timeout_s, GCancellable *cancel, int out_fd,
		  guint64 max, struct http_response *out);

/* http://host[:port]/path or https://... 0 or -EINVAL. path is "" or starts with '/'. */
int http_parse_url(const char *url, int *tls, char *host, size_t hsize, uint16_t *port,
		   char *path, size_t psize);

/* Parses a raw response (also used by the tests). 0 or -EBADMSG. */
int http_parse_response(const char *raw, size_t len, struct http_response *out);
