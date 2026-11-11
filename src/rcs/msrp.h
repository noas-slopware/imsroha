// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>
#include <glib.h>

struct rcs_config;
struct msrp;

struct msrp_cbs {
	/* A whole message (chunks joined). */
	void (*message)(struct msrp *m, const char *ctype, const char *body, size_t len, void *ud);
	/* The final answer to one of our SENDs: code 200, or the error (0: connection gone). */
	void (*result)(struct msrp *m, const char *msrp_id, int code, void *ud);
	/* up: connected and bound; !up: the connection is gone. */
	void (*state)(struct msrp *m, int up, void *ud);
};

/*
 * MSRP (RFC 4975) as the active end (RFC 6135 a=setup:active): we connect
 * to the first hop of remote_path, TLS for msrps:, and bind the session with
 * an empty SEND.
 */
struct msrp *msrp_new(const struct rcs_config *cfg, const char *local_path, const char *remote_path,
		      const struct msrp_cbs *cbs, void *ud);
void msrp_connect(struct msrp *m);
/* Queues nothing: call it once state(up). msrp_id gets the Message-ID used. */
int msrp_send(struct msrp *m, const char *ctype, const char *body, size_t len, int want_report,
	      char *msrp_id, size_t idsize);
void msrp_free(struct msrp *m);

/* Parses one frame off buf (also used by the tests). */
struct msrp_frame {
	char tid[40];
	int request;
	char method[16];
	int code;
	char flag;           /* '$', '+' or '#' */
	GPtrArray *names, *values;
	char *body;
	size_t blen;
};
gssize msrp_frame_parse(const char *buf, size_t len, struct msrp_frame **out);
void msrp_frame_free(struct msrp_frame *f);
const char *msrp_frame_header(const struct msrp_frame *f, const char *name);
