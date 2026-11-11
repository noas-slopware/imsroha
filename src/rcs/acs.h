// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <gio/gio.h>
#include "rcs_config.h"

/*
 * Autoconfiguration (GSMA RCC.14, TTAK.KO-06.0410/R9 6.3).
 *
 * The request builder and the response rules are pure functions so the
 * tests can hold them against golden files; acs_run() strings them together
 * over http.c.
 */

struct rcs_identity {
	char imsi[16];
	char imei[20];
	char msisdn[32];  /* +E.164 or "", only sent in the non-PS flow */
	char mcc[4], mnc[4];
};

/* What the ACS last told us about this IMSI (state file). */
struct acs_state {
	int version;           /* VERS version: >0 a configuration, 0, -1 .. -3 */
	int validity;          /* seconds */
	char token[1024];
	int64_t next_run;      /* unix time of the next run, 0 = the next start */
	int last_status;       /* last HTTP status, 0 = unreachable */
	int permanent;         /* version and validity -1: never again for this IMSI */
	int contacted;         /* the ACS has answered with VERS at least once */
	int disable_sent;      /* rcs_state=-4 went out after the last enable */
	int trial;             /* unanswered runs in a row (R9 6.3.1.2.3) */
	int rcscfg_force;      /* the next run sends vers=0 (R9 6.3.1.1.2.2) */
	int64_t last_run;      /* unix time the last run first contacted the ACS */
};

enum acs_leg {
	ACS_LEG_HTTP,   /* bare GET over HTTP: network-based authentication */
	ACS_LEG_HTTPS,  /* GET with the parameters */
	ACS_LEG_OTP,    /* GET /?OTP=... with the cookie */
};

struct acs_request {
	char *text;         /* the whole HTTP request, CRLFs and all */
	char host[256];
	uint16_t port;
	int tls;
};

/* rcs_state: NULL = from the state (version if > 0, else 0); "-4" to disable. */
int acs_build_request(const struct rcs_config *cfg, const struct rcs_identity *id,
		      const struct acs_state *st, enum acs_leg leg, int non_ps,
		      const char *cookie, const char *otp, const char *rcs_state,
		      struct acs_request *out);
void acs_request_clear(struct acs_request *r);

/* The parsed wap-provisioningdoc: (path, value) pairs in document order. Paths
 * are the characteristic types and the parm name joined by '/'. */
struct acs_xml {
	GPtrArray *keys;   /* char * */
	GPtrArray *values; /* char * */
	int has_vers;
	int version, validity;
	char *token;
};

struct acs_xml *acs_xml_parse(const char *body, size_t len, GError **error);
void acs_xml_free(struct acs_xml *x);
/* The first value whose path ends in "/<suffix>" (case-insensitive), or NULL. */
const char *acs_xml_get(const struct acs_xml *x, const char *suffix);
/* Every value whose path ends in "/<suffix>", in order; NULL-terminated, free with g_free. */
const char **acs_xml_get_all(const struct acs_xml *x, const char *suffix);

/* State files under <state_dir>/<imsi>/. */
int acs_state_load(const struct rcs_config *cfg, const char *imsi, struct acs_state *st);
int acs_state_save(const struct rcs_config *cfg, const char *imsi, const struct acs_state *st);
int acs_config_save(const struct rcs_config *cfg, const char *imsi, const char *xml, size_t len);
char *acs_config_load(const struct rcs_config *cfg, const char *imsi, size_t *len);
void acs_config_remove(const struct rcs_config *cfg, const char *imsi);
/* Is there a state for any IMSI that needs the "disabled by user" request? */
int acs_any_pending_disable(const struct rcs_config *cfg);

enum acs_outcome {
	ACS_ACTIVE,        /* a configuration to register with */
	ACS_NONE,          /* nothing usable now; st->next_run says when to try again */
	ACS_STOPPED,       /* -1, -2: no registration; no retry before the next start (or ever) */
	ACS_DORMANT,       /* -3 */
};

/* Applies a 200's VERS to the state (table 6-2). Returns what to do. */
enum acs_outcome acs_apply_vers(const struct rcs_config *cfg, const char *imsi,
				struct acs_state *st, const struct acs_xml *x,
				const char *body, size_t len, int64_t now);

/* The OTP source: blocks up to timeout_s for the OTP, 0 or a negative errno. */
typedef int (*acs_otp_fn)(void *userdata, char *otp, size_t size, unsigned timeout_s);

/*
 * One autoconfiguration run (blocking: run it in a thread). Updates and saves
 * the state, stores the XML. disable: send rcs_state=-4 and nothing else.
 */
enum acs_outcome acs_run(const struct rcs_config *cfg, const struct rcs_identity *id,
			 struct acs_state *st, int disable, acs_otp_fn otp_fn, void *otp_ud,
			 GCancellable *cancel);

/*
 * However a run is asked for (restart, 403, an unreachable P-CSCF, a crash
 * loop under Restart=), two runs are at least this far apart: the first step
 * of R9 6.3.1.2.3's ladder. Scheduled runs (validity) are never this close.
 */
#define ACS_MIN_INTERVAL 1200

/* Seconds before the trial'th retry after an unanswered run, -1 = the next start. */
int acs_retry_delay(int trial);
