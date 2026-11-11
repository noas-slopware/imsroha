// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <net/if.h>
#include <stdint.h>
#include "config.h"

/*
 * RCS configuration, on top of imsroha's (config.h):
 *
 *   - [rcs] in /etc/imsroha/imsroha.conf: the switch and everything local to
 *     this machine. enable= is read from there and nowhere else.
 *   - rcs-* keys of the carrier profile in carriers.conf (picked by PLMN as for
 *     VoLTE), overridable in [carrier]: how the carrier does RCS. None of
 *     them can turn RCS on.
 *   - [device]: model, build and operator as for VoLTE, plus vendor=.
 */

#define RCS_STATE_DIR "/var/lib/imsroha/rcs"

struct rcs_config {
	/* [rcs] */
	int enable;                   /* default 0 */
	char interface[IFNAMSIZ];     /* bind RCS sockets here ("" = routing decides) */
	char interface4[IFNAMSIZ];    /* IPv4 sockets here instead (CLAT), "" = interface */
	char msisdn[32];              /* own number for the non-PS flow; "" = ModemManager's */
	char ca_file[256];            /* extra trust anchors, "" = the system store */
	char client_vendor[8];        /* client_vendor, at most 4 characters (R9 table 6-1) */
	char client_version[24];      /* client_version: Platform-Major.Minor */
	int default_sms_app;          /* default_sms_app: 0, 1 or 2 */
	int assume_mobile;            /* start with the HTTP leg (network-based authentication) */
	unsigned otp_timeout;         /* seconds to wait for the OTP SMS */
	char state_dir[256];
	char download_dir[256];       /* received files: <dir>/<IMSI>/, owned by dir's owner;
	                               * "" = <state_dir>/<IMSI>/files (root only) */
	int chatbot;                  /* chatbots and A2P, when provisioned; default 1 */

	/* carriers.conf rcs-*, [carrier] */
	char acs_url[256];            /* rcs-acs-url: http://... (the HTTP leg) */
	char acs_https_url[256];      /* rcs-acs-https-url: "" = acs_url with https:// */
	uint16_t otp_port;            /* rcs-otp-port: application port of the OTP SMS */
	int otp_text;                 /* rcs-otp-type=text: a plain SMS matching rcs-otp-regex */
	char otp_regex[160];
	char profile[16];             /* rcs-profile: rcs_profile= */
	char provisioning_version[8]; /* rcs-provisioning-version */
	char rcs_version[8];          /* rcs-version: "" = not sent (UP 2.x) */
	char app[256];                /* rcs-app: app= values, comma separated */
	char user_agent[256];         /* rcs-user-agent: SIP */
	char http_user_agent[256];    /* rcs-http-user-agent: "" = user_agent */
	char accept_language[16];     /* rcs-accept-language: "" = no header */
	uint16_t sip_port;            /* rcs-sip-port: when NAPTR/SRV give nothing */
	int iscomposing_cpim;         /* rcs-iscomposing-cpim */
	int standalone;               /* rcs-standalone: pager-mode messages may be sent */
	unsigned reg_expires;         /* rcs-reg-expires */
	char ft_auth_hosts[512];      /* rcs-ft-auth-hosts: more file transfer hosts for Digest */
	int ft_auth_http;             /* rcs-ft-auth-http: Digest over plain http too */
	int xbotmessage;              /* rcs-xbotmessage: R9 7.7.4's extended bot message */

	/* imsroha's own configuration: [device], the VoLTE carrier profile */
	struct imsroha_config base;
	char terminal_vendor[16];     /* [device] vendor */
};

/* mcc/mnc of the SIM, or NULL when unknown. 0 or a negative errno. */
int rcs_config_load(struct rcs_config *cfg, const char *mcc, const char *mnc);
/* Only [rcs] enable= and state-dir=, without any carrier: for the off path. */
int rcs_config_load_switch(struct rcs_config *cfg);

/* A User-Agent template with [PRODUCT_MODEL] [BUILD_VERSION] [OPERATOR]. */
void rcs_config_expand_ua(const struct rcs_config *cfg, const char *tmpl, char *out, size_t size);
