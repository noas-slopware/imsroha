// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>

struct imsd_aka_challenge {
	unsigned char rand[16];
	unsigned char autn[16];
};

struct imsd_aka_result {
	unsigned char res[16];
	size_t res_len;
	unsigned char ck[16];
	unsigned char ik[16];
	unsigned char auts[14];
	size_t auts_len;
	int is_sync_failure;
	int success;
};

int imsd_aka_run_isim(const struct imsd_aka_challenge *ch,
		      struct imsd_aka_result *out);

/* What the ISIM says this subscriber is (TS 31.103 4.2.2-4.2.4). */
struct imsroha_device;

/* Which modem the SIM is behind ([device] in imsroha.conf); default QRTR node 0. */
void imsroha_sim_set_device(const struct imsroha_device *dev);

struct imsd_isim_identity {
	int has_isim;     /* 0: the card has no (usable) ISIM, the identity is derived */
	char impi[128];   /* EF_IMPI: private user identity (NAI), or <IMSI>@<derived domain> */
	char impu[128];   /* EF_IMPU on the home domain, or sip:<IMSI>@<derived domain> */
	char domain[128]; /* EF_DOMAIN: home network domain, "" without an ISIM */
	char imsi[16];    /* EF_IMSI on the USIM */
	char mcc[4], mnc[4];
	int mnc_len;      /* from EF_AD, 0 when the card did not say */
	char smsc[24];    /* EF_SMSP record 1's service centre, +E.164, "" when none */
};

/* Reads EF_IMPI, EF_IMPU and EF_DOMAIN from the ISIM. 0 or negative errno. */
/* Reads the identity: the ISIM's when there is one, else derived from the USIM. */
int imsd_isim_read_identity(struct imsd_isim_identity *id);
