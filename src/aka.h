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
struct imsd_isim_identity {
	char impi[128];   /* EF_IMPI: private user identity (NAI) */
	char impu[128];   /* EF_IMPU record 1: public user identity (SIP URI) */
	char domain[128]; /* EF_DOMAIN: home network domain */
};

/* Reads EF_IMPI, EF_IMPU and EF_DOMAIN from the ISIM. 0 or negative errno. */
int imsd_isim_read_identity(struct imsd_isim_identity *id);
