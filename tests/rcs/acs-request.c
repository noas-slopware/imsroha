// SPDX-License-Identifier: GPL-3.0-only
/*
 * Prints every autoconfiguration request imsroha-rcs can send for the Flip3
 * on LG U+ (data/carriers.conf, tests/rcs/flip3-rcs.conf), with placeholder
 * IMSI, IMEI, MSISDN, cookie, token and OTP. Compared with
 * tests/rcs/golden-acs-lguplus.txt: any change to what goes to the ACS shows
 * up as a diff.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "acs.h"

static void show(const char *title, const struct acs_request *r)
{
	printf("=== %s: %s %s:%u\n", title, r->tls ? "TLS" : "TCP", r->host, r->port);
	for (const char *p = r->text; *p; p++) {
		if (*p == '\r' && p[1] == '\n')
			fputs("\\r", stdout);
		else
			putchar(*p);
	}
	printf("=== end\n\n");
}

int main(void)
{
	struct rcs_config cfg;
	setenv("IMSROHA_CONF", GOLDEN_SRCDIR "/tests/rcs/flip3-rcs.conf", 1);
	setenv("IMSROHA_CARRIERS", GOLDEN_SRCDIR "/data/carriers.conf", 1);
	if (rcs_config_load(&cfg, "450", "06") < 0 || strcmp(cfg.base.car.name, "LG U+")) {
		fprintf(stderr, "acs-request: no LG U+ profile\n");
		return 1;
	}
	struct rcs_identity id = { .imsi = "450069999999999", .imei = "359999999999999",
				   .msisdn = "+821099999999", .mcc = "450", .mnc = "06" };
	struct acs_state st = { 0 };
	struct acs_request r;

	acs_build_request(&cfg, &id, &st, ACS_LEG_HTTP, 0, NULL, NULL, NULL, &r);
	show("1. first run, HTTP over the LG U+ PDN", &r);
	acs_request_clear(&r);

	acs_build_request(&cfg, &id, &st, ACS_LEG_HTTPS, 0, "COOKIE=placeholder", NULL, NULL, &r);
	show("2a. HTTPS after the HTTP leg answered 200 with a cookie", &r);
	acs_request_clear(&r);

	acs_build_request(&cfg, &id, &st, ACS_LEG_HTTPS, 1, NULL, NULL, NULL, &r);
	show("2b. HTTPS after the HTTP leg answered 511 (non-PS: msisdn, SMS_port, empty token)", &r);
	acs_request_clear(&r);

	acs_build_request(&cfg, &id, &st, ACS_LEG_OTP, 0, "COOKIE=placeholder", "123456", NULL, &r);
	show("3. the OTP from the SMS, with the cookie of the 200 that announced it", &r);
	acs_request_clear(&r);

	st.version = 12;
	st.validity = 2592000;
	st.contacted = 1;
	snprintf(st.token, sizeof(st.token), "TOKEN-placeholder");
	acs_build_request(&cfg, &id, &st, ACS_LEG_HTTPS, 0, NULL, NULL, NULL, &r);
	show("4. refresh after validity, configured with version 12", &r);
	acs_request_clear(&r);

	acs_build_request(&cfg, &id, &st, ACS_LEG_HTTPS, 0, NULL, NULL, "-4", &r);
	show("5. after [rcs] enable=false: rcs_state=-4 (disabled by the user)", &r);
	acs_request_clear(&r);
	return 0;
}
