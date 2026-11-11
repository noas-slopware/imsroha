// SPDX-License-Identifier: GPL-3.0-only
/*
 * One acs_run() against tests/rcs/fake-acs.py, with the configuration the
 * test script wrote (IMSROHA_CONF, IMSROHA_CARRIERS, IMSROHA_RCS_STATE).
 * argv[1]: "run" or "disable". The OTP source answers 654321 at once.
 * Prints the outcome and the stored state.
 */
#include <stdio.h>
#include <string.h>
#include "acs.h"

static int otp(void *ud, char *out, size_t size, unsigned timeout)
{
	(void)ud; (void)timeout;
	snprintf(out, size, "654321");
	printf("otp asked\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct rcs_config cfg;
	if (argc < 2 || rcs_config_load(&cfg, "450", "06") < 0)
		return 2;
	struct rcs_identity id = { .imsi = "450069999999999", .imei = "359999999999999",
				   .msisdn = "+821099999999", .mcc = "450", .mnc = "06" };
	struct acs_state st;
	acs_state_load(&cfg, id.imsi, &st);
	static const char *names[] = { "active", "none", "stopped", "dormant" };
	enum acs_outcome o = acs_run(&cfg, &id, &st, !strcmp(argv[1], "disable"), otp, NULL, NULL);
	printf("outcome %s version %d validity %d token %s permanent %d contacted %d disable-sent %d next-run %s\n",
	       names[o], st.version, st.validity, st.token[0] ? st.token : "-", st.permanent, st.contacted,
	       st.disable_sent, st.next_run ? "set" : "next-start");
	size_t len = 0;
	char *xml = acs_config_load(&cfg, id.imsi, &len);
	printf("config.xml %s\n", xml ? "stored" : "absent");
	if (xml) {
		struct acs_xml *x = acs_xml_parse(xml, len, NULL);
		printf("  impi %s\n  pcscf %s\n  auth %s\n", acs_xml_get(x, "Private_User_Identity"),
		       acs_xml_get(x, "LBO_P-CSCF_Address/NODE/Address"), acs_xml_get(x, "GSMA/AuthType"));
		acs_xml_free(x);
		g_free(xml);
	}
	return 0;
}
