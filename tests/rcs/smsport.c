// SPDX-License-Identifier: GPL-3.0-only
/* The OTP SMS of TTAK.KO-06.0410/R9 6.3.1.1.2: UCS-2, port 37273 (0x9199). */
#include <stdio.h>
#include <string.h>
#include "smsport.h"

static int fails;

static void expect(const char *what, int ok)
{
	printf("%s %s\n", ok ? "ok  " : "FAIL", what);
	fails += !ok;
}

int main(void)
{
	struct sms_deliver d;
	/* 00 no SMSC | 40 DELIVER+UDHI | OA 4 digits 1234 | PID 00 | DCS 08 |
	 * SCTS | UDL 19 | UDH 06 05 04 9199 0000 | "123456" in UCS-2 */
	const char *otp = "00" "40" "04" "81" "2143" "00" "08" "52111131000000" "13"
			  "06050491990000" "003100320033003400350036";
	expect("parses", sms_parse_deliver_hex(otp, &d) == 0);
	expect("destination port 37273", d.dest_port == 37273);
	expect("source port 0", d.src_port == 0);
	expect("text 123456", !strcmp(d.text, "123456"));
	expect("sender 1234", !strcmp(d.sender, "1234"));

	/* "450069999999999-rcscfg" in UCS-2, the network-initiated request. */
	char hex[400] = "00400481214300085211113100000034" "06050491990000";
	const char *t = "450069999999999-rcscfg";
	for (const char *c = t; *c; c++)
		snprintf(hex + strlen(hex), sizeof(hex) - strlen(hex), "00%02x", *c);
	expect("rcscfg parses", sms_parse_deliver_hex(hex, &d) == 0);
	expect("rcscfg text", !strcmp(d.text, t));

	/* A plain 7-bit SMS "hello" from +8210 without a UDH. */
	const char *plain = "00" "04" "0591" "2801f0" "00" "00" "52111131000000" "05" "e8329bfd06";
	expect("7-bit parses", sms_parse_deliver_hex(plain, &d) == 0);
	expect("7-bit no port", d.dest_port == -1);
	expect("7-bit text hello", !strcmp(d.text, "hello"));
	expect("7-bit sender +82100", !strcmp(d.sender, "+82100"));

	/* Which ones imsroha keeps from ModemManager (PortPduReceived). */
	expect("OTP is for an application (37273)", imsd_sms_app_port(otp) == 37273);
	expect("plain SMS is for the inbox", imsd_sms_app_port(plain) == -1);
	/* WAP push (MMS notification): 8-bit, UDH 06 05 04 0b84 23f0, 3 data octets. */
	const char *wap = "00" "40" "04" "81" "2143" "00" "04" "52111131000000" "0a"
			  "0605040b8423f0" "010203";
	expect("WAP push parses", sms_parse_deliver_hex(wap, &d) == 0 && d.dest_port == 2948);
	expect("WAP push stays with ModemManager", imsd_sms_app_port(wap) == -1);
	/* 8-bit to another port (e.g. visual voicemail on 5499). */
	const char *vvm = "00" "40" "04" "81" "2143" "00" "04" "52111131000000" "0a"
			  "060504157b0000" "010203";
	expect("8-bit port SMS is for an application (5499)", imsd_sms_app_port(vvm) == 5499);

	/* rcs-otp-type=text: the plain SMS matching rcs-otp-regex. */
	expect("text OTP regex matches", imsd_sms_text_matches(plain, "^HELLO"));
	expect("other text does not match", !imsd_sms_text_matches(plain, "verification code"));
	expect("no regex, no match", !imsd_sms_text_matches(plain, ""));
	return fails ? 1 : 0;
}
