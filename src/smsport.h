// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * An SMS-DELIVER as imsroha hands it to ModemManager (PduReceived: "00" for
 * no SMSC address, then the TPDU, in hex). Gives the application port
 * (TS 23.040 9.2.3.24.4/5) and the text (GSM 7-bit or UCS-2) of a single-part
 * message. port is -1 without port addressing.
 */
struct sms_deliver {
	int dest_port, src_port;
	char sender[32];
	char text[512];   /* UTF-8 */
	int concatenated; /* part of a multi-part message: text is one part only */
};

int sms_parse_deliver_hex(const char *hex, struct sms_deliver *out);

/*
 * The application port an MT-SMS (same hex) is addressed to, when it is for
 * an application rather than the user's inbox; -1 otherwise: no port
 * addressing, WAP push (2948, 2949: MMS notifications, which ModemManager
 * handles), or not an SMS-DELIVER it can read.
 */
int imsd_sms_app_port(const char *hex);

/* Whether a single-part SMS-DELIVER's text matches regex (caseless). */
int imsd_sms_text_matches(const char *hex, const char *regex);
