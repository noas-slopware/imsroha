// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>

/* Encodes an MO-SMS into TS 24.011 RP-DATA containing SMS-SUBMIT TPDU.
 * Handles UTF-8 to UCS-2 conversion.
 * Uses carrier SMSC +821020921827.
 * Returns bytes written, or negative errno.
 */
/* smsc: the RP destination address element (length, TON/NPI, BCD digits). */
int imsd_sms_encode_rp_data(const char *dest_number, const char *utf8_text,
			    const char *country_code, unsigned char mr,
			    const unsigned char *smsc, size_t smsc_len,
			    unsigned char *out_buf, size_t max_len);

/* "+821020921827" -> 07 91 28 01 02 29 81 72. Returns the element length or <0. */
int imsd_sms_address_element(const char *number, unsigned char *out, size_t size);
