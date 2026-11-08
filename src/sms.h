#pragma once

#include <stddef.h>

/* Encodes an MO-SMS into TS 24.011 RP-DATA containing SMS-SUBMIT TPDU.
 * Handles UTF-8 to UCS-2 conversion.
 * Uses carrier SMSC +821020921827.
 * Returns bytes written, or negative errno.
 */
int imsd_sms_encode_rp_data(const char *dest_number, const char *utf8_text,
			    unsigned char mr,
			    unsigned char *out_buf, size_t max_len);
