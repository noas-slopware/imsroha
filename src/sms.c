// SPDX-License-Identifier: GPL-3.0-only
#include "sms.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


static int bcd_pack(const char *digits, unsigned char *out, size_t max_out)
{
	size_t len = strlen(digits);
	size_t out_bytes = (len + 1) / 2;
	if (out_bytes > max_out)
		return -ENOSPC;

	memset(out, 0xff, out_bytes);
	for (size_t i = 0; i < len; i++) {
		char c = digits[i];
		unsigned char d = (c >= '0' && c <= '9') ? (c - '0') : 0;
		if (i % 2 == 0)
			out[i / 2] = (out[i / 2] & 0xf0) | d;
		else
			out[i / 2] = (out[i / 2] & 0x0f) | (d << 4);
	}
	return (int)out_bytes;
}

/* Convert UTF-8 string to UCS-2 Big-Endian byte buffer. */
static size_t utf8_to_ucs2(const char *utf8, unsigned char *ucs2, size_t max_ucs2_bytes)
{
	const unsigned char *p = (const unsigned char *)utf8;
	size_t written = 0;

	while (*p && written + 2 <= max_ucs2_bytes) {
		uint32_t cp;
		if ((*p & 0x80) == 0) {
			cp = *p++;
		} else if ((*p & 0xe0) == 0xc0) {
			if ((p[1] & 0xc0) != 0x80) break;
			cp = ((p[0] & 0x1f) << 6) | (p[1] & 0x3f);
			p += 2;
		} else if ((*p & 0xf0) == 0xe0) {
			if ((p[1] & 0xc0) != 0x80 || (p[2] & 0xc0) != 0x80) break;
			cp = ((p[0] & 0x0f) << 12) | ((p[1] & 0x3f) << 6) | (p[2] & 0x3f);
			p += 3;
		} else {
			/* Skip 4-byte UTF-8 or invalid sequences */
			p++;
			continue;
		}

		if (cp > 0xffff)
			cp = '?';

		ucs2[written++] = (unsigned char)((cp >> 8) & 0xff);
		ucs2[written++] = (unsigned char)(cp & 0xff);
	}
	return written;
}

/* Convert UCS-2 Big-Endian byte buffer to UTF-8 null-terminated string. */
static int normalize_phone_number(const char *in, const char *cc, char *out, size_t out_max,
				   uint8_t *out_ton, size_t *out_digits)
{
	if (!in || !out || out_max < 32)
		return -EINVAL;

	char cleaned[64];
	size_t c_idx = 0;
	int has_plus = (in[0] == '+');

	for (size_t i = (has_plus ? 1 : 0); in[i] && c_idx + 1 < sizeof(cleaned); i++) {
		if (in[i] >= '0' && in[i] <= '9')
			cleaned[c_idx++] = in[i];
	}
	cleaned[c_idx] = '\0';

	if (c_idx == 0)
		return -EINVAL;

	/* The home country code: national form, 0... */
	size_t cc_len = cc ? strlen(cc) : 0;
	if (has_plus && cc_len && strncmp(cleaned, cc, cc_len) == 0 && c_idx > cc_len) {
		snprintf(out, out_max, "0%s", cleaned + cc_len);
		*out_ton = 0x81; /* National / unknown */
		*out_digits = strlen(out);
		return 0;
	}

	if (has_plus) {
		/* True international number */
		snprintf(out, out_max, "%s", cleaned);
		*out_ton = 0x91; /* International */
		*out_digits = strlen(out);
		return 0;
	}

	/* Domestic number */
	snprintf(out, out_max, "%s", cleaned);
	*out_ton = 0x81; /* National */
	*out_digits = strlen(out);
	return 0;
}

int imsd_sms_encode_rp_data(const char *dest_number, const char *utf8_text,
			    const char *country_code, unsigned char mr,
			    const unsigned char *smsc, size_t smsc_len,
			    unsigned char *out_buf, size_t max_len)
{
	if (!dest_number || !utf8_text || !out_buf || max_len < 64)
		return -EINVAL;

	char norm_number[64];
	uint8_t ton = 0x81;
	size_t num_digits = 0;
	int r = normalize_phone_number(dest_number, country_code, norm_number, sizeof(norm_number), &ton, &num_digits);
	if (r < 0)
		return r;

	if (num_digits > 20 || num_digits == 0)
		return -EINVAL;

	unsigned char bcd[16];
	int bcd_len = bcd_pack(norm_number, bcd, sizeof(bcd));
	if (bcd_len < 0)
		return bcd_len;

	/* Build TPDU (SMS-SUBMIT) */
	unsigned char tpdu[256];
	size_t tpdu_idx = 0;
	tpdu[tpdu_idx++] = 0x01; /* SMS-SUBMIT */
	tpdu[tpdu_idx++] = mr;   /* TP-MR */

	/* TP-DA: length is number of useful semi-octets (digits) */
	tpdu[tpdu_idx++] = (unsigned char)num_digits;
	tpdu[tpdu_idx++] = ton;
	memcpy(&tpdu[tpdu_idx], bcd, bcd_len);
	tpdu_idx += bcd_len;

	tpdu[tpdu_idx++] = 0x00; /* TP-PID: normal */
	tpdu[tpdu_idx++] = 0x08; /* TP-DCS: UCS-2 */

	/* Encode UTF-8 to UCS-2 */
	unsigned char ud_buf[140];
	size_t ud_len = utf8_to_ucs2(utf8_text, ud_buf, sizeof(ud_buf));

	tpdu[tpdu_idx++] = (unsigned char)ud_len; /* TP-UDL in octets */
	memcpy(&tpdu[tpdu_idx], ud_buf, ud_len);
	tpdu_idx += ud_len;

	/* Build RP-DATA (MO) */
	size_t rp_idx = 0;
	out_buf[rp_idx++] = 0x00; /* RP-DATA (MO) */
	out_buf[rp_idx++] = mr;   /* RP-MR */
	out_buf[rp_idx++] = 0x00; /* RP-Originator Address len = 0 */

	/* RP-Destination Address = SMSC (+821020921827) */
	memcpy(&out_buf[rp_idx], smsc, smsc_len);
	rp_idx += smsc_len;

	/* RP-User-Data len + TPDU */
	out_buf[rp_idx++] = (unsigned char)tpdu_idx;

	if (rp_idx + tpdu_idx > max_len)
		return -ENOSPC;

	memcpy(&out_buf[rp_idx], tpdu, tpdu_idx);
	return (int)(rp_idx + tpdu_idx);
}

int imsd_sms_address_element(const char *number, unsigned char *out, size_t size)
{
	char digits[24];
	size_t n = 0;
	int intl = number[0] == '+';

	for (const char *p = number + intl; *p && n + 1 < sizeof(digits); p++)
		if (*p >= '0' && *p <= '9')
			digits[n++] = *p;
	digits[n] = '\0';
	if (!n || (n + 1) / 2 + 2 > size)
		return -EINVAL;
	out[1] = intl ? 0x91 : 0x81;
	int bcd = bcd_pack(digits, out + 2, size - 2);
	if (bcd < 0)
		return bcd;
	out[0] = (unsigned char)(bcd + 1);
	return bcd + 2;
}
