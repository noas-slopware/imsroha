// SPDX-License-Identifier: GPL-3.0-only
#include "smsport.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

/* GSM 03.38 default alphabet; the escape table only for the common few. */
static const char *const gsm7[128] = {
	"@", "£", "$", "¥", "è", "é", "ù", "ì", "ò", "Ç", "\n", "Ø", "ø", "\r", "Å", "å",
	"Δ", "_", "Φ", "Γ", "Λ", "Ω", "Π", "Ψ", "Σ", "Θ", "Ξ", "", "Æ", "æ", "ß", "É",
	" ", "!", "\"", "#", "¤", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?",
	"¡", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
	"P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Ä", "Ö", "Ñ", "Ü", "§",
	"¿", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
	"p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "ä", "ö", "ñ", "ü", "à",
};

static const char *gsm7_ext(unsigned c)
{
	switch (c) {
	case 0x0a: return "\f";
	case 0x14: return "^";
	case 0x28: return "{";
	case 0x29: return "}";
	case 0x2f: return "\\";
	case 0x3c: return "[";
	case 0x3d: return "~";
	case 0x3e: return "]";
	case 0x40: return "|";
	case 0x65: return "€";
	default: return " ";
	}
}

static int unhex(const char *hex, guint8 *out, size_t max)
{
	size_t n = strlen(hex);
	if (n % 2 || n / 2 > max)
		return -EINVAL;
	for (size_t i = 0; i < n / 2; i++) {
		int hi = g_ascii_xdigit_value(hex[2 * i]), lo = g_ascii_xdigit_value(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return -EINVAL;
		out[i] = (guint8)(hi << 4 | lo);
	}
	return (int)(n / 2);
}

int sms_parse_deliver_hex(const char *hex, struct sms_deliver *out)
{
	guint8 b[400];
	int n = unhex(hex, b, sizeof(b));
	memset(out, 0, sizeof(*out));
	out->dest_port = out->src_port = -1;
	if (n < 2)
		return -EINVAL;

	size_t i = 1 + b[0]; /* SMSC address */
	size_t len = (size_t)n;
	if (i >= len || (b[i] & 0x03) != 0) /* SMS-DELIVER only */
		return -EPROTO;
	int udhi = b[i] & 0x40;
	i++;
	if (i + 2 > len)
		return -EBADMSG;
	size_t digits = b[i], toa = b[i + 1];
	size_t oa_bytes = (digits + 1) / 2;
	if (i + 2 + oa_bytes > len)
		return -EBADMSG;
	if ((toa & 0x70) == 0x50) {
		snprintf(out->sender, sizeof(out->sender), "alphanumeric");
	} else {
		size_t p = 0;
		if ((toa & 0x70) == 0x10)
			out->sender[p++] = '+';
		for (size_t d = 0; d < digits && p + 1 < sizeof(out->sender); d++) {
			unsigned v = d % 2 ? b[i + 2 + d / 2] >> 4 : b[i + 2 + d / 2] & 0x0f;
			out->sender[p++] = v < 10 ? (char)('0' + v) : '?';
		}
		out->sender[p] = '\0';
	}
	i += 2 + oa_bytes;
	if (i + 2 + 7 + 1 > len)
		return -EBADMSG;
	guint8 dcs = b[i + 1];
	i += 2 + 7; /* PID, DCS, SCTS */
	size_t udl = b[i++];
	const guint8 *ud = b + i;
	size_t ud_bytes = len - i;

	/* 0x08 in the low nibble group: UCS-2; 0x04: 8-bit; else the default alphabet. */
	int alphabet = 0;
	if ((dcs & 0xc0) == 0x00 || (dcs & 0xc0) == 0x40)
		alphabet = (dcs >> 2) & 0x03;
	else if ((dcs & 0xf0) == 0xf0)
		alphabet = (dcs & 0x04) ? 1 : 0;
	else if ((dcs & 0xf0) == 0xe0)
		alphabet = 2;

	size_t udh_len = 0;
	if (udhi) {
		if (!ud_bytes)
			return -EBADMSG;
		udh_len = (size_t)ud[0] + 1;
		if (udh_len > ud_bytes)
			return -EBADMSG;
		for (size_t j = 1; j + 1 < udh_len;) {
			guint8 iei = ud[j], iel = ud[j + 1];
			const guint8 *v = ud + j + 2;
			if (j + 2 + iel > udh_len)
				return -EBADMSG;
			if (iei == 0x05 && iel == 4) {
				out->dest_port = v[0] << 8 | v[1];
				out->src_port = v[2] << 8 | v[3];
			} else if (iei == 0x04 && iel == 2) {
				out->dest_port = v[0];
				out->src_port = v[1];
			} else if (iei == 0x00 || iei == 0x08) {
				out->concatenated = 1;
			}
			j += 2 + iel;
		}
	}

	GString *t = g_string_new(NULL);
	if (alphabet == 2) {
		size_t bytes = MIN(udl, ud_bytes);
		if (bytes > udh_len) {
			gsize w = 0;
			char *u = g_convert((const char *)ud + udh_len, (gssize)((bytes - udh_len) & ~1u), "UTF-8",
					    "UTF-16BE", NULL, &w, NULL);
			if (u)
				g_string_append(t, u);
			g_free(u);
		}
	} else if (alphabet == 1) {
		size_t bytes = MIN(udl, ud_bytes);
		for (size_t j = udh_len; j < bytes; j++)
			g_string_append_c(t, g_ascii_isprint(ud[j]) ? (char)ud[j] : '.');
	} else {
		/* udl counts septets; the UDH is padded to a septet boundary. */
		size_t skip = udh_len ? (udh_len * 8 + 6) / 7 : 0;
		int esc = 0;
		for (size_t s = skip; s < udl; s++) {
			size_t bit = s * 7, byte = bit / 8, sh = bit % 8;
			if (byte >= ud_bytes)
				break;
			unsigned v = ud[byte] >> sh;
			if (sh > 1 && byte + 1 < ud_bytes)
				v |= ud[byte + 1] << (8 - sh);
			v &= 0x7f;
			if (esc) {
				g_string_append(t, gsm7_ext(v));
				esc = 0;
			} else if (v == 0x1b) {
				esc = 1;
			} else {
				g_string_append(t, gsm7[v]);
			}
		}
	}
	snprintf(out->text, sizeof(out->text), "%s", t->str);
	g_string_free(t, TRUE);
	return 0;
}
