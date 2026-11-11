// SPDX-License-Identifier: GPL-3.0-only
#include "sip.h"
#include "audio.h"
#include "inbox.h"
#include "aka.h"
#include "dbus.h"
#include "sms.h"
#include "dns.h"
#include "imei.h"
#include "amr_be.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Self-contained RFC 1321 MD5 */
typedef struct {
	uint32_t state[4];
	uint32_t count[2];
	uint8_t buffer[64];
} md5_context;

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF(a, b, c, d, x, s, ac) { (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }
#define GG(a, b, c, d, x, s, ac) { (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }
#define HH(a, b, c, d, x, s, ac) { (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }
#define II(a, b, c, d, x, s, ac) { (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
	for (int i = 0, j = 0; i < 16; i++, j += 4)
		x[i] = ((uint32_t)block[j]) | (((uint32_t)block[j + 1]) << 8) |
		       (((uint32_t)block[j + 2]) << 16) | (((uint32_t)block[j + 3]) << 24);

	FF(a, b, c, d, x[ 0], 7, 0xd76aa478); FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
	FF(c, d, a, b, x[ 2], 17, 0x242070db); FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
	FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
	FF(c, d, a, b, x[ 6], 17, 0xa8304613); FF(b, c, d, a, x[ 7], 22, 0xfd469501);
	FF(a, b, c, d, x[ 8], 7, 0x698098d8); FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
	FF(c, d, a, b, x[10], 17, 0xffff5bb1); FF(b, c, d, a, x[11], 22, 0x895cd7be);
	FF(a, b, c, d, x[12], 7, 0x6b901122); FF(d, a, b, c, x[13], 12, 0xfd987193);
	FF(c, d, a, b, x[14], 17, 0xa679438e); FF(b, c, d, a, x[15], 22, 0x49b40821);

	GG(a, b, c, d, x[ 1], 5, 0xf61e2562); GG(d, a, b, c, x[ 6], 9, 0xc040b340);
	GG(c, d, a, b, x[11], 14, 0x265e5a51); GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
	GG(a, b, c, d, x[ 5], 5, 0xd62f105d); GG(d, a, b, c, x[10], 9, 0x02441453);
	GG(c, d, a, b, x[15], 14, 0xd8a1e681); GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
	GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); GG(d, a, b, c, x[14], 9, 0xc33707d6);
	GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
	GG(a, b, c, d, x[13], 5, 0xa9e3e905); GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8);
	GG(c, d, a, b, x[ 7], 14, 0x676f02d9); GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

	HH(a, b, c, d, x[ 5], 4, 0xfffa3942); HH(d, a, b, c, x[ 8], 11, 0x8771f681);
	HH(c, d, a, b, x[11], 16, 0x6d9d6122); HH(b, c, d, a, x[14], 23, 0xfde5380c);
	HH(a, b, c, d, x[ 1], 4, 0xa4beea44); HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
	HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); HH(b, c, d, a, x[10], 23, 0xbebfbc70);
	HH(a, b, c, d, x[13], 4, 0x289b7ec6); HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
	HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); HH(b, c, d, a, x[ 6], 23, 0x04881d05);
	HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); HH(d, a, b, c, x[12], 11, 0xe6db99e5);
	HH(c, d, a, b, x[15], 16, 0x1fa27cf8); HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);

	II(a, b, c, d, x[ 0], 6, 0xf4292244); II(d, a, b, c, x[ 7], 10, 0x432aff97);
	II(c, d, a, b, x[14], 15, 0xab9423a7); II(b, c, d, a, x[ 5], 21, 0xfc93a039);
	II(a, b, c, d, x[12], 6, 0x655b59c3); II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
	II(c, d, a, b, x[10], 15, 0xffeff47d); II(b, c, d, a, x[ 1], 21, 0x85845dd1);
	II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
	II(c, d, a, b, x[ 6], 15, 0xa3014314); II(b, c, d, a, x[13], 21, 0x4e0811a1);
	II(a, b, c, d, x[ 4], 6, 0xf7537e82); II(d, a, b, c, x[11], 10, 0xbd3af235);
	II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); II(b, c, d, a, x[ 9], 21, 0xeb86d391);

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md5_init(md5_context *ctx) {
	ctx->count[0] = ctx->count[1] = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

static void md5_update(md5_context *ctx, const uint8_t *input, size_t inputLen) {
	size_t i, index = (ctx->count[0] >> 3) & 0x3f;
	if ((ctx->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3))
		ctx->count[1]++;
	ctx->count[1] += ((uint32_t)inputLen >> 29);
	size_t partLen = 64 - index;
	if (inputLen >= partLen) {
		memcpy(&ctx->buffer[index], input, partLen);
		md5_transform(ctx->state, ctx->buffer);
		for (i = partLen; i + 63 < inputLen; i += 64)
			md5_transform(ctx->state, &input[i]);
		index = 0;
	} else i = 0;
	memcpy(&ctx->buffer[index], &input[i], inputLen - i);
}

static void md5_final(uint8_t digest[16], md5_context *ctx) {
	static const uint8_t PADDING[64] = { 0x80 };
	uint8_t bits[8];
	for (int i = 0; i < 4; i++) {
		bits[i] = (uint8_t)((ctx->count[0] >> (i * 8)) & 0xff);
		bits[i + 4] = (uint8_t)((ctx->count[1] >> (i * 8)) & 0xff);
	}
	size_t index = (ctx->count[0] >> 3) & 0x3f;
	size_t padLen = (index < 56) ? (56 - index) : (120 - index);
	md5_update(ctx, PADDING, padLen);
	md5_update(ctx, bits, 8);
	for (int i = 0; i < 4; i++) {
		digest[i * 4]     = (uint8_t)((ctx->state[i]) & 0xff);
		digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
		digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
		digest[i * 4 + 3] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
	}
}

static void md5_hex(const void *data, size_t len, char *out_hex)
{
	md5_context ctx;
	uint8_t digest[16];
	md5_init(&ctx);
	md5_update(&ctx, (const uint8_t *)data, len);
	md5_final(digest, &ctx);
	for (int i = 0; i < 16; i++) {
		sprintf(out_hex + (i * 2), "%02x", digest[i]);
	}
	out_hex[32] = '\0';
}

static void rand_hex(char *out, size_t hex_len)
{
	static const char hex[] = "0123456789abcdef";
	for (size_t i = 0; i < hex_len; i++) {
		out[i] = hex[rand() % 16];
	}
	out[hex_len] = '\0';
}

static int b64_decode(const char *in, size_t in_len, unsigned char *out, size_t max_out)
{
	static const signed char tbl[256] = {
		['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
		['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
		['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
		['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
		['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
		['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
		['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
		['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
	};
	size_t written = 0;
	uint32_t buf = 0;
	int bits = 0;

	for (size_t i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		if (c == '=') break;
		if (c > ' ' && (tbl[c] || c == 'A')) {
			buf = (buf << 6) | (tbl[c] & 0x3f);
			bits += 6;
			if (bits >= 8) {
				bits -= 8;
				if (written < max_out)
					out[written++] = (unsigned char)((buf >> bits) & 0xff);
			}
		}
	}
	return (int)written;
}

static int b64_encode(const unsigned char *in, size_t in_len, char *out, size_t max_out)
{
	static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t written = 0;

	for (size_t i = 0; i < in_len; i += 3) {
		if (written + 4 >= max_out) break;
		uint32_t b = (in[i] << 16);
		if (i + 1 < in_len) b |= (in[i + 1] << 8);
		if (i + 2 < in_len) b |= in[i + 2];

		out[written++] = tbl[(b >> 18) & 0x3f];
		out[written++] = tbl[(b >> 12) & 0x3f];
		out[written++] = (i + 1 < in_len) ? tbl[(b >> 6) & 0x3f] : '=';
		out[written++] = (i + 2 < in_len) ? tbl[b & 0x3f] : '=';
	}
	out[written] = '\0';
	return (int)written;
}

static int find_header(const char *msg, const char *header_name, char *out_val, size_t max_val)
{
	/*
	 * Only at the start of a header line, and only in the header block: an
	 * unanchored search finds "Expires:" inside "Min-Expires:" or
	 * "Session-Expires:", and "To:" inside "Referred-To:".
	 */
	size_t name_len = strlen(header_name);
	const char *p = msg;
	for (;;) {
		const char *nl = strchr(p, '\n');
		if (!nl)
			return -ENOENT;
		p = nl + 1;
		if (*p == '\r' || *p == '\n' || !*p)
			return -ENOENT; /* blank line: end of headers */
		if (strncasecmp(p, header_name, name_len) != 0)
			continue;
		const char *q = p + name_len;
		while (*q == ' ' || *q == '\t')
			q++;
		if (*q == ':') {
			p = q + 1;
			break;
		}
	}
	while (*p == ' ' || *p == '\t') p++;

	const char *end = strstr(p, "\r\n");
	if (!end) end = strchr(p, '\n');
	if (!end) end = p + strlen(p);

	size_t len = end - p;
	if (len >= max_val) len = max_val - 1;
	memcpy(out_val, p, len);
	out_val[len] = '\0';
	return 0;
}

static int find_param(const char *hdr_val, const char *param_name, char *out_val, size_t max_val)
{
	const char *p = strcasestr(hdr_val, param_name);
	if (!p) return -ENOENT;
	p += strlen(param_name);
	while (*p == ' ' || *p == '=') p++;
	int quoted = (*p == '"');
	if (quoted) p++;

	size_t written = 0;
	while (*p && written + 1 < max_val) {
		if (quoted && *p == '"') break;
		if (!quoted && (*p == ',' || *p == ';' || *p == '\r' || *p == '\n' || *p == ' ')) break;
		out_val[written++] = *p++;
	}
	out_val[written] = '\0';
	return 0;
}

static int find_all_vias(const char *msg, char *out_vias, size_t max_vias)
{
	out_vias[0] = '\0';
	size_t written = 0;
	const char *p = msg;
	while (p && *p) {
		const char *v = NULL;
		if (strncasecmp(p, "Via:", 4) == 0) {
			v = p;
		} else {
			const char *nl = strcasestr(p, "\nVia:");
			if (nl) v = nl + 1;
		}
		if (!v) break;
		const char *line_end = strstr(v, "\r\n");
		if (!line_end) break;
		size_t len = (line_end + 2) - v;
		if (written + len + 1 >= max_vias) break;
		memcpy(out_vias + written, v, len);
		written += len;
		out_vias[written] = '\0';
		p = line_end + 2;
	}
	if (written == 0) {
		char single[512] = "";
		if (find_header(msg, "Via", single, sizeof(single)) == 0) {
			snprintf(out_vias, max_vias, "Via: %s\r\n", single);
			return 0;
		}
		return -ENOENT;
	}
	return 0;
}

static int parse_sdp_media(const char *sdp, char *out_ip, size_t max_ip, uint16_t *out_port)
{
	if (!sdp || !out_ip || !out_port)
		return -EINVAL;

	out_ip[0] = '\0';
	*out_port = 0;

	/* Find c=IN IP6 <ip> or c=IN IP4 <ip> */
	const char *c = strstr(sdp, "c=IN IP6 ");
	if (c) {
		c += 9;
		const char *end = strpbrk(c, "\r\n ");
		size_t len = end ? (size_t)(end - c) : strlen(c);
		if (len >= max_ip) len = max_ip - 1;
		memcpy(out_ip, c, len);
		out_ip[len] = '\0';
	} else if ((c = strstr(sdp, "c=IN IP4 "))) {
		c += 9;
		const char *end = strpbrk(c, "\r\n ");
		size_t len = end ? (size_t)(end - c) : strlen(c);
		if (len >= max_ip) len = max_ip - 1;
		memcpy(out_ip, c, len);
		out_ip[len] = '\0';
	}

	/* Find m=audio <port> */
	const char *m = strstr(sdp, "m=audio ");
	if (m) {
		m += 8;
		*out_port = (uint16_t)strtoul(m, NULL, 10);
	}

	return (out_ip[0] && *out_port > 0) ? 0 : -ENOENT;
}

/* Whether the a=fmtp line of payload type pt has octet-align=1 (RFC 4867 8.1). */
static int sdp_pt_octet_aligned(const char *sdp, int pt)
{
	char key[24];
	snprintf(key, sizeof(key), "a=fmtp:%d ", pt);
	const char *f = strstr(sdp, key);
	if (!f)
		return 0;
	size_t l = strcspn(f, "\r\n");
	char line[256];
	snprintf(line, sizeof(line), "%.*s", (int)(l < sizeof(line) - 1 ? l : sizeof(line) - 1), f);
	return strstr(line, "octet-align=1") != NULL;
}

static void parse_sdp_codecs(const char *sdp, struct imsd_sip_ctx *ctx)
{
	ctx->call_pt_amrwb = 0;
	ctx->call_pt_amr = 0;
	ctx->call_pt_dtmf = 0;
	ctx->call_pt_dtmf_wb = 0;
	ctx->call_pt_dtmf_nb = 0;
	ctx->call_octet_aligned = 0;
	ctx->call_wb_octet = ctx->call_nb_octet = 1;
	ctx->call_has_wb = 0;
	ctx->call_has_nb = 0;
	ctx->call_has_dtmf_wb = 0;
	ctx->call_has_dtmf_nb = 0;

	const char *p = sdp;
	while (p && *p) {
		const char *rtp = strstr(p, "a=rtpmap:");
		if (!rtp) break;
		rtp += 9;
		int pt = atoi(rtp);
		const char *sp = strchr(rtp, ' ');
		if (sp) {
			sp++;
			/*
			 * RFC 4867: octet-align=1 in this PT's fmtp, else bandwidth-
			 * efficient. With both on offer, take an octet-aligned one (what
			 * LG U+ has always had); otherwise the last listed, as before.
			 */
			int oa = sdp_pt_octet_aligned(sdp, pt);
			if (strncasecmp(sp, "AMR-WB", 6) == 0) {
				if (!ctx->call_pt_amrwb || oa || !ctx->call_wb_octet) {
					ctx->call_pt_amrwb = pt;
					ctx->call_wb_octet = oa;
				}
			} else if (strncasecmp(sp, "AMR", 3) == 0 && strncasecmp(sp, "AMR-WB", 6) != 0) {
				if (!ctx->call_pt_amr || oa || !ctx->call_nb_octet) {
					ctx->call_pt_amr = pt;
					ctx->call_nb_octet = oa;
				}
			} else if (strncasecmp(sp, "telephone-event/16000", 21) == 0) {
				ctx->call_pt_dtmf_wb = pt;
				ctx->call_has_dtmf_wb = 1;
				ctx->call_pt_dtmf = pt;
			} else if (strncasecmp(sp, "telephone-event/8000", 20) == 0) {
				ctx->call_pt_dtmf_nb = pt;
				ctx->call_has_dtmf_nb = 1;
				if (!ctx->call_pt_dtmf)
					ctx->call_pt_dtmf = pt;
			} else if (strncasecmp(sp, "telephone-event", 15) == 0) {
				ctx->call_pt_dtmf = pt;
			}
		}
		p = strchr(rtp, '\n');
		if (p) p++;
	}

	ctx->call_octet_aligned = ctx->call_pt_amrwb ? ctx->call_wb_octet : ctx->call_nb_octet;
	if (!ctx->call_pt_amrwb)
		ctx->call_wb_octet = 1;
	if (!ctx->call_pt_amr)
		ctx->call_nb_octet = 1;

	ctx->call_has_wb = ctx->call_pt_amrwb > 0;
	ctx->call_has_nb = ctx->call_pt_amr > 0;
	if (ctx->call_pt_amrwb <= 0) ctx->call_pt_amrwb = ctx->cfg.car.pt_amrwb;
	if (ctx->call_pt_amr <= 0) ctx->call_pt_amr = ctx->cfg.car.pt_amr;
	if (ctx->call_pt_dtmf_wb <= 0) ctx->call_pt_dtmf_wb = ctx->cfg.car.pt_dtmf_wb;
	if (ctx->call_pt_dtmf_nb <= 0) ctx->call_pt_dtmf_nb = ctx->cfg.car.pt_dtmf;
	if (ctx->call_pt_dtmf <= 0) ctx->call_pt_dtmf = ctx->call_has_wb ? ctx->call_pt_dtmf_wb : ctx->call_pt_dtmf_nb;

	fprintf(stderr, "imsroha: remote SDP codecs: AMR-WB %s, AMR %s, DTMF PT %d (wb %d, nb %d), octet-align=%d\n",
		ctx->call_has_wb ? "yes" : "no", ctx->call_has_nb ? "yes" : "no",
		ctx->call_pt_dtmf, ctx->call_pt_dtmf_wb, ctx->call_pt_dtmf_nb, ctx->call_octet_aligned);
}

/* Whether an SDP offer lists AMR-WB or AMR, the only codecs we can speak. */
static int sdp_has_amr(const char *sdp)
{
	struct imsd_sip_ctx probe;
	memset(&probe, 0, sizeof(probe));
	parse_sdp_codecs(sdp, &probe);
	return probe.call_has_wb || probe.call_has_nb;
}

/* A new call gets a new SDP session id; every later body bumps the version. */
static void sdp_new_session(struct imsd_sip_ctx *ctx)
{
	ctx->sdp_sess_id = (uint64_t)time(NULL);
	ctx->sdp_sess_ver = ctx->sdp_sess_id;
}

/*
 * Our SDP body. As an offer (answer = 0) it lists everything we speak under
 * our own payload types, ordered like the stock profile: AMR-WB, AMR, DTMF WB,
 * DTMF NB. telephone-event must run at the speech codec's clock (RFC 4733
 * 2.1), so AMR-WB needs a telephone-event/16000 next to it: with only /8000
 * offered, an answerer that keeps DTMF can only pick AMR-NB (what LG U+
 * answered with).
 *
 * As an answer (answer = 1) to the offer parse_sdp_codecs() just read, it
 * lists only the formats that offer carried, under the offer's payload type
 * numbers (RFC 3264 6.1). LG U+ and KT offer AMR-WB as 100 and AMR as 96;
 * answering with our own 106/104 is a mismatch, and the network drops the
 * call right after the ACK. This holds for the initial INVITE and for every
 * re-INVITE or UPDATE in the dialog.
 *
 * Returns the body length, or -ENOTSUP if the offer has no AMR at all.
 */
/*
 * Our SDP. An offer lists AMR-WB and AMR octet-aligned, and with sdp-tta
 * (TTAK.KO-06.0357/R6 5.4.2, Table 5-4) also bandwidth-efficient PTs,
 * maxptime:120, b=RS:0, b=RR:2500 and the phone number as o= username.
 * An answer takes the PTs (and their payload format) chosen from the offer.
 */
static int build_local_sdp(struct imsd_sip_ctx *ctx, char *sdp, size_t size, int answer)
{
	const struct imsroha_carrier *car = &ctx->cfg.car;
	int amrwb = car->pt_amrwb, amr = car->pt_amr;
	int amrwb_be = car->pt_amrwb_be, amr_be = car->pt_amr_be;
	int dtmf_wb = car->pt_dtmf_wb, dtmf_nb = car->pt_dtmf;
	int wb_oa = 1, nb_oa = 1;

	if (answer) {
		amrwb = ctx->call_has_wb ? ctx->call_pt_amrwb : 0;
		amr = ctx->call_has_nb ? ctx->call_pt_amr : 0;
		wb_oa = ctx->call_wb_octet;
		nb_oa = ctx->call_nb_octet;
		amrwb_be = amr_be = 0;
		dtmf_wb = ctx->call_has_dtmf_wb ? ctx->call_pt_dtmf_wb : 0;
		dtmf_nb = ctx->call_has_dtmf_nb ? ctx->call_pt_dtmf_nb : 0;
		if (!amrwb && !amr)
			return -ENOTSUP;
	}

	char pts[96] = "";
	size_t pts_len = 0;
	const int list[] = { amrwb, amrwb_be, amr, amr_be, dtmf_wb, dtmf_nb };
	for (size_t i = 0; i < sizeof(list) / sizeof(list[0]); i++)
		if (list[i] > 0)
			pts_len += snprintf(pts + pts_len, sizeof(pts) - pts_len, " %d", list[i]);

	/* Table 5-4 note 1: the originator's username is its phone number. */
	char user[64] = "-";
	if (car->sdp_tta) {
		const char *u = !strncmp(ctx->impu, "sip:", 4) ? ctx->impu + 4 :
				!strncmp(ctx->impu, "tel:", 4) ? ctx->impu + 4 : ctx->impu;
		size_t n = strcspn(u, "@;>");
		if (n && n < sizeof(user))
			snprintf(user, sizeof(user), "%.*s", (int)n, u);
	}

	unsigned long long ver = (unsigned long long)ctx->sdp_sess_ver++;
	size_t len = (size_t)snprintf(sdp, size,
		"v=0\r\n"
		"o=%s %llu %llu IN IP6 %s\r\n"
		"s=-\r\n"
		"c=IN IP6 %s\r\n"
		"t=0 0\r\n"
		"m=audio %u RTP/AVP%s\r\n"
		"b=AS:41\r\n"
		"%s",
		user, (unsigned long long)ctx->sdp_sess_id, ver, ctx->local_ip, ctx->local_ip,
		(unsigned)car->rtp_port, pts, car->sdp_tta ? "b=RS:0\r\nb=RR:2500\r\n" : "");
	if (amrwb > 0 && len < size)
		len += (size_t)snprintf(sdp + len, size - len,
			"a=rtpmap:%d AMR-WB/16000/1\r\n"
			"a=fmtp:%d %smode-set=0,1,2\r\n", amrwb, amrwb, wb_oa ? "octet-align=1;" : "");
	if (amrwb_be > 0 && len < size)
		len += (size_t)snprintf(sdp + len, size - len,
			"a=rtpmap:%d AMR-WB/16000/1\r\n"
			"a=fmtp:%d mode-set=0,1,2\r\n", amrwb_be, amrwb_be);
	if (amr > 0 && len < size)
		len += (size_t)snprintf(sdp + len, size - len,
			"a=rtpmap:%d AMR/8000/1\r\n"
			"a=fmtp:%d %smode-set=0,2,4,7\r\n", amr, amr, nb_oa ? "octet-align=1;" : "");
	if (amr_be > 0 && len < size)
		len += (size_t)snprintf(sdp + len, size - len,
			"a=rtpmap:%d AMR/8000/1\r\n"
			"a=fmtp:%d mode-set=0,2,4,7\r\n", amr_be, amr_be);
	if (dtmf_wb > 0 && len < size)
		len += (size_t)snprintf(sdp + len, size - len,
			"a=rtpmap:%d telephone-event/16000\r\n"
			"a=fmtp:%d 0-15\r\n", dtmf_wb, dtmf_wb);
	if (dtmf_nb > 0 && len < size)
		len += (size_t)snprintf(sdp + len, size - len,
			"a=rtpmap:%d telephone-event/8000\r\n"
			"a=fmtp:%d 0-15\r\n", dtmf_nb, dtmf_nb);
	if (len < size)
		len += (size_t)snprintf(sdp + len, size - len,
			"a=ptime:20\r\n%s"
			"a=sendrecv\r\n", car->sdp_tta ? "a=maxptime:120\r\n" : "");
	if (len >= size)
		return -ENOSPC;
	return (int)len;
}

/*
 * Once the SAs are up, requests leave from port_uc to the P-CSCF's port_ps,
 * and responses (to the requests it sends us on port_us) from port_us to its
 * port_pc. The kernel's policies put both into ESP.
 */
static int send_sip_msg(struct imsd_sip_ctx *ctx, const void *buf, size_t len)
{
	struct sockaddr_in6 to = ctx->pcscf_addr;
	int fd = ctx->fd;

	if (ctx->sec_state == IMSD_SEC_PROTECTED) {
		int response = len >= 8 && !memcmp(buf, "SIP/2.0 ", 8);
		fd = response ? ctx->fd_s : ctx->fd_c;
		to.sin6_port = htons(response ? ctx->sec.port_pc : ctx->sec.port_ps);
	}
	ssize_t sent = sendto(fd, buf, len, 0, (struct sockaddr *)&to, sizeof(to));
	if (sent < 0) {
		fprintf(stderr, "imsroha: sendto failed: %s\n", strerror(errno));
		return -errno;
	}
	return 0;
}

/* FNV-1a over a string, continuing from h. */
static uint32_t fnv1a(uint32_t h, const char *str)
{
	for (; *str; str++) {
		h ^= (unsigned char)*str;
		h *= 16777619u;
	}
	return h;
}

/*
 * A bodiless response that echoes the request's Via lines (as find_all_vias()
 * returns them), From, To, Call-ID and CSeq. A To without a tag gets one, as
 * every final response needs (RFC 3261 8.2.6.2). The tag is derived from the
 * request's Call-ID, From and CSeq, so a retransmission of the same request
 * gets the same tag without keeping a transaction around.
 */
static void send_simple_response(struct imsd_sip_ctx *ctx, const char *status,
				 const char *vias, const char *from, const char *to,
				 const char *call_id, const char *cseq)
{
	char tag[24] = "";
	if (!strcasestr(to, ";tag=")) {
		uint32_t h = fnv1a(2166136261u, call_id);
		h = fnv1a(h, from);
		h = fnv1a(h, cseq);
		snprintf(tag, sizeof(tag), ";tag=ir%08x", h);
	}

	char resp[2048];
	int len = snprintf(resp, sizeof(resp),
		"SIP/2.0 %s\r\n"
		"%s"
		"From: %s\r\n"
		"To: %s%s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %s\r\n"
		"Content-Length: 0\r\n\r\n",
		status, vias, from, to, tag, call_id, cseq);
	if (len > 0 && (size_t)len < sizeof(resp))
		send_sip_msg(ctx, resp, (size_t)len);
}

static void schedule_reg_retry(struct imsd_sip_ctx *ctx);

/* The Contact feature tag that asks for SMS over IP (TS 24.341 5.3.1.2), when the carrier does it. */
static const char *contact_sms(const struct imsd_sip_ctx *ctx)
{
	return ctx->cfg.car.sms_over_ip ? ";+g.3gpp.smsip" : "";
}

/* REGISTER's Contact parameters: smsip, and the IMEI instance id when the carrier wants it. */
static const char *contact_reg(const struct imsd_sip_ctx *ctx)
{
	static char buf[160];
	snprintf(buf, sizeof(buf), "%s%s", contact_sms(ctx), ctx->instance);
	return buf;
}

/*
 * The Expires we ask for. 600000 s unless the registrar answered 423 Interval
 * Too Brief with a larger Min-Expires (RFC 3261 10.2.8), which then sticks.
 */
#define IMSD_REG_EXPIRES 600000u
static uint32_t reg_req_expires(const struct imsd_sip_ctx *ctx)
{
	return ctx->reg_min_expires > IMSD_REG_EXPIRES ? ctx->reg_min_expires : IMSD_REG_EXPIRES;
}

static void arm_reg_retry(struct imsd_sip_ctx *ctx, uint64_t delay_sec);

/*
 * sec-agree did not come up: drop the SAs and start over with a fresh
 * initial REGISTER that offers it again, after a back-off. Never without
 * IPsec: TTAK.KO-06.0357/R6 deleted the R5 fallback ("IPSec off 기능 삭제").
 */
static void sec_restart(struct imsd_sip_ctx *ctx, const char *why)
{
	uint64_t delay = 30ULL << (ctx->reg_retry_count < 5 ? ctx->reg_retry_count : 5);
	if (delay > 900)
		delay = 900;
	imsroha_ipsec_remove(&ctx->sec);
	ctx->sec_state = IMSD_SEC_OFFERED;
	ctx->ua_port = ctx->sip_port;
	ctx->reg_state = IMSD_REGISTERING;
	fprintf(stderr, "imsroha: sec-agree failed (%s), registering again with IPsec in %" PRIu64 " s\n",
		why, delay);
	arm_reg_retry(ctx, delay);
}

/*
 * The sec-agree lines of a REGISTER (TS 24.229 5.1.1.2.1, RFC 3329): our
 * Security-Client, and once the SAs are up the P-CSCF's Security-Server back
 * as Security-Verify. Empty when sec-agree is off or was given up.
 */
static void sec_lines(struct imsd_sip_ctx *ctx, char *out, size_t size)
{
	char client[512];

	out[0] = '\0';
	if (ctx->sec_state != IMSD_SEC_OFFERED && ctx->sec_state != IMSD_SEC_PROTECTED)
		return;
	if (imsroha_ipsec_client_header(&ctx->sec, client, sizeof(client)) < 0)
		return;
	int n = snprintf(out, size, "Security-Client: %s\r\n", client);
	if (ctx->sec_state == IMSD_SEC_PROTECTED && n > 0 && (size_t)n < size)
		n += snprintf(out + n, size - n, "Security-Verify: %s\r\n", ctx->sec.server_line);
	if (n > 0 && (size_t)n < size)
		snprintf(out + n, size - n, "Require: sec-agree\r\nProxy-Require: sec-agree\r\n");
}

static const char *sec_supported(const struct imsd_sip_ctx *ctx)
{
	return ctx->sec_state == IMSD_SEC_OFFERED || ctx->sec_state == IMSD_SEC_PROTECTED ?
	       "path, sec-agree" : "path";
}

int imsd_sip_register(struct imsd_sip_ctx *ctx)
{
	char branch[32];
	snprintf(branch, sizeof(branch), "z9hG4bK%08x", (unsigned)rand());

	/*
	 * Every REGISTER offers fresh SPIs (TS 24.229 5.1.1.4.1, TS 33.203 7.4):
	 * if the network challenges it, the 401 leads to a new SA set on them;
	 * if it does not, the SAs in use simply carry on.
	 */
	char sec[1200];
	if (ctx->sec_state == IMSD_SEC_OFFERED || ctx->sec_state == IMSD_SEC_PROTECTED)
		imsroha_ipsec_new_spis(&ctx->sec);
	sec_lines(ctx, sec, sizeof(sec));
	/* R5 5.2.2 wanted algorithm=AKAv1-MD5 here; R6 dropped that, so: as LG U+ has it. */
	const char *alg = "";

	char req[3072];
	int len = snprintf(req, sizeof(req),
		"REGISTER sip:%s SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [%s]:%u;branch=%s;rport\r\n"
		"From: <%s>;tag=%s\r\n"
		"To: <%s>\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %u REGISTER\r\n"
		"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\"%s\r\n"
		"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"\", uri=\"sip:%s\", response=\"\"%s\r\n"
		"%s"
		"Max-Forwards: 70\r\n"
		"Expires: %u\r\n"
		"Supported: %s\r\n"
		"P-Access-Network-Info: %s\r\n"
		"User-Agent: %s\r\n"
		"Content-Length: 0\r\n\r\n",
		ctx->domain, ctx->local_ip, ctx->ua_port, branch, ctx->reg_impu, ctx->reg_from_tag, ctx->reg_impu, ctx->reg_call_id, ctx->reg_cseq++,
		ctx->impu_user, ctx->local_ip, ctx->ua_port, contact_reg(ctx), ctx->impi, ctx->domain, ctx->domain, alg,
		sec, reg_req_expires(ctx), sec_supported(ctx), ctx->pani, ctx->user_agent);

	/* A refresh keeps the account usable; only the first REGISTER is "registering". */
	if (ctx->reg_state != IMSD_UP)
		ctx->reg_state = IMSD_REGISTERING;
	fprintf(stderr, "imsroha: sending REGISTER (CSeq %u)...\n", ctx->reg_cseq - 1);
	schedule_reg_retry(ctx);
	return send_sip_msg(ctx, req, len);
}

static int handle_401_challenge(struct imsd_sip_ctx *ctx, const char *msg)
{
	char auth_hdr[512];
	if (find_header(msg, "WWW-Authenticate", auth_hdr, sizeof(auth_hdr)) < 0) {
		fprintf(stderr, "imsroha: 401 missing WWW-Authenticate\n");
		return -EINVAL;
	}

	char nonce_str[128] = "";
	char realm_str[128];
	snprintf(realm_str, sizeof(realm_str), "%s", ctx->domain);
	char alg_str[32] = "AKAv1-MD5";
	find_param(auth_hdr, "nonce", nonce_str, sizeof(nonce_str));
	find_param(auth_hdr, "realm", realm_str, sizeof(realm_str));
	find_param(auth_hdr, "algorithm", alg_str, sizeof(alg_str));

	if (!nonce_str[0]) {
		fprintf(stderr, "imsroha: 401 missing nonce\n");
		return -EINVAL;
	}

	unsigned char nonce_bin[64];
	int nonce_len = b64_decode(nonce_str, strlen(nonce_str), nonce_bin, sizeof(nonce_bin));
	if (nonce_len < 32) {
		fprintf(stderr, "imsroha: nonce decode failed or too short (%d bytes)\n", nonce_len);
		return -EINVAL;
	}

	struct imsd_aka_challenge ch;
	struct imsd_aka_result res;
	memcpy(ch.rand, nonce_bin, 16);
	memcpy(ch.autn, nonce_bin + 16, 16);

	fprintf(stderr, "imsroha: executing AKA on ISIM via QMI UIM...\n");
	int r = imsd_aka_run_isim(&ch, &res);
	if (r < 0 || !res.success) {
		fprintf(stderr, "imsroha: imsd_aka_run_isim failed: %d\n", r);
		return -EIO;
	}

	/*
	 * sec-agree: take the P-CSCF's Security-Server and bring the SAs up with
	 * this challenge's IK and CK; the answer goes out over them. Without a
	 * usable Security-Server, or when the SAs cannot be installed, there is
	 * no answer at all: TTAK.KO-06.0357/R6 5.2.2 has no unprotected way.
	 */
	if (ctx->sec_state == IMSD_SEC_OFFERED || ctx->sec_state == IMSD_SEC_PROTECTED) {
		char ss[1024] = "";
		char pcscf[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ctx->pcscf_addr.sin6_addr, pcscf, sizeof(pcscf));
		if (res.is_sync_failure) {
			/* No keys from a sync failure: answer with AUTS over what is there. */
		} else if (find_header(msg, "Security-Server", ss, sizeof(ss)) < 0 ||
			   imsroha_ipsec_parse_server(&ctx->sec, ss) < 0) {
			sec_restart(ctx, "the 401 has no Security-Server matching our offer");
			return -EPROTO;
		} else if (imsroha_ipsec_install(&ctx->sec, ctx->local_ip, pcscf, res.ik, res.ck) < 0) {
			/* Most likely a kernel without XFRM_USER or INET6_ESP. */
			sec_restart(ctx, "ip xfrm could not install the SAs (kernel without XFRM_USER/INET6_ESP?)");
			return -EIO;
		} else {
			ctx->sec_state = IMSD_SEC_PROTECTED;
			ctx->ua_port = ctx->sec.port_us;
		}
	}

	char branch[32];
	snprintf(branch, sizeof(branch), "z9hG4bK%08x", (unsigned)rand());

	char auth_line[512];
	if (res.is_sync_failure) {
		char auts_b64[64];
		b64_encode(res.auts, res.auts_len, auts_b64, sizeof(auts_b64));

		/* RFC 3310 empty password digest */
		char ha1_in[320];
		snprintf(ha1_in, sizeof(ha1_in), "%s:%s:",
		ctx->impi, realm_str);
		char ha1[33];
		md5_hex(ha1_in, strlen(ha1_in), ha1);

		char ha2_in[256];
		snprintf(ha2_in, sizeof(ha2_in), "REGISTER:sip:%s", ctx->domain);
		char ha2[33];
		md5_hex(ha2_in, strlen(ha2_in), ha2);

		char resp_in[128];
		snprintf(resp_in, sizeof(resp_in), "%s:%s:%s", ha1, nonce_str, ha2);
		char resp_digest[33];
		md5_hex(resp_in, strlen(resp_in), resp_digest);

		snprintf(auth_line, sizeof(auth_line),
			"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"sip:%s\", response=\"%s\", algorithm=%s, auts=\"%s\"\r\n",
		ctx->impi, realm_str, nonce_str, ctx->domain, resp_digest, alg_str, auts_b64);
		fprintf(stderr, "imsroha: resending REGISTER with AUTS...\n");
	} else {
		/* HA1 = MD5(username:realm:RES_BIN) */
		unsigned char ha1_raw[256];
		int ha1_len = snprintf((char *)ha1_raw, sizeof(ha1_raw), "%s:%s:",
		ctx->impi, realm_str);
		memcpy(ha1_raw + ha1_len, res.res, res.res_len);
		ha1_len += res.res_len;

		char ha1[33];
		md5_hex(ha1_raw, ha1_len, ha1);

		char ha2_in[256];
		snprintf(ha2_in, sizeof(ha2_in), "REGISTER:sip:%s", ctx->domain);
		char ha2[33];
		md5_hex(ha2_in, strlen(ha2_in), ha2);

		char resp_in[128];
		snprintf(resp_in, sizeof(resp_in), "%s:%s:%s", ha1, nonce_str, ha2);
		char resp_digest[33];
		md5_hex(resp_in, strlen(resp_in), resp_digest);

		snprintf(auth_line, sizeof(auth_line),
			"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"sip:%s\", response=\"%s\", algorithm=%s\r\n",
		ctx->impi, realm_str, nonce_str, ctx->domain, resp_digest, alg_str);
		fprintf(stderr, "imsroha: sending authenticated REGISTER (RES len %zu)...\n", res.res_len);
	}

	char sec[1200];
	sec_lines(ctx, sec, sizeof(sec));

	char req[3072];
	int len = snprintf(req, sizeof(req),
		"REGISTER sip:%s SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [%s]:%u;branch=%s;rport\r\n"
		"From: <%s>;tag=%s\r\n"
		"To: <%s>\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %u REGISTER\r\n"
		"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\"%s\r\n"
		"%s"
		"%s"
		"Max-Forwards: 70\r\n"
		"Expires: %u\r\n"
		"Supported: %s\r\n"
		"P-Access-Network-Info: %s\r\n"
		"User-Agent: %s\r\n"
		"Content-Length: 0\r\n\r\n",
		ctx->domain, ctx->local_ip, ctx->ua_port, branch, ctx->reg_impu, ctx->reg_from_tag, ctx->reg_impu, ctx->reg_call_id, ctx->reg_cseq++,
		ctx->impu_user, ctx->local_ip, ctx->ua_port, contact_reg(ctx), auth_line, sec,
		reg_req_expires(ctx), sec_supported(ctx), ctx->pani, ctx->user_agent);

	schedule_reg_retry(ctx);
	return send_sip_msg(ctx, req, len);
}

static int on_reg_retry_timer(sd_event_source *s, uint64_t usec, void *userdata)
{
	(void)s; (void)usec;
	struct imsd_sip_ctx *ctx = userdata;
	ctx->reg_retry_count++;
	/*
	 * No answer over the SAs: the authenticated REGISTER that should have
	 * completed sec-agree, or two refreshes in a row. Start over with new
	 * SAs (an initial REGISTER offering sec-agree again).
	 */
	if (ctx->sec_state == IMSD_SEC_PROTECTED && (ctx->reg_state != IMSD_UP || ctx->reg_retry_count >= 2)) {
		fprintf(stderr, "imsroha: no answer over IPsec, starting sec-agree over\n");
		imsroha_ipsec_remove(&ctx->sec);
		ctx->sec_state = IMSD_SEC_OFFERED;
		ctx->ua_port = ctx->sip_port;
	}
	/* TS 24.229 5.1.1.2.1: a P-CSCF that stays silent is replaced by the next one. */
	if (ctx->pcscf_n > 1 && ctx->reg_retry_count % 2 == 0) {
		char a[INET6_ADDRSTRLEN];
		ctx->pcscf_cur = (ctx->pcscf_cur + 1) % ctx->pcscf_n;
		ctx->pcscf_addr = ctx->pcscf_list[ctx->pcscf_cur];
		inet_ntop(AF_INET6, &ctx->pcscf_addr.sin6_addr, a, sizeof(a));
		fprintf(stderr, "imsroha: no answer, trying P-CSCF [%s]:%u\n", a, ntohs(ctx->pcscf_addr.sin6_port));
	}
	fprintf(stderr, "imsroha: REGISTER timed out (retry #%d), resending...\n", ctx->reg_retry_count);
	imsd_sip_register(ctx);
	return 0;
}

static void arm_reg_retry(struct imsd_sip_ctx *ctx, uint64_t delay_sec)
{
	uint64_t now_usec = 0;
	sd_event_now(ctx->event, CLOCK_BOOTTIME, &now_usec);
	uint64_t next_usec = now_usec + delay_sec * 1000000ULL;

	if (ctx->reg_retry_timer) {
		sd_event_source_set_time(ctx->reg_retry_timer, next_usec);
		sd_event_source_set_enabled(ctx->reg_retry_timer, SD_EVENT_ONESHOT);
	} else {
		sd_event_add_time(ctx->event, &ctx->reg_retry_timer, CLOCK_BOOTTIME,
				  next_usec, 500000ULL, on_reg_retry_timer, ctx);
	}
}

/* Resend a REGISTER that got no answer: 4, 8, 16, then every 30 s. */
static void schedule_reg_retry(struct imsd_sip_ctx *ctx)
{
	uint64_t delay_sec = 4ULL << (ctx->reg_retry_count < 3 ? ctx->reg_retry_count : 3);
	arm_reg_retry(ctx, delay_sec > 30 ? 30 : delay_sec);
}

/*
 * A final error to REGISTER (401 is the AKA challenge and handled apart).
 * The no-answer retry would resend it every 30 s forever; a network that
 * says no gets a growing back-off instead, 30 s doubling up to 15 min, or the
 * Retry-After it asks for (RFC 3261 20.33). Registration is never given up
 * for good: after a modem reset the P-CSCF can refuse a stale binding for a
 * while and then accept a fresh one.
 */
static void handle_register_rejected(struct imsd_sip_ctx *ctx, const char *msg, int status_code)
{
	if (status_code == 494 && ctx->cfg.car.ipsec && ctx->sec_state == IMSD_SEC_PROTECTED) {
		/* RFC 3329 2.3.1: Security Agreement Required. Offer it again. */
		fprintf(stderr, "imsroha: REGISTER 494, offering sec-agree again\n");
		imsroha_ipsec_remove(&ctx->sec);
		ctx->sec_state = IMSD_SEC_OFFERED;
		ctx->ua_port = ctx->sip_port;
		imsd_sip_register(ctx);
		return;
	}
	if (status_code == 423) {
		/* Too short an Expires: ask again at once with the registrar's minimum. */
		char min_exp[32] = "";
		unsigned long me = 0;
		if (find_header(msg, "Min-Expires", min_exp, sizeof(min_exp)) == 0)
			me = strtoul(min_exp, NULL, 10);
		if (me > reg_req_expires(ctx) && me <= UINT32_MAX) {
			ctx->reg_min_expires = (uint32_t)me;
			fprintf(stderr, "imsroha: REGISTER 423, retrying with Expires %u\n",
				ctx->reg_min_expires);
			imsd_sip_register(ctx);
			return;
		}
		/* No usable Min-Expires: an answer we cannot satisfy, back off like any other. */
	}

	uint64_t delay_sec = 30ULL << (ctx->reg_retry_count < 5 ? ctx->reg_retry_count : 5);
	if (delay_sec > 900)
		delay_sec = 900;

	char retry_after[32] = "";
	if (find_header(msg, "Retry-After", retry_after, sizeof(retry_after)) == 0) {
		unsigned long ra = strtoul(retry_after, NULL, 10);
		if (ra > 0 && ra <= 3600)
			delay_sec = ra;
	}
	fprintf(stderr, "imsroha: REGISTER rejected (SIP %d), next attempt in %" PRIu64 " s\n",
		status_code, delay_sec);
	arm_reg_retry(ctx, delay_sec);
}

static void cancel_reg_retry(struct imsd_sip_ctx *ctx)
{
	ctx->reg_retry_count = 0;
	if (ctx->reg_retry_timer)
		sd_event_source_set_enabled(ctx->reg_retry_timer, SD_EVENT_OFF);
}

static int on_reg_timer(sd_event_source *s, uint64_t usec, void *userdata)
{
	(void)s; (void)usec;
	struct imsd_sip_ctx *ctx = userdata;
	fprintf(stderr, "imsroha: refreshing SIP registration...\n");
	imsd_sip_register(ctx);
	return 0;
}

static void schedule_reg_refresh(struct imsd_sip_ctx *ctx, uint32_t expires)
{
	uint64_t now_usec = 0;
	sd_event_now(ctx->event, CLOCK_BOOTTIME, &now_usec);
	uint64_t refresh_interval_usec = (uint64_t)(expires > 120 ? expires / 2 : 60) * 1000000ULL;

	if (ctx->reg_timer) {
		sd_event_source_set_time(ctx->reg_timer, now_usec + refresh_interval_usec);
		sd_event_source_set_enabled(ctx->reg_timer, SD_EVENT_ONESHOT);
	} else {
		sd_event_add_time(ctx->event, &ctx->reg_timer, CLOCK_BOOTTIME,
				  now_usec + refresh_interval_usec, 1000000ULL,
				  on_reg_timer, ctx);
	}
}

static void setup_remote_rtp(struct imsd_sip_ctx *ctx, const char *ip, uint16_t port)
{
	if (!ip || !ip[0] || port == 0)
		return;

	snprintf(ctx->remote_rtp_ip, sizeof(ctx->remote_rtp_ip), "%s", ip);
	ctx->remote_rtp_port = port;

	memset(&ctx->remote_rtp_addr, 0, sizeof(ctx->remote_rtp_addr));
	ctx->remote_rtp_addr.sin6_family = AF_INET6;
	ctx->remote_rtp_addr.sin6_port = htons(port);
	if (inet_pton(AF_INET6, ip, &ctx->remote_rtp_addr.sin6_addr) <= 0) {
		fprintf(stderr, "imsroha: inet_pton failed for remote RTP IP '%s'\n", ip);
	} else {
		fprintf(stderr, "imsroha: remote RTP target set to [%s]:%u\n", ip, port);
	}
}

static void imsd_audio_start(struct imsd_sip_ctx *ctx)
{
	if (!ctx->codec_open)
		ctx->codec_open = imsd_codec_open(&ctx->codec) == 0;
	imsd_audio_call_start();
}

static void imsd_audio_stop(struct imsd_sip_ctx *ctx)
{
	imsd_audio_call_end();
	if (ctx->codec_open) {
		imsd_codec_close(&ctx->codec);
		ctx->codec_open = 0;
	}
}

static int dtmf_char_to_event(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c == '*')
		return 10;
	if (c == '#')
		return 11;
	if (c >= 'A' && c <= 'D')
		return 12 + (c - 'A');
	if (c >= 'a' && c <= 'd')
		return 12 + (c - 'a');
	return -1;
}

/*
 * Send what the far end's SDP accepts: AMR-WB if it lists it, else AMR-NB.
 * An interconnect answer can drop AMR-WB even when early media used it.
 */
static enum imsd_codec active_codec(const struct imsd_sip_ctx *ctx)
{
	return (ctx->call_has_wb || !ctx->call_has_nb) ? IMSD_CODEC_AMRWB : IMSD_CODEC_AMRNB;
}

/*
 * The telephone-event payload type for the speech codec in use, or -1. It
 * must run at that codec's clock (RFC 4733 2.1) and be one the far end's SDP
 * listed; an event under a payload type it never agreed to is noise to it.
 */
static int dtmf_pt(const struct imsd_sip_ctx *ctx, enum imsd_codec codec)
{
	if (codec == IMSD_CODEC_AMRNB)
		return ctx->call_has_dtmf_nb ? ctx->call_pt_dtmf_nb : -1;
	return ctx->call_has_dtmf_wb ? ctx->call_pt_dtmf_wb : -1;
}

int imsd_sip_send_dtmf(struct imsd_sip_ctx *ctx, const char *dtmf)
{
	if (!ctx || !dtmf || !dtmf[0])
		return -EINVAL;
	if (dtmf_pt(ctx, active_codec(ctx)) < 0)
		return -ENOTSUP;

	size_t n = strlen(dtmf);
	for (size_t i = 0; i < n; i++)
		if (dtmf_char_to_event(dtmf[i]) < 0)
			return -EINVAL;
	if (ctx->dtmf_q_len + n > sizeof(ctx->dtmf_queue))
		return -ENOSPC;

	memcpy(ctx->dtmf_queue + ctx->dtmf_q_len, dtmf, n);
	ctx->dtmf_q_len += n;
	fprintf(stderr, "imsroha: queued DTMF \"%s\" (queue len %zu)\n", dtmf, ctx->dtmf_q_len);
	return 0;
}

/* ---- downlink playout ---- */

static void playout_reset(struct imsd_sip_ctx *ctx, uint32_t ts, uint32_t step, int wb)
{
	memset(ctx->playout, 0, sizeof(ctx->playout));
	ctx->playout_step = step;
	ctx->playout_wb = wb;
	ctx->playout_ts = ts - IMSD_PLAYOUT_DELAY * step;
	ctx->playout_started = 1;
}

/* A received speech or SID frame: keep it until its 20 ms turn. */
static void playout_put(struct imsd_sip_ctx *ctx, uint32_t ts, int wb,
			const uint8_t *frame, size_t len)
{
	uint32_t step = wb ? 320 : 160;
	int32_t ahead;

	if (len > sizeof(ctx->playout[0].frame))
		return;
	if (!ctx->playout_started || step != ctx->playout_step) {
		/* First frame of the call, or the far end switched AMR-WB/AMR-NB. */
		if (ctx->playout_started)
			ctx->playout_resyncs++;
		playout_reset(ctx, ts, step, wb);
	}
	ahead = (int32_t)(ts - ctx->playout_ts);
	if (ahead < 0) {
		ctx->playout_late++;	/* its turn has passed */
		return;
	}
	if ((uint32_t)ahead / step >= IMSD_PLAYOUT_SLOTS) {
		/* Far ahead of playout (a long stall, or a timestamp jump). */
		ctx->playout_resyncs++;
		playout_reset(ctx, ts, step, wb);
	}
	unsigned int i = (ts / step) % IMSD_PLAYOUT_SLOTS;
	memcpy(ctx->playout[i].frame, frame, len);
	ctx->playout[i].len = (uint8_t)len;
	ctx->playout[i].wb = (uint8_t)wb;
	ctx->playout[i].ts = ts;
	ctx->playout[i].valid = 1;
}

/* One 20 ms tick: play the frame whose turn it is, or NO_DATA if it is missing. */
static void playout_tick(struct imsd_sip_ctx *ctx)
{
	static const uint8_t no_data = 0x7c; /* FT=15 NO_DATA, Q=1: same ToC for AMR and AMR-WB */
	int16_t pcm_out[IMSD_AUDIO_FRAME];
	const uint8_t *frame = &no_data;
	size_t len = 1;

	if (!ctx->codec_open || !ctx->playout_started)
		return;
	unsigned int i = (ctx->playout_ts / ctx->playout_step) % IMSD_PLAYOUT_SLOTS;
	if (ctx->playout[i].valid && ctx->playout[i].ts == ctx->playout_ts) {
		frame = ctx->playout[i].frame;
		len = ctx->playout[i].len;
	} else {
		ctx->playout_filled++;
	}
	if (imsd_codec_decode(&ctx->codec, ctx->playout_wb ? IMSD_CODEC_AMRWB : IMSD_CODEC_AMRNB,
			      frame, len, pcm_out) == 0)
		imsd_audio_downlink(pcm_out);
	ctx->playout[i].valid = 0;
	ctx->playout_ts += ctx->playout_step;
}

static int on_rtp_tx_timer(sd_event_source *s, uint64_t usec, void *userdata)
{
	struct imsd_sip_ctx *ctx = userdata;
	playout_tick(ctx);
	if (ctx->rtp_fd < 0 || ctx->remote_rtp_port == 0)
		goto reschedule;

	/*
	 * RFC 4867 octet-aligned, one frame per packet: RTP header, CMR, then the
	 * frame in AMR-WB storage format, whose first byte is already the ToC
	 * (FT << 3 | Q << 2, F = 0). Mode 2 (12.65 kbit/s) is 1 + 32 bytes.
	 */
	unsigned char pkt[12 + 1 + 1 + 60];
	size_t pkt_len = 12 + 1;
	int16_t pcm_in[IMSD_AUDIO_FRAME];

	enum imsd_codec codec = active_codec(ctx);
	uint16_t step_ticks = (uint16_t)imsd_codec_ticks(codec);
	int pt_dtmf = dtmf_pt(ctx, codec);

	if (pt_dtmf < 0 && (ctx->dtmf_q_len || ctx->dtmf_active_event >= 0)) {
		/* A re-INVITE or UPDATE dropped telephone-event mid-sequence. */
		fprintf(stderr, "imsroha: telephone-event no longer negotiated, dropping %zu queued DTMF\n",
			ctx->dtmf_q_len);
		ctx->dtmf_q_len = 0;
		ctx->dtmf_active_event = -1;
	}

	if (ctx->dtmf_gap_frames > 0) {
		ctx->dtmf_gap_frames--;
	} else if (ctx->dtmf_active_event < 0 && ctx->dtmf_q_len > 0) {
		ctx->dtmf_active_event = dtmf_char_to_event(ctx->dtmf_queue[0]);
		memmove(ctx->dtmf_queue, ctx->dtmf_queue + 1, --ctx->dtmf_q_len);
		ctx->dtmf_duration = 0;
		ctx->dtmf_end_sent = 0;
		ctx->dtmf_start_ts = ctx->rtp_tx_ts;
	}

	if (ctx->dtmf_active_event >= 0) {
		/* Drain uplink PCM so the user-session socket does not back up during DTMF. */
		(void)imsd_audio_uplink(pcm_in);

		int first_pkt = (ctx->dtmf_duration == 0 && ctx->dtmf_end_sent == 0);
		uint16_t max_dur = step_ticks * 5; /* 100 ms tone */
		int is_end = 0;

		if (ctx->dtmf_duration < max_dur) {
			ctx->dtmf_duration += step_ticks;
		} else {
			is_end = 1;
			ctx->dtmf_end_sent++;
		}

		pkt[0] = 0x80;
		pkt[1] = (uint8_t)((first_pkt ? 0x80 : 0x00) | (pt_dtmf & 0x7f));
		pkt[2] = (ctx->rtp_tx_seq >> 8) & 0xff;
		pkt[3] = ctx->rtp_tx_seq & 0xff;
		pkt[4] = (ctx->dtmf_start_ts >> 24) & 0xff;
		pkt[5] = (ctx->dtmf_start_ts >> 16) & 0xff;
		pkt[6] = (ctx->dtmf_start_ts >> 8) & 0xff;
		pkt[7] = ctx->dtmf_start_ts & 0xff;
		pkt[8] = 0x12;
		pkt[9] = 0x34;
		pkt[10] = 0x56;
		pkt[11] = 0x78;
		/* RFC 4733 2.3: event (8b), E|R|volume (8b), duration (16b) */
		pkt[12] = (uint8_t)ctx->dtmf_active_event;
		pkt[13] = (uint8_t)((is_end ? 0x80 : 0x00) | 10);
		pkt[14] = (ctx->dtmf_duration >> 8) & 0xff;
		pkt[15] = ctx->dtmf_duration & 0xff;
		pkt_len = 16;

		ctx->rtp_tx_seq++;
		ctx->rtp_tx_ts += step_ticks;
		ctx->rtp_tx_pkts++;

		sendto(ctx->rtp_fd, pkt, pkt_len, 0,
		       (struct sockaddr *)&ctx->remote_rtp_addr, sizeof(ctx->remote_rtp_addr));

		if (first_pkt || ctx->dtmf_end_sent == 3) {
			fprintf(stderr, "imsroha: DTMF event %d %s (pt %d, dur %u)\n",
				ctx->dtmf_active_event, is_end ? "end" : "start",
				pt_dtmf, ctx->dtmf_duration);
		}
		if (ctx->dtmf_end_sent >= 3) {
			ctx->dtmf_active_event = -1;
			ctx->dtmf_gap_frames = 2; /* 40 ms inter-digit silence */
		}
		goto reschedule;
	}

	pkt[0] = 0x80; /* V=2, P=0, X=0, CC=0 */
	pkt[1] = (uint8_t)(codec == IMSD_CODEC_AMRNB ? ctx->call_pt_amr : ctx->call_pt_amrwb);
	pkt[2] = (ctx->rtp_tx_seq >> 8) & 0xff;
	pkt[3] = ctx->rtp_tx_seq & 0xff;
	pkt[4] = (ctx->rtp_tx_ts >> 24) & 0xff;
	pkt[5] = (ctx->rtp_tx_ts >> 16) & 0xff;
	pkt[6] = (ctx->rtp_tx_ts >> 8) & 0xff;
	pkt[7] = ctx->rtp_tx_ts & 0xff;
	pkt[8] = 0x12; /* SSRC: 0x12345678 */
	pkt[9] = 0x34;
	pkt[10] = 0x56;
	pkt[11] = 0x78;
	pkt[12] = 0xf0; /* CMR = 15: no mode request */

	int enc_len = 0;
	if (ctx->codec_open && imsd_audio_uplink(pcm_in))
		enc_len = imsd_codec_encode(&ctx->codec, codec, pcm_in, pkt + 13, sizeof(pkt) - 13);
	if (enc_len > 0) {
		pkt_len += enc_len;
	} else {
		pkt[13] = 0x7c; /* NO_DATA: FT=15, Q=1, no speech bits */
		pkt_len += 1;
		enc_len = 1;
	}
	if (!(codec == IMSD_CODEC_AMRNB ? ctx->call_nb_octet : ctx->call_wb_octet)) {
		/* Bandwidth-efficient: CMR, ToC and speech bits without padding between. */
		uint8_t st[64];
		memcpy(st, pkt + 13, (size_t)enc_len);
		int be = imsroha_amr_be_pack(codec != IMSD_CODEC_AMRNB, st, (size_t)enc_len, 15,
					     pkt + 12, sizeof(pkt) - 12);
		if (be > 0)
			pkt_len = 12 + (size_t)be;
	}

	ctx->rtp_tx_seq++;
	ctx->rtp_tx_ts += imsd_codec_ticks(codec);
	ctx->rtp_tx_pkts++;

	sendto(ctx->rtp_fd, pkt, pkt_len, 0,
	       (struct sockaddr *)&ctx->remote_rtp_addr, sizeof(ctx->remote_rtp_addr));

	if (ctx->rtp_tx_pkts == 1 || ctx->rtp_tx_pkts % 100 == 0) {
		fprintf(stderr, "imsroha: RTP tx #%" PRIu64 " (ts %u, len %zu) -> [%s]:%u\n",
			ctx->rtp_tx_pkts, ctx->rtp_tx_ts, pkt_len,
			ctx->remote_rtp_ip, ctx->remote_rtp_port);
	}

reschedule: ;
	uint64_t next_usec = usec + 20000; /* 20 ms */
	sd_event_source_set_time(s, next_usec);
	sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
	return 0;
}

static int on_rtp_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	(void)s; (void)revents;
	struct imsd_sip_ctx *ctx = userdata;
	unsigned char buf[1500];
	struct sockaddr_in6 from;
	socklen_t from_len = sizeof(from);

	ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
	if (n <= 0)
		return 0;

	ctx->rtp_rx_pkts++;
	ctx->rtp_rx_bytes += n;

	if (ctx->remote_rtp_port == 0 && from.sin6_family == AF_INET6) {
		memcpy(&ctx->remote_rtp_addr, &from, sizeof(from));
		ctx->remote_rtp_port = ntohs(from.sin6_port);
		inet_ntop(AF_INET6, &from.sin6_addr, ctx->remote_rtp_ip, sizeof(ctx->remote_rtp_ip));
		fprintf(stderr, "imsroha: learned remote RTP endpoint from incoming packet: [%s]:%u\n",
			ctx->remote_rtp_ip, ctx->remote_rtp_port);
	}

	if (n >= 12) {
		uint16_t seq = (buf[2] << 8) | buf[3];
		uint8_t pt = buf[1] & 0x7f;
		if (ctx->rtp_rx_pkts <= 5 || ctx->rtp_rx_pkts % 50 == 1) {
			fprintf(stderr, "imsroha: RTP rx #%" PRIu64 " (pt %u, seq %u, len %zd) [hdr: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x payload: %02x %02x %02x %02x]\n",
				ctx->rtp_rx_pkts, pt, seq, n,
				buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
				buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
				n > 12 ? buf[12] : 0, n > 13 ? buf[13] : 0, n > 14 ? buf[14] : 0, n > 15 ? buf[15] : 0);
		}

		/* Octet-aligned: byte 12 is the CMR, the storage-format frame follows. */
		/*
		 * Pick the decoder by payload type: the numbers we offered or
		 * answered with, or the far end's. Anything else (telephone-event,
		 * comfort noise) is not speech for the AMR decoders.
		 */
		int pt_rx = buf[1] & 0x7f;
		int is_wb = pt_rx == ctx->call_pt_amrwb || pt_rx == ctx->cfg.car.pt_amrwb ||
			    (ctx->cfg.car.pt_amrwb_be > 0 && pt_rx == ctx->cfg.car.pt_amrwb_be);
		int is_nb = pt_rx == ctx->call_pt_amr || pt_rx == ctx->cfg.car.pt_amr ||
			    (ctx->cfg.car.pt_amr_be > 0 && pt_rx == ctx->cfg.car.pt_amr_be);
		if (ctx->codec_open && n > 13 && (is_wb || is_nb)) {
			uint32_t ts = (uint32_t)buf[4] << 24 | (uint32_t)buf[5] << 16 |
				      (uint32_t)buf[6] << 8 | buf[7];
			int octet = pt_rx == ctx->call_pt_amrwb ? ctx->call_wb_octet :
				    pt_rx == ctx->call_pt_amr ? ctx->call_nb_octet :
				    pt_rx == ctx->cfg.car.pt_amrwb_be || pt_rx == ctx->cfg.car.pt_amr_be ? 0 : 1;
			if (octet) {
				playout_put(ctx, ts, is_wb, buf + 13, (size_t)(n - 13));
			} else {
				uint8_t st[64];
				int sl = imsroha_amr_be_unpack(is_wb, buf + 12, (size_t)(n - 12), st, sizeof(st));
				if (sl > 0)
					playout_put(ctx, ts, is_wb, st, (size_t)sl);
			}
		}
	}
	return 0;
}

static void imsd_rtp_start(struct imsd_sip_ctx *ctx)
{
	imsd_audio_start(ctx);
	if (ctx->rtp_fd < 0) {
		int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd < 0) {
			fprintf(stderr, "imsroha: failed to create RTP socket: %m\n");
			return;
		}

		int on = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		/* Same as the SIP socket: media only from the IMS PDN. */
		setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ctx->iface, strlen(ctx->iface) + 1);

		struct sockaddr_in6 addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(ctx->cfg.car.rtp_port);
		inet_pton(AF_INET6, ctx->local_ip, &addr.sin6_addr);

		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			fprintf(stderr, "imsroha: failed to bind RTP socket to port %u: %m\n", ctx->cfg.car.rtp_port);
			close(fd);
			return;
		}

		ctx->rtp_fd = fd;
		ctx->rtp_rx_pkts = 0;
		ctx->rtp_rx_bytes = 0;

		sd_event_add_io(ctx->event, &ctx->rtp_source, ctx->rtp_fd, EPOLLIN, on_rtp_packet, ctx);
		fprintf(stderr, "imsroha: RTP receiver listening on [%s]:%u\n", ctx->local_ip, ctx->cfg.car.rtp_port);
	}

	if (!ctx->rtp_tx_timer) {
		uint64_t now_usec = 0;
		sd_event_now(ctx->event, CLOCK_MONOTONIC, &now_usec);
		ctx->rtp_tx_seq = 1000;
		ctx->rtp_tx_ts = 160000;
		ctx->rtp_tx_pkts = 0;
		ctx->dtmf_q_len = 0;
		ctx->dtmf_active_event = -1;
		ctx->dtmf_duration = 0;
		ctx->dtmf_end_sent = 0;
		ctx->dtmf_gap_frames = 0;
		sd_event_add_time(ctx->event, &ctx->rtp_tx_timer, CLOCK_MONOTONIC,
				  now_usec + 20000, 1000, on_rtp_tx_timer, ctx);
		fprintf(stderr, "imsroha: started RTP TX timer (20ms) for uplink audio\n");
	}
}

static void imsd_rtp_stop(struct imsd_sip_ctx *ctx)
{
	imsd_audio_stop(ctx);
	if (ctx->rtp_tx_timer) {
		sd_event_source_unref(ctx->rtp_tx_timer);
		ctx->rtp_tx_timer = NULL;
	}
	if (ctx->rtp_source) {
		sd_event_source_unref(ctx->rtp_source);
		ctx->rtp_source = NULL;
	}
	if (ctx->rtp_fd >= 0) {
		close(ctx->rtp_fd);
		ctx->rtp_fd = -1;
	}
	if (ctx->rtp_rx_pkts > 0 || ctx->rtp_tx_pkts > 0) {
		fprintf(stderr, "imsroha: RTP session ended, rx %" PRIu64 " pkts (%" PRIu64 " bytes), tx %" PRIu64 " pkts; "
			"playout: %" PRIu64 " frames filled, %" PRIu64 " late, %" PRIu64 " resyncs\n",
			ctx->rtp_rx_pkts, ctx->rtp_rx_bytes, ctx->rtp_tx_pkts,
			ctx->playout_filled, ctx->playout_late, ctx->playout_resyncs);
	}
	ctx->playout_started = 0;
	ctx->playout_filled = ctx->playout_late = ctx->playout_resyncs = 0;
}

/*
 * The addr-spec of a name-addr header value: what is inside <...>, or for a
 * bare URI everything up to its header parameters. A Request-URI must be
 * this, never the raw Contact/From value with brackets and parameters.
 */
static void sip_uri_of(const char *value, char *out, size_t out_size)
{
	const char *start = strchr(value, '<');
	const char *end;

	if (start) {
		start++;
		end = strchr(start, '>');
	} else {
		start = value;
		while (*start == ' ')
			start++;
		end = strpbrk(start, "; \t");
	}
	size_t len = end ? (size_t)(end - start) : strlen(start);
	if (len >= out_size)
		len = out_size - 1;
	memcpy(out, start, len);
	out[len] = '\0';
}

static void extract_caller_number(const char *from_hdr, char *out, size_t out_max)
{
	out[0] = '\0';
	if (!from_hdr) return;

	const char *start = strstr(from_hdr, "sip:");
	if (!start)
		start = strstr(from_hdr, "tel:");
	if (start) {
		start += 4;
		const char *end = start;
		while (*end && *end != '@' && *end != ';' && *end != '>' && *end != ' ')
			end++;
		size_t len = (size_t)(end - start);
		if (len >= out_max) len = out_max - 1;
		memcpy(out, start, len);
		out[len] = '\0';
		return;
	}
	snprintf(out, out_max, "unknown");
}

static int handle_incoming_invite(struct imsd_sip_ctx *ctx, const char *msg, size_t msg_len)
{
	(void)msg_len;
	char via[1024] = "", from[256] = "", to[256] = "", call_id[128] = "", cseq[64] = "", contact[256] = "";
	find_all_vias(msg, via, sizeof(via));
	find_header(msg, "From", from, sizeof(from));
	find_header(msg, "To", to, sizeof(to));
	find_header(msg, "Call-ID", call_id, sizeof(call_id));
	find_header(msg, "CSeq", cseq, sizeof(cseq));
	find_header(msg, "Contact", contact, sizeof(contact));

	/*
	 * A retransmission of the INVITE we are already handling (same Call-ID
	 * and CSeq, RFC 3261 17.2.1): the network repeats it until it hears from
	 * us, and after a suspend they all arrive at once. Answer with the
	 * current provisional response again; it is not a new call.
	 */
	if (ctx->call_is_incoming && !strcmp(call_id, ctx->inc_call_id) && !strcmp(cseq, ctx->inc_cseq)) {
		fprintf(stderr, "imsroha: INVITE retransmission (Call-ID %s)\n", call_id);
		if (ctx->call_state == IMSD_CALL_RINGING) {
			char ringing[2048];
			int rlen = snprintf(ringing, sizeof(ringing),
				"SIP/2.0 180 Ringing\r\n"
				"%s"
				"From: %s\r\n"
				"To: %s;tag=%s\r\n"
				"Call-ID: %s\r\n"
				"CSeq: %s\r\n"
				"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\"\r\n"
				"Allow: " IMSD_ALLOW "\r\n"
				"Content-Length: 0\r\n\r\n",
				via, from, to, ctx->call_to_tag, call_id, cseq, ctx->impu_user, ctx->local_ip, ctx->ua_port);
			send_sip_msg(ctx, ringing, rlen);
		}
		return 0;
	}

	const char *active_cid = ctx->call_is_incoming ? ctx->inc_call_id : ctx->call_id;
	if (ctx->call_state == IMSD_CALL_ACTIVE && active_cid[0] && !strcmp(call_id, active_cid)) {
		fprintf(stderr, "imsroha: in-dialog re-INVITE (Call-ID %s, CSeq %s)\n", call_id, cseq);
		const char *body = strstr(msg, "\r\n\r\n");
		int has_offer = body && body[4];
		char sdp[1024];
		int sdp_len;
		if (has_offer) {
			/* Check the offer before it replaces the session we have. */
			if (!sdp_has_amr(body + 4)) {
				fprintf(stderr, "imsroha: re-INVITE offers no AMR, keeping the session\n");
				send_simple_response(ctx, "488 Not Acceptable Here", via, from, to, call_id, cseq);
				return 0;
			}
			char remote_ip[INET6_ADDRSTRLEN] = "";
			uint16_t remote_port = 0;
			if (parse_sdp_media(body + 4, remote_ip, sizeof(remote_ip), &remote_port) == 0)
				setup_remote_rtp(ctx, remote_ip, remote_port);
			parse_sdp_codecs(body + 4, ctx);
			sdp_len = build_local_sdp(ctx, sdp, sizeof(sdp), 1);
		} else {
			/* An offerless re-INVITE: the 200 OK carries our offer, the ACK the answer. */
			sdp_len = build_local_sdp(ctx, sdp, sizeof(sdp), 0);
		}
		if (sdp_len < 0) {
			send_simple_response(ctx, "500 Server Internal Error", via, from, to, call_id, cseq);
			return 0;
		}
		char to_with_tag[320];
		if (strcasestr(to, ";tag="))
			snprintf(to_with_tag, sizeof(to_with_tag), "%s", to);
		else
			snprintf(to_with_tag, sizeof(to_with_tag), "%s;tag=%s", to,
				 ctx->call_is_incoming ? ctx->call_to_tag : ctx->call_from_tag);
		char se_hdr[128] = "", se_val[64] = "";
		if (find_header(msg, "Session-Expires", se_val, sizeof(se_val)) == 0 && se_val[0])
			snprintf(se_hdr, sizeof(se_hdr), "Session-Expires: %s\r\nSupported: timer\r\n", se_val);
		char resp[3072];
		int len = snprintf(resp, sizeof(resp),
			"SIP/2.0 200 OK\r\n"
			"%s"
			"From: %s\r\n"
			"To: %s\r\n"
			"Call-ID: %s\r\n"
			"CSeq: %s\r\n"
			"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\"\r\n"
			"Allow: " IMSD_ALLOW "\r\n"
			"%s"
			"Content-Type: application/sdp\r\n"
			"Content-Length: %d\r\n\r\n"
			"%s",
			via, from, to_with_tag, call_id, cseq,
			ctx->impu_user, ctx->local_ip, ctx->ua_port, se_hdr, sdp_len, sdp);
		send_sip_msg(ctx, resp, len);
		return 0;
	}

	/*
	 * A second call while one is in progress. There is no call waiting, and
	 * taking it would overwrite the first call's dialog state.
	 */
	if (ctx->call_state != IMSD_CALL_IDLE && ctx->call_state != IMSD_CALL_TERMINATED) {
		fprintf(stderr, "imsroha: busy, rejecting INVITE (Call-ID %s)\n", call_id);
		send_simple_response(ctx, "486 Busy Here", via, from, to, call_id, cseq);
		return 0;
	}

	const char *offer = strstr(msg, "\r\n\r\n");
	if (offer && offer[4]) {
		if (!sdp_has_amr(offer + 4)) {
			fprintf(stderr, "imsroha: INVITE offers no AMR, rejecting (Call-ID %s)\n", call_id);
			send_simple_response(ctx, "488 Not Acceptable Here", via, from, to, call_id, cseq);
			return 0;
		}
	}

	char caller[64] = "";
	extract_caller_number(from, caller, sizeof(caller));
	fprintf(stderr, "imsroha: incoming VoLTE call from %s (Call-ID %s)\n", caller, call_id);
	fprintf(stderr, "imsroha: incoming INVITE message:\n%s\n", msg);

	sdp_new_session(ctx);
	snprintf(ctx->inc_via, sizeof(ctx->inc_via), "%s", via);
	snprintf(ctx->inc_from, sizeof(ctx->inc_from), "%s", from);
	snprintf(ctx->inc_to, sizeof(ctx->inc_to), "%s", to);
	snprintf(ctx->inc_call_id, sizeof(ctx->inc_call_id), "%s", call_id);
	snprintf(ctx->inc_cseq, sizeof(ctx->inc_cseq), "%s", cseq);
	snprintf(ctx->inc_contact, sizeof(ctx->inc_contact), "%s", contact);

	/* Parse remote SDP. Without one, our 200 OK offers and the ACK answers. */
	const char *body = strstr(msg, "\r\n\r\n");
	ctx->inc_offerless = !(body && body[4]);
	if (ctx->inc_offerless) {
		ctx->call_pt_amrwb = ctx->cfg.car.pt_amrwb;
		ctx->call_pt_amr = ctx->cfg.car.pt_amr;
		ctx->call_has_wb = ctx->call_has_nb = 1;
		ctx->call_has_dtmf_wb = ctx->call_has_dtmf_nb = 0;
	} else {
		char remote_ip[INET6_ADDRSTRLEN] = "";
		uint16_t remote_port = 0;
		if (parse_sdp_media(body + 4, remote_ip, sizeof(remote_ip), &remote_port) == 0) {
			setup_remote_rtp(ctx, remote_ip, remote_port);
		}
		parse_sdp_codecs(body + 4, ctx);
	}

	rand_hex(ctx->call_to_tag, 8);
	ctx->call_is_incoming = 1;
	ctx->active_call_id++;
	ctx->call_cseq = 1;

	/* 1. Send 100 Trying */
	char trying[2048];
	int tlen = snprintf(trying, sizeof(trying),
		"SIP/2.0 100 Trying\r\n"
		"%s"
		"From: %s\r\n"
		"To: %s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %s\r\n"
		"Content-Length: 0\r\n\r\n",
		via, from, to, call_id, cseq);
	send_sip_msg(ctx, trying, tlen);

	/* 2. Send 180 Ringing */
	char ringing[2048];
	int rlen = snprintf(ringing, sizeof(ringing),
		"SIP/2.0 180 Ringing\r\n"
		"%s"
		"From: %s\r\n"
		"To: %s;tag=%s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %s\r\n"
		"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\"\r\n"
		"Allow: " IMSD_ALLOW "\r\n"
		"Content-Length: 0\r\n\r\n",
		via, from, to, ctx->call_to_tag, call_id, cseq, ctx->impu_user, ctx->local_ip, ctx->ua_port);
	send_sip_msg(ctx, ringing, rlen);

	ctx->call_state = IMSD_CALL_RINGING;
	imsd_emit_call_added(ctx->bus, ctx->active_call_id, caller, 1);


	return 0;
}

static int handle_incoming_cancel(struct imsd_sip_ctx *ctx, const char *msg, size_t msg_len)
{
	(void)msg_len;
	char cancel_via[1024] = "", from[256] = "", to[256] = "", call_id[128] = "", cseq[64] = "";
	find_all_vias(msg, cancel_via, sizeof(cancel_via));
	find_header(msg, "From", from, sizeof(from));
	find_header(msg, "To", to, sizeof(to));
	find_header(msg, "Call-ID", call_id, sizeof(call_id));
	find_header(msg, "CSeq", cseq, sizeof(cseq));

	if (!ctx->call_is_incoming || ctx->call_state == IMSD_CALL_IDLE ||
	    ctx->call_state == IMSD_CALL_TERMINATED || strcmp(call_id, ctx->inc_call_id) != 0) {
		fprintf(stderr, "imsroha: ignoring CANCEL for unknown Call-ID %s\n", call_id);
		char err_resp[2048];
		int err_len = snprintf(err_resp, sizeof(err_resp),
			"SIP/2.0 481 Call/Transaction Does Not Exist\r\n"
			"%s"
			"From: %s\r\n"
			"To: %s\r\n"
			"Call-ID: %s\r\n"
			"CSeq: %s\r\n"
			"Content-Length: 0\r\n\r\n",
			cancel_via, from, to, call_id, cseq);
		send_sip_msg(ctx, err_resp, err_len);
		return 0;
	}

	/*
	 * The INVITE already got its 200 OK: the CANCEL crossed it and has no
	 * effect on the call (RFC 3261 9.2). The caller ends it with a BYE.
	 */
	if (ctx->call_state != IMSD_CALL_RINGING) {
		fprintf(stderr, "imsroha: CANCEL after the call was answered, ignoring (Call-ID %s)\n", call_id);
		send_simple_response(ctx, "200 OK", cancel_via, from, to, call_id, cseq);
		return 0;
	}

	fprintf(stderr, "imsroha: caller cancelled incoming call (Call-ID %s)\n", call_id);


	/* 1. 200 OK for CANCEL */
	char ok_resp[2048];
	int ok_len = snprintf(ok_resp, sizeof(ok_resp),
		"SIP/2.0 200 OK\r\n"
		"%s"
		"From: %s\r\n"
		"To: %s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %s\r\n"
		"Content-Length: 0\r\n\r\n",
		cancel_via, from, to, call_id, cseq);
	send_sip_msg(ctx, ok_resp, ok_len);

	/* 2. 487 Request Terminated for INVITE */
	char term_resp[2048];
	int term_len = snprintf(term_resp, sizeof(term_resp),
		"SIP/2.0 487 Request Terminated\r\n"
		"%s"
		"From: %s\r\n"
		"To: %s;tag=%s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %s\r\n"
		"Content-Length: 0\r\n\r\n",
		ctx->inc_via, ctx->inc_from, ctx->inc_to, ctx->call_to_tag,
		ctx->inc_call_id, ctx->inc_cseq);
	send_sip_msg(ctx, term_resp, term_len);

	ctx->call_state = IMSD_CALL_TERMINATED;
	ctx->call_is_incoming = 0;
	imsd_rtp_stop(ctx);
	imsd_emit_call_state_changed(ctx->bus, ctx->active_call_id, 6, 0);

	return 0;
}

/*
 * Locate the TPDU inside a TS 24.011 RP-DATA MT-SMS. Each RP address is a
 * length octet counting the octets that follow (type-of-address plus BCD
 * digits, TS 24.011 8.2.5.1/8.2.5.2), so an empty address is a single 0x00.
 */
static int rp_data_get_tpdu(const unsigned char *rp, size_t rp_len,
			    const unsigned char **out_tpdu, size_t *out_tpdu_len,
			    unsigned char *out_dcs)
{
	size_t idx = 2;

	if (rp_len < 6 || rp[0] != 0x01)
		return -EPROTO;

	size_t oa_len = rp[idx++];
	idx += oa_len;
	if (idx >= rp_len)
		return -EBADMSG;

	size_t da_len = rp[idx++];
	idx += da_len;
	if (idx >= rp_len)
		return -EBADMSG;

	size_t tpdu_len = rp[idx++];
	if (tpdu_len < 9 || idx + tpdu_len > rp_len)
		return -EBADMSG;

	const unsigned char *tpdu = rp + idx;
	size_t sender_digits = tpdu[1];
	size_t dcs_off = 3 + (sender_digits + 1) / 2 + 1;
	if (dcs_off >= tpdu_len)
		return -EBADMSG;

	*out_tpdu = tpdu;
	*out_tpdu_len = tpdu_len;
	*out_dcs = tpdu[dcs_off];
	return 0;
}

/*
 * ModemManager's 3GPP PDU parser takes the SMSC address prefix followed by
 * the TPDU. 0x00 means "no SMSC address", so the TPDU goes over untouched.
 */
static int tpdu_to_mm_hex(const unsigned char *tpdu, size_t tpdu_len, char *hex, size_t hex_size)
{
	if (tpdu_len == 0 || 2 + 2 * tpdu_len + 1 > hex_size)
		return -EMSGSIZE;

	size_t pos = 0;
	hex[pos++] = '0';
	hex[pos++] = '0';
	for (size_t i = 0; i < tpdu_len; i++) {
		hex[pos++] = "0123456789abcdef"[tpdu[i] >> 4];
		hex[pos++] = "0123456789abcdef"[tpdu[i] & 0x0f];
	}
	hex[pos] = '\0';
	return 0;
}


/*
 * Answer an incoming RP-DATA. TS 24.341 5.3.2.4: a bodiless 200 OK, then the
 * RP-ACK or RP-ERROR in a MESSAGE of our own to the SC that sent it, with
 * In-Reply-To naming the received MESSAGE. LG U+ takes the RP reply in the
 * 200 OK's body instead (sms-rp-ack=response in its carrier profile).
 */
static void send_rp_reply(struct imsd_sip_ctx *ctx, const char *via, const char *from,
			  const char *to, const char *tag, const char *call_id, const char *cseq,
			  const unsigned char *rp, size_t rp_len)
{
	unsigned char full[2048];
	int in_response = ctx->cfg.car.sms_rp_in_response;
	int len = snprintf((char *)full, sizeof(full),
		"SIP/2.0 200 OK\r\n"
		"%s"
		"From: %s\r\n"
		"To: %s;tag=%s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %s\r\n"
		"P-Access-Network-Info: %s\r\n"
		"%s"
		"Content-Length: %zu\r\n\r\n",
		via, from, to, tag, call_id, cseq, ctx->pani,
		in_response ? "Content-Type: application/vnd.3gpp.sms\r\n" : "",
		in_response ? rp_len : 0);
	if (len < 0 || (size_t)len + rp_len > sizeof(full))
		return;
	if (in_response) {
		memcpy(full + len, rp, rp_len);
		send_sip_msg(ctx, full, len + rp_len);
		return;
	}
	send_sip_msg(ctx, full, len);

	char sc[256], branch[32], ftag[16], cid[64], route[300] = "";
	sip_uri_of(from, sc, sizeof(sc));
	rand_hex(branch, 8);
	rand_hex(ftag, 8);
	rand_hex(cid, 16);
	if (ctx->reg_service_route[0])
		snprintf(route, sizeof(route), "Route: %s\r\n", ctx->reg_service_route);
	len = snprintf((char *)full, sizeof(full),
		"MESSAGE %s SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [%s]:%u;branch=z9hG4bK%s;rport\r\n"
		"%s"
		"From: <%s>;tag=%s\r\n"
		"To: <%s>\r\n"
		"Call-ID: %s@%s\r\n"
		"CSeq: 1 MESSAGE\r\n"
		"In-Reply-To: %s\r\n"
		"Max-Forwards: 70\r\n"
		"P-Access-Network-Info: %s\r\n"
		"P-Preferred-Identity: <%s>\r\n"
		"User-Agent: %s\r\n"
		"Content-Type: application/vnd.3gpp.sms\r\n"
		"Content-Length: %zu\r\n\r\n",
		sc, ctx->local_ip, ctx->ua_port, branch, route, ctx->impu, ftag, sc,
		cid, ctx->domain, call_id, ctx->pani, ctx->impu, ctx->user_agent, rp_len);
	if (len < 0 || (size_t)len + rp_len > sizeof(full))
		return;
	memcpy(full + len, rp, rp_len);
	send_sip_msg(ctx, full, len + rp_len);
}

static int handle_incoming_message(struct imsd_sip_ctx *ctx, const char *msg, size_t msg_len)
{
	char via[1024] = "", from[256] = "", to[256] = "", call_id[128] = "", cseq[64] = "";
	find_all_vias(msg, via, sizeof(via));
	find_header(msg, "From", from, sizeof(from));
	find_header(msg, "To", to, sizeof(to));
	find_header(msg, "Call-ID", call_id, sizeof(call_id));
	find_header(msg, "CSeq", cseq, sizeof(cseq));

	char tag[16];
	rand_hex(tag, 8);

	const char *body_start = strstr(msg, "\r\n\r\n");
	if (body_start)
		body_start += 4;
	size_t body_len = body_start ? msg_len - (body_start - msg) : 0;

	if (body_len >= 6 && (unsigned char)body_start[0] == 0x01) {
		/*
		 * RP-DATA (MT-SMS). The message is ours once the RP-ACK leaves, so it
		 * goes to the durable inbox first; ModemManager decodes the TPDU
		 * (text, concatenation, WAP Push) and acks the inbox entry.
		 */
		const unsigned char *rp = (const unsigned char *)body_start;
		const unsigned char *tpdu = NULL;
		size_t tpdu_len = 0;
		unsigned char dcs = 0;
		unsigned char mr = rp[1];
		char hex[2 + 2 * 255 + 1];
		char id[IMSD_INBOX_ID_LEN];
		int r = rp_data_get_tpdu(rp, body_len, &tpdu, &tpdu_len, &dcs);

		if (r == 0)
			r = tpdu_to_mm_hex(tpdu, tpdu_len, hex, sizeof(hex));
		if (r < 0) {
			char dump[2 * 256 + 1];
			size_t n = body_len < 256 ? body_len : 256;
			for (size_t i = 0; i < n; i++)
				snprintf(dump + 2 * i, 3, "%02x", rp[i]);
			fprintf(stderr, "imsroha: could not parse RP-DATA (%d), sending RP-ERROR: %s\n",
				r, dump);
			/* RP-ERROR, cause 111: protocol error, unspecified (TS 24.011 8.2.5.4) */
			const unsigned char rp_err[4] = { 0x04, mr, 0x01, 111 };
			send_rp_reply(ctx, via, from, to, tag, call_id, cseq, rp_err, sizeof(rp_err));
			return 0;
		}

		if (imsd_inbox_seen(hex)) {
			/* A retry of a message we already took: answer it, keep nothing. */
			const unsigned char rp_ack[2] = { 0x02, mr };
			send_rp_reply(ctx, via, from, to, tag, call_id, cseq, rp_ack, sizeof(rp_ack));
			fprintf(stderr, "imsroha: duplicate MT-SMS (MR 0x%02x), acked again\n", mr);
			return 0;
		}

		r = imsd_inbox_store(hex, id);
		if (r < 0) {
			fprintf(stderr, "imsroha: cannot store MT-SMS (MR 0x%02x): %s, sending RP-ERROR\n",
				mr, strerror(-r));
			/* RP-ERROR, cause 22: memory capacity exceeded, so the SMSC keeps it */
			const unsigned char rp_err[4] = { 0x04, mr, 0x01, 22 };
			send_rp_reply(ctx, via, from, to, tag, call_id, cseq, rp_err, sizeof(rp_err));
			return 0;
		}

		imsd_inbox_remember(hex);
		const unsigned char rp_ack[2] = { 0x02, mr };
		send_rp_reply(ctx, via, from, to, tag, call_id, cseq, rp_ack, sizeof(rp_ack));
		fprintf(stderr, "imsroha: stored MT-SMS %s (MR 0x%02x, DCS 0x%02x, %zu bytes), sent RP-ACK\n",
			id, mr, dcs, tpdu_len);
		imsd_emit_pdu_received(ctx->bus, id, hex);
		return 0;
	}

	/* Send standard 200 OK for other MESSAGE requests (e.g. carrier RP-ACK) */
	char ok_resp[2048];
	int ok_len = snprintf(ok_resp, sizeof(ok_resp),
		"SIP/2.0 200 OK\r\n"
		"%s"
		"From: %s\r\n"
		"To: %s;tag=%s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %s\r\n"
		"Content-Length: 0\r\n\r\n",
		via, from, to, tag, call_id, cseq);
	send_sip_msg(ctx, ok_resp, ok_len);

	if (body_len >= 2 && (unsigned char)body_start[0] == 0x03) {
		/* RP-ACK for MO-SMS */
		unsigned char mr = (unsigned char)body_start[1];
		fprintf(stderr, "imsroha: received RP-ACK for MO-SMS (MR 0x%02x)\n", mr);
		char ref_str[16];
		snprintf(ref_str, sizeof(ref_str), "%u", mr);

		if (ctx->pending_sms_msg) {
			sd_bus_reply_method_return(ctx->pending_sms_msg, "s", ref_str);
			sd_bus_message_unref(ctx->pending_sms_msg);
			ctx->pending_sms_msg = NULL;
			if (ctx->sms_timeout_timer) {
				sd_event_source_unref(ctx->sms_timeout_timer);
				ctx->sms_timeout_timer = NULL;
			}
		}
		return 0;
	}

	if (body_len >= 2 && (unsigned char)body_start[0] == 0x05) {
		/* RP-ERROR for MO-SMS */
		unsigned char mr = (unsigned char)body_start[1];
		fprintf(stderr, "imsroha: received RP-ERROR for MO-SMS (MR 0x%02x)\n", mr);
		if (ctx->pending_sms_msg) {
			sd_bus_reply_method_errorf(ctx->pending_sms_msg, SD_BUS_ERROR_FAILED,
						   "Carrier returned RP-ERROR for MR %u", mr);
			sd_bus_message_unref(ctx->pending_sms_msg);
			ctx->pending_sms_msg = NULL;
			if (ctx->sms_timeout_timer) {
				sd_event_source_unref(ctx->sms_timeout_timer);
				ctx->sms_timeout_timer = NULL;
			}
		}
		return 0;
	}

	return 0;
}

/*
 * The reg event package (TS 24.229 5.1.1.3, RFC 3680): one subscription for
 * the life of the registration, refreshed with it, in one dialog. A 489
 * means the network has none; then never again (TTAK.KO-06.0357 5.2.1).
 */
static void reg_event_subscribe(struct imsd_sip_ctx *ctx)
{
	if (!ctx->cfg.car.reg_event || ctx->sub_state < 0)
		return;
	if (!ctx->sub_call_id[0]) {
		char rnd[32];
		rand_hex(rnd, 16);
		snprintf(ctx->sub_call_id, sizeof(ctx->sub_call_id), "%s@%s", rnd, ctx->domain);
		rand_hex(ctx->sub_from_tag, 8);
		ctx->sub_to_tag[0] = '\0';
		ctx->sub_cseq = 1;
	}
	char branch[32], route[300] = "", to_tag[80] = "";
	rand_hex(branch, 8);
	if (ctx->reg_service_route[0])
		snprintf(route, sizeof(route), "Route: %s\r\n", ctx->reg_service_route);
	if (ctx->sub_to_tag[0])
		snprintf(to_tag, sizeof(to_tag), ";tag=%s", ctx->sub_to_tag);

	char req[2048];
	int len = snprintf(req, sizeof(req),
		"SUBSCRIBE %s SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [%s]:%u;branch=z9hG4bK%s;rport\r\n"
		"%s"
		"From: <%s>;tag=%s\r\n"
		"To: <%s>%s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %u SUBSCRIBE\r\n"
		"Contact: <sip:%s@[%s]:%u>\r\n"
		"Event: reg\r\n"
		"Accept: application/reginfo+xml\r\n"
		"Expires: %u\r\n"
		"Max-Forwards: 70\r\n"
		"P-Access-Network-Info: %s\r\n"
		"P-Preferred-Identity: <%s>\r\n"
		"User-Agent: %s\r\n"
		"Content-Length: 0\r\n\r\n",
		ctx->impu, ctx->local_ip, ctx->ua_port, branch, route, ctx->impu, ctx->sub_from_tag,
		ctx->impu, to_tag, ctx->sub_call_id, ctx->sub_cseq++, ctx->impu_user, ctx->local_ip,
		ctx->ua_port, reg_req_expires(ctx), ctx->pani, ctx->impu, ctx->user_agent);
	if (len > 0 && (size_t)len < sizeof(req)) {
		fprintf(stderr, "imsroha: subscribing to the reg event\n");
		send_sip_msg(ctx, req, (size_t)len);
	}
}

/*
 * A reg event NOTIFY: if it says the contact we registered is gone
 * (state="terminated"), register again (TS 24.229 5.1.1.3); a terminated
 * subscription is started over at the next registration.
 */
static void reg_event_notify(struct imsd_sip_ctx *ctx, const char *msg)
{
	char ev[32] = "", ss[64] = "";
	find_header(msg, "Event", ev, sizeof(ev));
	if (strncasecmp(ev, "reg", 3) != 0)
		return;
	find_header(msg, "Subscription-State", ss, sizeof(ss));
	if (!strncasecmp(ss, "terminated", 10)) {
		ctx->sub_call_id[0] = '\0';
		ctx->sub_to_tag[0] = '\0';
	}
	const char *body = strstr(msg, "\r\n\r\n");
	if (!body)
		return;
	char needle[INET6_ADDRSTRLEN + 3];
	snprintf(needle, sizeof(needle), "[%s]", ctx->local_ip);
	for (const char *c = strstr(body, "<contact"); c; c = strstr(c + 8, "<contact")) {
		const char *end = strstr(c, "</contact>");
		const char *tag_end = strchr(c, '>');
		if (!end || !tag_end)
			break;
		size_t n = (size_t)(end - c);
		char el[1024];
		snprintf(el, sizeof(el), "%.*s", (int)(n < sizeof(el) - 1 ? n : sizeof(el) - 1), c);
		char head[512];
		snprintf(head, sizeof(head), "%.*s", (int)(tag_end - c), c);
		if (strstr(el, needle) && strstr(head, "state=\"terminated\"")) {
			fprintf(stderr, "imsroha: the network ended our registration (reg event), registering again\n");
			ctx->reg_state = IMSD_REGISTERING;
			imsd_emit_state_changed(ctx->bus, IMSD_REGISTERING);
			imsd_sip_register(ctx);
			return;
		}
	}
}

static int on_sip_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	(void)s; (void)revents;
	struct imsd_sip_ctx *ctx = userdata;
	char buf[4096];
	struct sockaddr_in6 from_addr;
	socklen_t from_len = sizeof(from_addr);

	ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
			     (struct sockaddr *)&from_addr, &from_len);
	if (n <= 0)
		return 0;
	buf[n] = '\0';

	if (strncmp(buf, "SIP/2.0 ", 8) == 0) {
		int status_code = atoi(buf + 8);
		const char *eol = strstr(buf, "\r\n");
		size_t line_len = eol ? (size_t)(eol - buf) : 32;
		if (line_len >= 120) line_len = 119;
		char status_line[128];
		memcpy(status_line, buf, line_len);
		status_line[line_len] = '\0';
		fprintf(stderr, "imsroha: received %s\n", status_line);

		if (status_code >= 300) {
			char reason[256] = "", warning[256] = "";
			find_header(buf, "Reason", reason, sizeof(reason));
			find_header(buf, "Warning", warning, sizeof(warning));
			if (reason[0]) fprintf(stderr, "imsroha: Reason: %s\n", reason);
			if (warning[0]) fprintf(stderr, "imsroha: Warning: %s\n", warning);
			fprintf(stderr, "imsroha: full error response (%d):\n%s\n", status_code, buf);
		}

		if (status_code == 401) {
			handle_401_challenge(ctx, buf);
		} else if (status_code == 200) {
			char cseq[64] = "";
			find_header(buf, "CSeq", cseq, sizeof(cseq));
			if (strstr(cseq, "REGISTER")) {
				cancel_reg_retry(ctx);
				char exp_str[32] = "10800";
				find_header(buf, "Expires", exp_str, sizeof(exp_str));
				ctx->reg_expires = (uint32_t)atoi(exp_str);
				if (!ctx->reg_expires) ctx->reg_expires = 10800;
				find_header(buf, "Service-Route", ctx->reg_service_route, sizeof(ctx->reg_service_route));
				find_header(buf, "P-Associated-URI", ctx->reg_associated_uri, sizeof(ctx->reg_associated_uri));
				/*
				 * A temporary IMPU (derived from the IMSI) is barred outside
				 * REGISTER: everything else goes out as the default public
				 * identity, the first URI in P-Associated-URI (TS 24.229 5.1.1.2.1).
				 */
				if (ctx->impu_temporary && ctx->reg_associated_uri[0]) {
					char first[256];
					sip_uri_of(ctx->reg_associated_uri, first, sizeof(first));
					if (first[0] && strcmp(first, ctx->impu)) {
						snprintf(ctx->impu, sizeof(ctx->impu), "%s", first);
						fprintf(stderr, "imsroha: using %s as the public identity\n", "the default one from P-Associated-URI");
					}
				}
				ctx->reg_state = IMSD_UP;
				fprintf(stderr, "imsroha: registered successfully! (expires %u s)\n", ctx->reg_expires);
				fprintf(stderr, "imsroha: REGISTER 200 OK headers:\n%s\n", buf);
				if (ctx->reg_service_route[0])
					fprintf(stderr, "imsroha: learned Service-Route: %s\n", ctx->reg_service_route);
				if (ctx->reg_associated_uri[0])
					fprintf(stderr, "imsroha: learned P-Associated-URI: %s\n", ctx->reg_associated_uri);
				imsd_emit_state_changed(ctx->bus, IMSD_UP);
				schedule_reg_refresh(ctx, ctx->reg_expires);
				reg_event_subscribe(ctx);
			} else if (strstr(cseq, "SUBSCRIBE")) {
				char to[256] = "", tag[64] = "";
				find_header(buf, "To", to, sizeof(to));
				find_param(to, "tag", tag, sizeof(tag));
				snprintf(ctx->sub_to_tag, sizeof(ctx->sub_to_tag), "%s", tag);
				ctx->sub_state = 1;
				fprintf(stderr, "imsroha: reg event subscription active\n");
			} else if (strstr(cseq, "PRACK")) {
				fprintf(stderr, "imsroha: PRACK acknowledged (200 OK)\n");
			} else if (strstr(cseq, "INVITE")) {
				/* 200 OK for Call -> Send ACK */
				const char *body = strstr(buf, "\r\n\r\n");
				fprintf(stderr, "imsroha: INVITE answered (200 OK):\n%s\n", buf);
				if (body && body[4]) {
					char remote_ip[INET6_ADDRSTRLEN] = "";
					uint16_t remote_port = 0;
					/* The answer's payload types are the ones to send with (RFC 3264 6.1). */
					parse_sdp_codecs(body + 4, ctx);
					if (parse_sdp_media(body + 4, remote_ip, sizeof(remote_ip), &remote_port) == 0) {
						setup_remote_rtp(ctx, remote_ip, remote_port);
					}
				}
				char to_hdr[256] = "";
				find_header(buf, "To", to_hdr, sizeof(to_hdr));
				find_param(to_hdr, "tag", ctx->call_to_tag, sizeof(ctx->call_to_tag));
				char contact_hdr[256] = "";
				if (find_header(buf, "Contact", contact_hdr, sizeof(contact_hdr)) == 0) {
					const char *start = strchr(contact_hdr, '<');
					const char *end = start ? strchr(start, '>') : NULL;
					if (start && end && end > start + 1) {
						size_t ulen = end - (start + 1);
						if (ulen >= sizeof(ctx->call_remote_contact)) ulen = sizeof(ctx->call_remote_contact) - 1;
						memcpy(ctx->call_remote_contact, start + 1, ulen);
						ctx->call_remote_contact[ulen] = '\0';
					}
				}
				const char *ruri = ctx->call_remote_contact[0] ? ctx->call_remote_contact : ctx->call_remote_uri;
				char branch[32];
				rand_hex(branch, 8);
				char ack[1024];
				int ack_len = snprintf(ack, sizeof(ack),
					"ACK %s SIP/2.0\r\n"
					"Via: SIP/2.0/UDP [%s]:%u;branch=z9hG4bK%s;rport\r\n"
					"From: <%s>;tag=%s\r\n"
					"To: %s;tag=%s\r\n"
					"Call-ID: %s\r\n"
					"CSeq: %u ACK\r\n"
					"Max-Forwards: 70\r\n"
					"Content-Length: 0\r\n\r\n",
		ruri, ctx->local_ip, ctx->ua_port, branch, ctx->impu, ctx->call_from_tag, ctx->call_remote, ctx->call_to_tag, ctx->call_id, ctx->call_invite_cseq);
				send_sip_msg(ctx, ack, ack_len);
				fprintf(stderr, "imsroha: sent ACK:\n%.*s\n", ack_len, ack);
				ctx->call_state = IMSD_CALL_ACTIVE;
				imsd_emit_call_state_changed(ctx->bus, ctx->active_call_id, 4, 0);
			}
		} else if (status_code == 183 || status_code == 180) {
			/* Session Progress / Ringing */
			const char *body = strstr(buf, "\r\n\r\n");
			if (body && body[4]) {
				char remote_ip[INET6_ADDRSTRLEN] = "";
				uint16_t remote_port = 0;
				fprintf(stderr, "imsroha: early media SDP (%d):\n%s\n", status_code, body + 4);
				parse_sdp_codecs(body + 4, ctx);
				if (parse_sdp_media(body + 4, remote_ip, sizeof(remote_ip), &remote_port) == 0) {
					setup_remote_rtp(ctx, remote_ip, remote_port);
				}
			}
			char to_hdr[256] = "";
			find_header(buf, "To", to_hdr, sizeof(to_hdr));
			find_param(to_hdr, "tag", ctx->call_to_tag, sizeof(ctx->call_to_tag));

			char contact_hdr[256] = "";
			if (find_header(buf, "Contact", contact_hdr, sizeof(contact_hdr)) == 0) {
				const char *start = strchr(contact_hdr, '<');
				const char *end = start ? strchr(start, '>') : NULL;
				if (start && end && end > start + 1) {
					size_t ulen = end - (start + 1);
					if (ulen >= sizeof(ctx->call_remote_contact)) ulen = sizeof(ctx->call_remote_contact) - 1;
					memcpy(ctx->call_remote_contact, start + 1, ulen);
					ctx->call_remote_contact[ulen] = '\0';
				}
			}

			char rseq_hdr[32] = "";
			if (find_header(buf, "RSeq", rseq_hdr, sizeof(rseq_hdr)) == 0 && rseq_hdr[0]) {
				/* Send PRACK for 100rel */
				const char *ruri = ctx->call_remote_contact[0] ? ctx->call_remote_contact : ctx->call_remote_uri;
				char prack_branch[32];
				rand_hex(prack_branch, 8);
				char prack[1024];
				ctx->call_cseq++;
				int prack_len = snprintf(prack, sizeof(prack),
					"PRACK %s SIP/2.0\r\n"
					"Via: SIP/2.0/UDP [%s]:%u;branch=z9hG4bK%s;rport\r\n"
					"From: <%s>;tag=%s\r\n"
					"To: %s\r\n"
					"Call-ID: %s\r\n"
					"CSeq: %u PRACK\r\n"
					"RAck: %s %u INVITE\r\n"
					"Max-Forwards: 70\r\n"
					"Content-Length: 0\r\n\r\n",
		ruri, ctx->local_ip, ctx->ua_port, prack_branch, ctx->impu, ctx->call_from_tag, to_hdr, ctx->call_id, ctx->call_cseq, rseq_hdr, ctx->call_invite_cseq);
				send_sip_msg(ctx, prack, prack_len);
			}
			ctx->call_state = (status_code == 180) ? IMSD_CALL_RINGING : IMSD_CALL_EARLY_MEDIA;
			/*
			 * ModemManager's call states carry a direction. A 183 on an
			 * outgoing call is still ringing out; only an incoming call
			 * with early media is ringing in.
			 */
			imsd_emit_call_state_changed(ctx->bus, ctx->active_call_id,
						     ctx->call_is_incoming ? 3 : 2, 0);
		} else if (status_code >= 300) {
			char cseq[64] = "";
			find_header(buf, "CSeq", cseq, sizeof(cseq));
			if (strstr(cseq, "MESSAGE")) {
				fprintf(stderr, "imsroha: SIP MESSAGE rejected by carrier (SIP %d)\n", status_code);
				if (ctx->pending_sms_msg) {
					sd_bus_reply_method_errorf(ctx->pending_sms_msg, SD_BUS_ERROR_FAILED,
								   "Carrier rejected SMS (SIP status %d)", status_code);
					sd_bus_message_unref(ctx->pending_sms_msg);
					ctx->pending_sms_msg = NULL;
					if (ctx->sms_timeout_timer) {
						sd_event_source_unref(ctx->sms_timeout_timer);
						ctx->sms_timeout_timer = NULL;
					}
				}
			}
			if (strstr(cseq, "INVITE")) {
				/* Non-2xx final response to INVITE -> send transaction ACK */
				const char *ruri = ctx->call_remote_uri;
				char to_hdr[256] = "";
				find_header(buf, "To", to_hdr, sizeof(to_hdr));
				char ack[1024];
				int ack_len = snprintf(ack, sizeof(ack),
					"ACK %s SIP/2.0\r\n"
					"Via: SIP/2.0/UDP [%s]:%u;branch=%s;rport\r\n"
					"From: <%s>;tag=%s\r\n"
					"To: %s\r\n"
					"Call-ID: %s\r\n"
					"CSeq: %u ACK\r\n"
					"Max-Forwards: 70\r\n"
					"Content-Length: 0\r\n\r\n",
		ruri, ctx->local_ip, ctx->ua_port, ctx->call_branch, ctx->impu, ctx->call_from_tag, to_hdr, ctx->call_id, ctx->call_invite_cseq);
				send_sip_msg(ctx, ack, ack_len);
				ctx->call_state = IMSD_CALL_TERMINATED;
				imsd_rtp_stop(ctx);
				imsd_emit_call_state_changed(ctx->bus, ctx->active_call_id, 6, 0);
			}
			if (strstr(cseq, "SUBSCRIBE")) {
				/* 489 Bad Event: the network has no reg event package. */
				if (status_code == 489)
					ctx->sub_state = -1;
				ctx->sub_call_id[0] = '\0';
				fprintf(stderr, "imsroha: reg event SUBSCRIBE refused (SIP %d)%s\n", status_code,
					status_code == 489 ? ", not subscribing again" : "");
			}
			if (strstr(cseq, "REGISTER"))
				handle_register_rejected(ctx, buf, status_code);
		}
	} else if (strncmp(buf, "INVITE ", 7) == 0) {
		handle_incoming_invite(ctx, buf, (size_t)n);
	} else if (strncmp(buf, "CANCEL ", 7) == 0) {
		handle_incoming_cancel(ctx, buf, (size_t)n);
	} else if (strncmp(buf, "ACK ", 4) == 0) {
		fprintf(stderr, "imsroha: received ACK for incoming call dialog\n");
		/* After an offerless INVITE or re-INVITE the ACK carries the answer. */
		char ack_cid[128] = "";
		find_header(buf, "Call-ID", ack_cid, sizeof(ack_cid));
		const char *active_cid = ctx->call_is_incoming ? ctx->inc_call_id : ctx->call_id;
		const char *body = strstr(buf, "\r\n\r\n");
		if (ctx->call_state == IMSD_CALL_ACTIVE && active_cid[0] && !strcmp(ack_cid, active_cid) &&
		    body && body[4]) {
			char remote_ip[INET6_ADDRSTRLEN] = "";
			uint16_t remote_port = 0;
			if (parse_sdp_media(body + 4, remote_ip, sizeof(remote_ip), &remote_port) == 0)
				setup_remote_rtp(ctx, remote_ip, remote_port);
			parse_sdp_codecs(body + 4, ctx);
			ctx->inc_offerless = 0;
		}
	} else if (strncmp(buf, "MESSAGE ", 8) == 0) {
		handle_incoming_message(ctx, buf, (size_t)n);
	} else if (strncmp(buf, "BYE ", 4) == 0) {
		char via[1024] = "", from[256] = "", to[256] = "", call_id[128] = "", cseq[64] = "";
		find_all_vias(buf, via, sizeof(via));
		find_header(buf, "From", from, sizeof(from));
		find_header(buf, "To", to, sizeof(to));
		find_header(buf, "Call-ID", call_id, sizeof(call_id));
		find_header(buf, "CSeq", cseq, sizeof(cseq));
		const char *active_cid = ctx->call_is_incoming ? ctx->inc_call_id : ctx->call_id;
		int same_dialog = active_cid[0] && strcmp(call_id, active_cid) == 0;
		if (same_dialog && ctx->call_state == IMSD_CALL_TERMINATED) {
			/* Our 200 OK got lost and the BYE came again: answer it again. */
			fprintf(stderr, "imsroha: BYE retransmission (Call-ID %s)\n", call_id);
			send_simple_response(ctx, "200 OK", via, from, to, call_id, cseq);
			return 0;
		}
		if (ctx->call_state == IMSD_CALL_IDLE || ctx->call_state == IMSD_CALL_TERMINATED ||
		    !same_dialog) {
			fprintf(stderr, "imsroha: ignoring BYE for inactive/mismatched Call-ID %s\n", call_id);
			char err_resp[2048];
			int err_len = snprintf(err_resp, sizeof(err_resp),
				"SIP/2.0 481 Call/Transaction Does Not Exist\r\n"
				"%s"
				"From: %s\r\n"
				"To: %s\r\n"
				"Call-ID: %s\r\n"
				"CSeq: %s\r\n"
				"Content-Length: 0\r\n\r\n",
				via, from, to, call_id, cseq);
			send_sip_msg(ctx, err_resp, err_len);
			return 0;
		}
		char reason[160] = "";
		find_header(buf, "Reason", reason, sizeof(reason));
		fprintf(stderr, "imsroha: remote hung up (BYE)%s%s\n", reason[0] ? ", Reason: " : "", reason);
		char ok_resp[2048];
		int ok_len = snprintf(ok_resp, sizeof(ok_resp),
			"SIP/2.0 200 OK\r\n"
			"%s"
			"From: %s\r\n"
			"To: %s\r\n"
			"Call-ID: %s\r\n"
			"CSeq: %s\r\n"
			"Content-Length: 0\r\n\r\n",
			via, from, to, call_id, cseq);
		send_sip_msg(ctx, ok_resp, ok_len);
		ctx->call_state = IMSD_CALL_TERMINATED;
		imsd_rtp_stop(ctx);
		imsd_emit_call_state_changed(ctx->bus, ctx->active_call_id, 6, 0);
	} else if (strncmp(buf, "UPDATE ", 7) == 0 ||
		   strncmp(buf, "OPTIONS ", 8) == 0 ||
		   strncmp(buf, "INFO ", 5) == 0 ||
		   strncmp(buf, "NOTIFY ", 7) == 0 ||
		   strncmp(buf, "PRACK ", 6) == 0) {
		char via[1024] = "", from[256] = "", to[256] = "", call_id[128] = "", cseq[64] = "";
		find_all_vias(buf, via, sizeof(via));
		find_header(buf, "From", from, sizeof(from));
		find_header(buf, "To", to, sizeof(to));
		find_header(buf, "Call-ID", call_id, sizeof(call_id));
		find_header(buf, "CSeq", cseq, sizeof(cseq));

		/*
		 * UPDATE, INFO and PRACK only exist inside a dialog (RFC 3311, 6086,
		 * 3262). One for a call we do not have must not touch the RTP
		 * session of the one we do.
		 */
		int in_dialog_only = strncmp(buf, "UPDATE ", 7) == 0 ||
				     strncmp(buf, "INFO ", 5) == 0 ||
				     strncmp(buf, "PRACK ", 6) == 0;
		const char *active_cid = ctx->call_is_incoming ? ctx->inc_call_id : ctx->call_id;
		if (in_dialog_only &&
		    (ctx->call_state == IMSD_CALL_IDLE || ctx->call_state == IMSD_CALL_TERMINATED ||
		     !active_cid[0] || strcmp(call_id, active_cid) != 0)) {
			fprintf(stderr, "imsroha: in-dialog request for unknown Call-ID %s\n", call_id);
			send_simple_response(ctx, "481 Call/Transaction Does Not Exist", via, from, to, call_id, cseq);
			return 0;
		}

		char to_with_tag[320];
		if (strcasestr(to, ";tag=")) {
			snprintf(to_with_tag, sizeof(to_with_tag), "%s", to);
		} else {
			const char *tag = (ctx->call_state != IMSD_CALL_IDLE && ctx->call_state != IMSD_CALL_TERMINATED)
				? (ctx->call_is_incoming ? ctx->call_to_tag : ctx->call_from_tag)
				: ctx->reg_from_tag;
			snprintf(to_with_tag, sizeof(to_with_tag), "%s;tag=%s", to, tag[0] ? tag : "imsroha");
		}

		char se_hdr[128] = "", se_val[64] = "";
		if (find_header(buf, "Session-Expires", se_val, sizeof(se_val)) == 0 && se_val[0])
			snprintf(se_hdr, sizeof(se_hdr), "Session-Expires: %s\r\nSupported: timer\r\n", se_val);

		const char *body = strstr(buf, "\r\n\r\n");
		if (strncmp(buf, "UPDATE ", 7) == 0 && body && body[4]) {
			/* Check the offer before it replaces the session we have. */
			if (!sdp_has_amr(body + 4)) {
				fprintf(stderr, "imsroha: UPDATE offers no AMR, keeping the session\n");
				send_simple_response(ctx, "488 Not Acceptable Here", via, from, to, call_id, cseq);
				return 0;
			}
			char remote_ip[INET6_ADDRSTRLEN] = "";
			uint16_t remote_port = 0;
			if (parse_sdp_media(body + 4, remote_ip, sizeof(remote_ip), &remote_port) == 0)
				setup_remote_rtp(ctx, remote_ip, remote_port);
			parse_sdp_codecs(body + 4, ctx);

			char sdp[1024];
			int sdp_len = build_local_sdp(ctx, sdp, sizeof(sdp), 1);
			if (sdp_len < 0) {
				send_simple_response(ctx, "500 Server Internal Error", via, from, to, call_id, cseq);
				return 0;
			}
			char ok_resp[3072];
			int ok_len = snprintf(ok_resp, sizeof(ok_resp),
				"SIP/2.0 200 OK\r\n"
				"%s"
				"From: %s\r\n"
				"To: %s\r\n"
				"Call-ID: %s\r\n"
				"CSeq: %s\r\n"
				"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\"\r\n"
				"Allow: " IMSD_ALLOW "\r\n"
				"%s"
				"Content-Type: application/sdp\r\n"
				"Content-Length: %d\r\n\r\n"
				"%s",
				via, from, to_with_tag, call_id, cseq,
				ctx->impu_user, ctx->local_ip, ctx->ua_port, se_hdr, sdp_len, sdp);
			send_sip_msg(ctx, ok_resp, ok_len);
			fprintf(stderr, "imsroha: answered UPDATE with SDP (CSeq %s)\n", cseq);
		} else {
			char ok_resp[2048];
			int ok_len = snprintf(ok_resp, sizeof(ok_resp),
				"SIP/2.0 200 OK\r\n"
				"%s"
				"From: %s\r\n"
				"To: %s\r\n"
				"Call-ID: %s\r\n"
				"CSeq: %s\r\n"
				"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\"\r\n"
				"Allow: " IMSD_ALLOW "\r\n"
				"%s"
				"Content-Length: 0\r\n\r\n",
				via, from, to_with_tag, call_id, cseq,
				ctx->impu_user, ctx->local_ip, ctx->ua_port, se_hdr);
			send_sip_msg(ctx, ok_resp, ok_len);
			fprintf(stderr, "imsroha: answered in-dialog/request with 200 OK (CSeq %s)\n", cseq);
		}
		if (strncmp(buf, "NOTIFY ", 7) == 0)
			reg_event_notify(ctx, buf);
	}

	return 0;
}

static int on_sms_timeout(sd_event_source *s, uint64_t usec, void *userdata)
{
	(void)s; (void)usec;
	struct imsd_sip_ctx *ctx = userdata;
	ctx->sms_timeout_timer = NULL;
	if (ctx->pending_sms_msg) {
		fprintf(stderr, "imsroha: SMS delivery timeout (no carrier RP-ACK received)\n");
		sd_bus_reply_method_errorf(ctx->pending_sms_msg, SD_BUS_ERROR_TIMEOUT,
					   "SMS delivery timed out waiting for carrier ack");
		sd_bus_message_unref(ctx->pending_sms_msg);
		ctx->pending_sms_msg = NULL;
	}
	return 0;
}

int imsd_sip_send_sms(struct imsd_sip_ctx *ctx, const char *dest_number, const char *text, sd_bus_message *msg)
{
	if (!dest_number || !text || ctx->reg_state != IMSD_UP)
		return -EINVAL;

	if (ctx->pending_sms_msg) {
		fprintf(stderr, "imsroha: rejecting MO-SMS, previous SMS still pending ack\n");
		return -EBUSY;
	}

	ctx->sms_mr++;
	if (ctx->sms_mr == 0)
		ctx->sms_mr = 1;

	unsigned char rp_buf[512];
	int rp_len = imsd_sms_encode_rp_data(dest_number, text, ctx->cfg.car.country_code,
					     ctx->sms_mr, ctx->smsc, ctx->smsc_len,
					     rp_buf, sizeof(rp_buf));
	if (rp_len < 0) {
		fprintf(stderr, "imsroha: failed to encode SMS RP-DATA: %d\n", rp_len);
		return rp_len;
	}

	char branch[32], cid[64], tag[16];
	rand_hex(branch, 8);
	rand_hex(cid, 16);
	rand_hex(tag, 8);

	char clean_dest[64];
	size_t c_idx = 0;
	int has_plus = (dest_number[0] == '+');
	for (size_t i = (has_plus ? 1 : 0); dest_number[i] && c_idx + 1 < sizeof(clean_dest); i++) {
		if (dest_number[i] >= '0' && dest_number[i] <= '9')
			clean_dest[c_idx++] = dest_number[i];
	}
	clean_dest[c_idx] = '\0';

	char sip_dest[64];
	const char *cc = ctx->cfg.car.country_code;
	size_t cc_len = strlen(cc);
	if (has_plus && cc_len && strncmp(clean_dest, cc, cc_len) == 0 && c_idx > cc_len) {
		snprintf(sip_dest, sizeof(sip_dest), "0%s", clean_dest + cc_len);
	} else if (has_plus) {
		snprintf(sip_dest, sizeof(sip_dest), "+%s", clean_dest);
	} else {
		snprintf(sip_dest, sizeof(sip_dest), "%s", clean_dest);
	}

	/*
	 * TS 24.341 5.3.1.2 and TTAK.KO-06.0357 9.3: the Request-URI is the SC's
	 * PSI when the carrier gives one; otherwise the Korean form, the
	 * destination as a local number in a SIP URI (LG U+ routes on it).
	 */
	char ruri[256];
	if (ctx->cfg.car.sms_psi[0])
		snprintf(ruri, sizeof(ruri), "%s", ctx->cfg.car.sms_psi);
	else
		snprintf(ruri, sizeof(ruri), "sip:%s@%s;user=phone", sip_dest, ctx->domain);

	char req_hdr[2048];
	int hdr_len = snprintf(req_hdr, sizeof(req_hdr),
		"MESSAGE %s SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [%s]:%u;branch=z9hG4bK%s;rport\r\n"
		"From: <%s>;tag=%s\r\n"
		"To: <sip:%s@%s;user=phone>\r\n"
		"Call-ID: %s@%s\r\n"
		"CSeq: 1 MESSAGE\r\n"
		"Max-Forwards: 70\r\n"
		"P-Access-Network-Info: %s\r\n"
		"P-Preferred-Identity: <%s>\r\n"
		"P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel.smsip\r\n"
		"User-Agent: %s\r\n"
		"Accept-Contact: *;+g.3gpp.smsip;require;explicit\r\n"
		"Content-Type: application/vnd.3gpp.sms\r\n"
		"Content-Length: %d\r\n\r\n",
		ruri, ctx->local_ip, ctx->ua_port, branch, ctx->impu, tag, sip_dest, ctx->domain,
		cid, ctx->domain, ctx->pani, ctx->impu, ctx->user_agent, rp_len);

	unsigned char full_msg[2560];
	memcpy(full_msg, req_hdr, hdr_len);
	memcpy(full_msg + hdr_len, rp_buf, rp_len);

	fprintf(stderr, "imsroha: sending MO-SMS (MR 0x%02x) to %s (%d bytes)...\n",
		ctx->sms_mr, sip_dest, rp_len);
	int r = send_sip_msg(ctx, full_msg, hdr_len + rp_len);
	if (r < 0)
		return r;

	ctx->pending_sms_msg = sd_bus_message_ref(msg);

	uint64_t now_usec = 0;
	sd_event_now(ctx->event, CLOCK_MONOTONIC, &now_usec);
	if (ctx->sms_timeout_timer) {
		sd_event_source_unref(ctx->sms_timeout_timer);
		ctx->sms_timeout_timer = NULL;
	}
	sd_event_add_time(ctx->event, &ctx->sms_timeout_timer, CLOCK_MONOTONIC,
			  now_usec + 15000000ULL, 1000000ULL, on_sms_timeout, ctx);

	return 0;
}

int imsd_sip_place_call(struct imsd_sip_ctx *ctx, const char *dest_number, uint32_t *out_call_id)
{
	if (!dest_number || ctx->reg_state != IMSD_UP)
		return -EINVAL;

	ctx->active_call_id++;
	if (out_call_id)
		*out_call_id = ctx->active_call_id;

	rand_hex(ctx->call_from_tag, 8);
	char cid_rnd[32];
	rand_hex(cid_rnd, 16);
	snprintf(ctx->call_id, sizeof(ctx->call_id), "%s@%s", cid_rnd, ctx->domain);
	ctx->call_cseq = 1;
	ctx->call_invite_cseq = 1;
	ctx->call_is_incoming = 0;
	ctx->call_state = IMSD_CALL_DIALING;
	ctx->call_to_tag[0] = '\0';
	ctx->call_remote_contact[0] = '\0';

	char branch[32];
	rand_hex(branch, 8);
	snprintf(ctx->call_branch, sizeof(ctx->call_branch), "z9hG4bK%s", branch);

	/* Fixed payload types in our offer, never the previous call's. */
	ctx->call_pt_amrwb = ctx->cfg.car.pt_amrwb;
	ctx->call_pt_amr = ctx->cfg.car.pt_amr;
	ctx->call_has_wb = ctx->call_has_nb = 1;
	/* No DTMF until the answer says which telephone-event clocks it kept. */
	ctx->call_has_dtmf_wb = ctx->call_has_dtmf_nb = 0;
	sdp_new_session(ctx);

	char sdp[1024];
	int sdp_len = build_local_sdp(ctx, sdp, sizeof(sdp), 0);

	char clean_dest[64];
	size_t c_idx = 0;
	int has_plus = (dest_number[0] == '+');
	const char *cc = ctx->cfg.car.country_code;
	size_t cc_len = strlen(cc);
	for (size_t i = (has_plus ? 1 : 0); dest_number[i] && c_idx + 1 < sizeof(clean_dest); i++) {
		if (dest_number[i] >= '0' && dest_number[i] <= '9')
			clean_dest[c_idx++] = dest_number[i];
	}
	clean_dest[c_idx] = '\0';

	/*
	 * The R-URI the stock Samsung IMS stack (UriGeneratorImpl, LG U+ profile
	 * "remote_uri_type": "tel", "policy_on_local_numbers": "home-local")
	 * sends: a tel: URI, and for a number without a leading '+' a
	 * phone-context of the home domain:
	 *
	 *   tel:010xxxxxxxx;phone-context=lte-lguplus.co.kr
	 *
	 * The S-CSCF then routes on the number, so other networks work too. The
	 * old sip:<number>@lte-lguplus.co.kr;user=phone form was terminated on
	 * LG U+'s own HSS and failed for every KT and SKT number. A dial string
	 * that is already a sip: or tel: URI is passed through for diagnostics.
	 */
	char target_ruri[256];
	char target_to[260];
	if (strncmp(dest_number, "sip:", 4) == 0 || strncmp(dest_number, "tel:", 4) == 0) {
		snprintf(target_ruri, sizeof(target_ruri), "%s", dest_number);
	} else if (has_plus && (!cc_len || strncmp(clean_dest, cc, cc_len))) {
		/* International number outside the home country: a global tel: URI. */
		snprintf(target_ruri, sizeof(target_ruri), "tel:+%s", clean_dest);
	} else {
		/*
		 * Domestic, service code (114) or +<home cc>: the national form as a
		 * local number. A global tel:+82... got 503 from LG U+.
		 */
		char national[64];
		const char *number = clean_dest;
		if (has_plus) {
			snprintf(national, sizeof(national), "0%s", clean_dest + cc_len);
			number = national;
		}
		snprintf(target_ruri, sizeof(target_ruri), "tel:%s;phone-context=%s", number, ctx->domain);
	}
	snprintf(target_to, sizeof(target_to), "<%s>", target_ruri);

	/* In-dialog ACK, CANCEL and BYE must carry the INVITE's To (RFC 3261 9.1, 12.2.1.1). */
	snprintf(ctx->call_remote, sizeof(ctx->call_remote), "%s", target_to);

	snprintf(ctx->call_remote_uri, sizeof(ctx->call_remote_uri), "%s", target_ruri);

	char route_hdr[300] = "";
	if (ctx->reg_service_route[0]) {
		snprintf(route_hdr, sizeof(route_hdr), "Route: %s\r\n", ctx->reg_service_route);
	}

	char req[3072];
	int req_len = snprintf(req, sizeof(req),
		"INVITE %s SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [%s]:%u;branch=z9hG4bK%s;rport\r\n"
		"%s"
		"From: <%s>;tag=%s\r\n"
		"To: %s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %u INVITE\r\n"
		"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\"\r\n"
		"Max-Forwards: 70\r\n"
		"P-Access-Network-Info: %s\r\n"
		"P-Preferred-Identity: <%s>\r\n"
		"P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel\r\n"
		"User-Agent: %s\r\n"
		"P-Early-Media: supported\r\n"
		"Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\";require;explicit\r\n"
		"Allow: " IMSD_ALLOW "\r\n"
		"Supported: 100rel, timer\r\n"
		"Session-Expires: %u\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: %d\r\n\r\n"
		"%s",
		target_ruri, ctx->local_ip, ctx->ua_port, branch, route_hdr, ctx->impu, ctx->call_from_tag, target_to, ctx->call_id, ctx->call_cseq, ctx->impu_user, ctx->local_ip, ctx->ua_port, ctx->pani, ctx->impu, ctx->user_agent,
		ctx->cfg.car.session_expires, sdp_len, sdp);

	fprintf(stderr, "imsroha: placing VoLTE call to %s with INVITE:\n%s\n", dest_number, req);
	imsd_rtp_start(ctx);
	imsd_emit_call_added(ctx->bus, ctx->active_call_id, dest_number, 2);
	imsd_emit_call_state_changed(ctx->bus, ctx->active_call_id, 2, 0);
	return send_sip_msg(ctx, req, req_len);
}

int imsd_sip_answer_call(struct imsd_sip_ctx *ctx)
{
	if (!ctx->call_is_incoming || ctx->call_state != IMSD_CALL_RINGING)
		return -EINVAL;


	/* Answer with the INVITE's own payload types (see build_local_sdp()). */
	char sdp[1024];
	int sdp_len = build_local_sdp(ctx, sdp, sizeof(sdp), !ctx->inc_offerless);
	if (sdp_len < 0)
		return sdp_len;

	char resp[3072];
	int len = snprintf(resp, sizeof(resp),
		"SIP/2.0 200 OK\r\n"
		"%s"
		"From: %s\r\n"
		"To: %s;tag=%s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %s\r\n"
		"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\"\r\n"
		"Allow: " IMSD_ALLOW "\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: %d\r\n\r\n"
		"%s",
		ctx->inc_via, ctx->inc_from, ctx->inc_to, ctx->call_to_tag, ctx->inc_call_id, ctx->inc_cseq, ctx->impu_user, ctx->local_ip, ctx->ua_port, sdp_len, sdp);

	imsd_rtp_start(ctx);
	send_sip_msg(ctx, resp, len);
	ctx->call_state = IMSD_CALL_ACTIVE;
	imsd_emit_call_state_changed(ctx->bus, ctx->active_call_id, 4, 0);
	return 0;
}

int imsd_sip_hangup(struct imsd_sip_ctx *ctx)
{
	if (ctx->call_state == IMSD_CALL_IDLE)
		return 0;

	imsd_rtp_stop(ctx);

	if (ctx->call_is_incoming) {
		if (ctx->call_state == IMSD_CALL_RINGING) {
			char decl[1024];
			/* inc_via already holds complete "Via: ...\r\n" lines (find_all_vias). */
			int dlen = snprintf(decl, sizeof(decl),
				"SIP/2.0 603 Decline\r\n"
				"%s"
				"From: %s\r\n"
				"To: %s;tag=%s\r\n"
				"Call-ID: %s\r\n"
				"CSeq: %s\r\n"
				"Content-Length: 0\r\n\r\n",
				ctx->inc_via, ctx->inc_from, ctx->inc_to, ctx->call_to_tag,
				ctx->inc_call_id, ctx->inc_cseq);
			send_sip_msg(ctx, decl, dlen);
			fprintf(stderr, "imsroha: declined incoming call (603)\n");
		} else if (ctx->call_state == IMSD_CALL_ACTIVE) {
			char bye_branch[32];
			rand_hex(bye_branch, 8);
			char ruri[256];
			sip_uri_of(ctx->inc_contact[0] ? ctx->inc_contact : ctx->inc_from, ruri, sizeof(ruri));
			char req[1024];
			int len = snprintf(req, sizeof(req),
				"BYE %s SIP/2.0\r\n"
				"Via: SIP/2.0/UDP [%s]:%u;branch=z9hG4bK%s;rport\r\n"
				"From: %s;tag=%s\r\n"
				"To: %s\r\n"
				"Call-ID: %s\r\n"
				"CSeq: %u BYE\r\n"
				"Max-Forwards: 70\r\n"
				"Content-Length: 0\r\n\r\n",
				ruri, ctx->local_ip, ctx->ua_port, bye_branch,
				ctx->inc_to, ctx->call_to_tag, ctx->inc_from,
				ctx->inc_call_id, ++ctx->call_cseq);
			send_sip_msg(ctx, req, len);
		}
		ctx->call_is_incoming = 0;
	} else {
		if (ctx->call_state == IMSD_CALL_DIALING || ctx->call_state == IMSD_CALL_RINGING || ctx->call_state == IMSD_CALL_EARLY_MEDIA) {
			/* Send CANCEL with matching INVITE branch and CSeq */
			const char *ruri = ctx->call_remote_uri;
			char req[1024];
			int len = snprintf(req, sizeof(req),
				"CANCEL %s SIP/2.0\r\n"
				"Via: SIP/2.0/UDP [%s]:%u;branch=%s;rport\r\n"
				"From: <%s>;tag=%s\r\n"
				"To: %s\r\n"
				"Call-ID: %s\r\n"
				"CSeq: %u CANCEL\r\n"
				"Max-Forwards: 70\r\n"
				"Content-Length: 0\r\n\r\n",
		ruri, ctx->local_ip, ctx->ua_port, ctx->call_branch, ctx->impu, ctx->call_from_tag, ctx->call_remote, ctx->call_id, ctx->call_invite_cseq);
			send_sip_msg(ctx, req, len);
		} else if (ctx->call_state == IMSD_CALL_ACTIVE) {
			/* Send BYE */
			char bye_branch[32];
			rand_hex(bye_branch, 8);
			const char *ruri = ctx->call_remote_contact[0] ? ctx->call_remote_contact : ctx->call_remote_uri;
			char req[1024];
			int len = snprintf(req, sizeof(req),
				"BYE %s SIP/2.0\r\n"
				"Via: SIP/2.0/UDP [%s]:%u;branch=z9hG4bK%s;rport\r\n"
				"From: <%s>;tag=%s\r\n"
				"To: %s;tag=%s\r\n"
				"Call-ID: %s\r\n"
				"CSeq: %u BYE\r\n"
				"Max-Forwards: 70\r\n"
				"Content-Length: 0\r\n\r\n",
		ruri, ctx->local_ip, ctx->ua_port, bye_branch, ctx->impu, ctx->call_from_tag, ctx->call_remote, ctx->call_to_tag, ctx->call_id, ++ctx->call_cseq);
			send_sip_msg(ctx, req, len);
		}
	}

	uint32_t cid = ctx->active_call_id;
	ctx->call_state = IMSD_CALL_IDLE;
	imsd_emit_call_state_changed(ctx->bus, cid, 6, 0);
	return 0;
}

/* Adds one P-CSCF to the list unless it is there already. */
static void pcscf_add(struct imsd_sip_ctx *ctx, const struct in6_addr *a, uint16_t port)
{
	for (int i = 0; i < ctx->pcscf_n; i++)
		if (!memcmp(&ctx->pcscf_list[i].sin6_addr, a, sizeof(*a)) &&
		    ctx->pcscf_list[i].sin6_port == htons(port))
			return;
	if (ctx->pcscf_n >= IMSD_MAX_PCSCF)
		return;
	struct sockaddr_in6 *sa = &ctx->pcscf_list[ctx->pcscf_n++];
	memset(sa, 0, sizeof(*sa));
	sa->sin6_family = AF_INET6;
	sa->sin6_port = htons(port);
	sa->sin6_addr = *a;
}

/* "addr", "[addr]:port", "name" or "name:port"; names resolve over the PDN's DNS. */
static void pcscf_add_spec(struct imsd_sip_ctx *ctx, const char *spec, const struct imsroha_pdn *pdn)
{
	char host[256];
	uint16_t port = ctx->cfg.car.pcscf_port;
	struct in6_addr a[4];

	if (spec[0] == '[') {
		const char *end = strchr(spec, ']');
		if (!end)
			return;
		snprintf(host, sizeof(host), "%.*s", (int)(end - spec - 1), spec + 1);
		if (end[1] == ':')
			port = (uint16_t)atoi(end + 2);
	} else if (strchr(spec, ':') && strchr(spec, ':') == strrchr(spec, ':') && !strchr(spec, '[')
		   && inet_pton(AF_INET6, spec, &a[0]) != 1) {
		/* one colon and not an IPv6 address: name:port */
		const char *c = strchr(spec, ':');
		snprintf(host, sizeof(host), "%.*s", (int)(c - spec), spec);
		port = (uint16_t)atoi(c + 1);
	} else {
		snprintf(host, sizeof(host), "%s", spec);
	}
	if (inet_pton(AF_INET6, host, &a[0]) == 1) {
		pcscf_add(ctx, &a[0], port);
		return;
	}
	struct in_addr v4;
	if (inet_pton(AF_INET, host, &v4) == 1) {
		fprintf(stderr, "imsroha: P-CSCF %s is IPv4, the IMS PDN is IPv6 only: skipped\n", host);
		return;
	}
	int n = imsroha_dns_aaaa(host, pdn->dns, ctx->local_ip, ctx->iface, a, 4, 2000);
	for (int i = 0; i < n; i++)
		pcscf_add(ctx, &a[i], port);
}

static void pcscf_add_list(struct imsd_sip_ctx *ctx, const char *list, const struct imsroha_pdn *pdn)
{
	char buf[512];
	snprintf(buf, sizeof(buf), "%s", list);
	for (char *save = NULL, *t = strtok_r(buf, " ,", &save); t; t = strtok_r(NULL, " ,", &save))
		pcscf_add_spec(ctx, t, pdn);
}

int imsd_sip_setup(struct imsd_sip_ctx *ctx, const struct imsd_isim_identity *id,
		   const struct imsroha_config *cfg, const struct imsroha_pdn *pdn)
{
	ctx->cfg = *cfg;
	snprintf(ctx->impi, sizeof(ctx->impi), "%s", id->impi);
	snprintf(ctx->impu, sizeof(ctx->impu), "%s", id->impu);
	snprintf(ctx->reg_impu, sizeof(ctx->reg_impu), "%s", id->impu);
	ctx->impu_temporary = !id->has_isim;
	if (strncmp(id->impu, "sip:", 4) != 0 || !strchr(id->impu, '@')) {
		fprintf(stderr, "imsroha: public identity is not a SIP URI\n");
		return -EPROTO;
	}
	snprintf(ctx->impu_user, sizeof(ctx->impu_user), "%.*s",
		 (int)(strchr(id->impu, '@') - (id->impu + 4)), id->impu + 4);

	/* The ISIM's home domain, else the carrier's, else the one derived from the PLMN. */
	if (id->has_isim && id->domain[0])
		snprintf(ctx->domain, sizeof(ctx->domain), "%s", id->domain);
	else if (cfg->car.domain[0])
		snprintf(ctx->domain, sizeof(ctx->domain), "%s", cfg->car.domain);
	else
		imsroha_derived_domain(id->mcc, id->mnc, ctx->domain, sizeof(ctx->domain));
	if (id->has_isim && cfg->car.domain[0] && strcmp(id->domain, cfg->car.domain))
		fprintf(stderr, "imsroha: ISIM home domain %s, carrier profile says %s: using the ISIM's\n",
			id->domain, cfg->car.domain);

	snprintf(ctx->iface, sizeof(ctx->iface), "%s", pdn->iface);
	snprintf(ctx->local_ip, sizeof(ctx->local_ip), "%s", pdn->addr);
	ctx->sip_port = cfg->car.sip_port;
	ctx->ua_port = ctx->sip_port;
	ctx->fd_c = ctx->fd_s = -1;
	ctx->sec_state = cfg->car.ipsec ? IMSD_SEC_OFFERED : IMSD_SEC_OFF;
	memset(&ctx->sec, 0, sizeof(ctx->sec));
	/* Our protected ports: next to the plain one, clear of it. */
	ctx->sec.port_uc = (uint16_t)(ctx->sip_port + 2);
	ctx->sec.port_us = (uint16_t)(ctx->sip_port + 4);
	snprintf(ctx->sec.offer_alg, sizeof(ctx->sec.offer_alg), "%s", cfg->car.alg);
	snprintf(ctx->sec.offer_ealg, sizeof(ctx->sec.offer_ealg), "%s", cfg->car.ealg);
	imsroha_config_user_agent(cfg, ctx->user_agent, sizeof(ctx->user_agent));
	/*
	 * No cell identity is read from the modem: the PLMN with an all-zero
	 * TAC and cell id, which is what LG U+ has been answering to.
	 */
	snprintf(ctx->pani, sizeof(ctx->pani), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=%s%s00000000000",
		 id->mcc, id->mnc);

	const char *smsc = cfg->car.smsc[0] ? cfg->car.smsc : id->smsc;
	int n = smsc[0] ? imsd_sms_address_element(smsc, ctx->smsc, sizeof(ctx->smsc)) : -ENOENT;
	ctx->smsc_len = n > 0 ? (size_t)n : 0;
	if (cfg->car.sms_over_ip && !ctx->smsc_len)
		fprintf(stderr, "imsroha: no SMSC (EF_SMSP is empty, no smsc= set): MO-SMS will fail\n");

	/* P-CSCFs: what the network sent in the PCO, then the carrier's list. */
	ctx->pcscf_n = 0;
	pcscf_add_list(ctx, pdn->pcscf, pdn);
	pcscf_add_list(ctx, pdn->pcscf_fqdn, pdn);
	pcscf_add_list(ctx, cfg->car.pcscf, pdn);
	if (!ctx->pcscf_n) {
		fprintf(stderr, "imsroha: no P-CSCF: none in the PCO, none in the carrier profile\n");
		return -EDESTADDRREQ;
	}
	ctx->pcscf_cur = 0;
	ctx->pcscf_addr = ctx->pcscf_list[0];

	char a[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ctx->pcscf_addr.sin6_addr, a, sizeof(a));
	fprintf(stderr, "imsroha: carrier %s, domain %s, P-CSCF [%s]:%u (%d known), SIP port %u, SMS over IP %s\n",
		cfg->car.name[0] ? cfg->car.name : "(none, 3GPP defaults)", ctx->domain, a,
		ntohs(ctx->pcscf_addr.sin6_port), ctx->pcscf_n, ctx->sip_port,
		cfg->car.sms_over_ip ? "yes" : "no");

	rand_hex(ctx->reg_from_tag, 8);
	char cid_rnd[32];
	rand_hex(cid_rnd, 16);
	snprintf(ctx->reg_call_id, sizeof(ctx->reg_call_id), "%s@%s", cid_rnd, ctx->domain);
	ctx->reg_cseq = 1;
	return 0;
}

/* A UDP socket on the IMS address and link, fed to on_sip_packet. */
static int sip_socket(struct imsd_sip_ctx *ctx, uint16_t port, int *out)
{
	int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons(port) };
	inet_pton(AF_INET6, ctx->local_ip, &a.sin6_addr);
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ctx->iface, strlen(ctx->iface) + 1) < 0 ||
	    bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
		int r = -errno;
		close(fd);
		return r;
	}
	int r = sd_event_add_io(ctx->event, NULL, fd, EPOLLIN, on_sip_packet, ctx);
	if (r < 0) {
		close(fd);
		return r;
	}
	*out = fd;
	return 0;
}

int imsd_sip_init(struct imsd_sip_ctx *ctx, sd_event *event, sd_bus *bus)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->event = event;
	ctx->bus = bus;
	ctx->reg_state = IMSD_DOWN;
	ctx->call_state = IMSD_CALL_IDLE;
	ctx->fd = -1;
	ctx->rtp_fd = -1;
	srand((unsigned)time(NULL) ^ getpid());

	struct imsroha_config cfg;
	int r = imsroha_config_load_device(&cfg.dev);
	if (r < 0)
		return r;
	imsroha_sim_set_device(&cfg.dev);

	/*
	 * Who we are comes from the SIM (the ISIM's files, or identities derived
	 * from the USIM's IMSI), never from constants: the same build works for
	 * any SIM, and no subscriber identity lives in the source.
	 */
	struct imsd_isim_identity id;
	r = imsd_isim_read_identity(&id);
	if (r < 0) {
		fprintf(stderr, "imsroha: cannot read the identity from the SIM: %s\n", strerror(-r));
		return r;
	}
	fprintf(stderr, "imsroha: identity read from the %s\n", id.has_isim ? "ISIM" : "USIM (derived)");

	r = imsroha_config_load(&cfg, id.mcc, id.mnc);
	if (r < 0)
		return r;

	struct imsroha_pdn pdn;
	r = imsroha_pdn_read(imsroha_runtime_dir(), &pdn);
	if (r < 0) {
		fprintf(stderr, "imsroha: no IMS PDN hand-off in %s/pdn (%s): is imsroha-bearer up?\n",
			imsroha_runtime_dir(), strerror(-r));
		return r;
	}

	r = imsd_sip_setup(ctx, &id, &cfg, &pdn);
	if (r < 0)
		return r;

	if (cfg.car.sip_instance) {
		char imei[32], urn[64];
		if (imsroha_read_imei(&cfg.dev, imei, sizeof(imei)) == 0 && imsroha_imei_urn(imei, urn, sizeof(urn)) == 0)
			snprintf(ctx->instance, sizeof(ctx->instance), ";+sip.instance=\"<%s>\"", urn);
		else
			fprintf(stderr, "imsroha: no IMEI from the modem, registering without +sip.instance\n");
	}

	ctx->fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (ctx->fd < 0) {
		fprintf(stderr, "imsroha: socket failed: %s\n", strerror(errno));
		return -errno;
	}

	int val = 1;
	setsockopt(ctx->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	/*
	 * Linux takes a packet for a local address on any interface, so without
	 * this a host on Wi-Fi could hand us SIP (and fake SMS) for the IMS
	 * address. Only the carrier's side of the IMS PDN may reach this socket.
	 */
	if (setsockopt(ctx->fd, SOL_SOCKET, SO_BINDTODEVICE, ctx->iface, strlen(ctx->iface) + 1) < 0) {
		fprintf(stderr, "imsroha: SO_BINDTODEVICE %s failed: %s\n", ctx->iface, strerror(errno));
		int r = -errno;
		close(ctx->fd);
		ctx->fd = -1;
		return r;
	}

	struct sockaddr_in6 bind_addr;
	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_addr.sin6_family = AF_INET6;
	bind_addr.sin6_port = htons(ctx->sip_port);
	inet_pton(AF_INET6, ctx->local_ip, &bind_addr.sin6_addr);

	if (bind(ctx->fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
		int r = -errno;
		fprintf(stderr, "imsroha: bind %s:%u failed: %s\n",
			ctx->local_ip, ctx->sip_port, strerror(-r));
		close(ctx->fd);
		ctx->fd = -1;
		return r;
	}

	sd_event_source *io_src = NULL;
	r = sd_event_add_io(event, &io_src, ctx->fd, EPOLLIN, on_sip_packet, ctx);
	if (r < 0) {
		fprintf(stderr, "imsroha: sd_event_add_io failed: %d\n", r);
		close(ctx->fd);
		return r;
	}

	fprintf(stderr, "imsroha: SIP UDP socket bound to [%s]:%u\n", ctx->local_ip, ctx->sip_port);

	if (ctx->sec_state == IMSD_SEC_OFFERED) {
		if ((r = sip_socket(ctx, ctx->sec.port_uc, &ctx->fd_c)) < 0 ||
		    (r = sip_socket(ctx, ctx->sec.port_us, &ctx->fd_s)) < 0) {
			fprintf(stderr, "imsroha: no sockets for the protected ports %u/%u: %s\n",
				ctx->sec.port_uc, ctx->sec.port_us, strerror(-r));
			return r;
		}
	}
	return imsd_sip_register(ctx);
}

void imsd_sip_destroy(struct imsd_sip_ctx *ctx)
{
	imsroha_ipsec_remove(&ctx->sec);
	if (ctx->fd_c >= 0)
		close(ctx->fd_c);
	if (ctx->fd_s >= 0)
		close(ctx->fd_s);
	ctx->fd_c = ctx->fd_s = -1;
	imsd_rtp_stop(ctx);
	if (ctx->sms_timeout_timer) {
		sd_event_source_unref(ctx->sms_timeout_timer);
		ctx->sms_timeout_timer = NULL;
	}
	if (ctx->pending_sms_msg) {
		sd_bus_message_unref(ctx->pending_sms_msg);
		ctx->pending_sms_msg = NULL;
	}
	if (ctx->reg_timer) {
		sd_event_source_unref(ctx->reg_timer);
		ctx->reg_timer = NULL;
	}
	if (ctx->reg_retry_timer) {
		sd_event_source_unref(ctx->reg_retry_timer);
		ctx->reg_retry_timer = NULL;
	}
	if (ctx->fd >= 0) {
		close(ctx->fd);
		ctx->fd = -1;
	}
}
