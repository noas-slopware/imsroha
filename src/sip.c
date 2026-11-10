#include "sip.h"
#include "audio.h"
#include "inbox.h"
#include "aka.h"
#include "dbus.h"
#include "sms.h"

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

static void parse_sdp_codecs(const char *sdp, struct imsd_sip_ctx *ctx)
{
	ctx->call_pt_amrwb = 0;
	ctx->call_pt_amr = 0;
	ctx->call_pt_dtmf = 0;
	ctx->call_octet_aligned = 0;
	ctx->call_has_wb = 0;
	ctx->call_has_nb = 0;

	const char *p = sdp;
	while (p && *p) {
		const char *rtp = strstr(p, "a=rtpmap:");
		if (!rtp) break;
		rtp += 9;
		int pt = atoi(rtp);
		const char *sp = strchr(rtp, ' ');
		if (sp) {
			sp++;
			if (strncasecmp(sp, "AMR-WB", 6) == 0) {
				ctx->call_pt_amrwb = pt;
			} else if (strncasecmp(sp, "AMR", 3) == 0 && strncasecmp(sp, "AMR-WB", 6) != 0) {
				ctx->call_pt_amr = pt;
			} else if (strncasecmp(sp, "telephone-event", 15) == 0) {
				ctx->call_pt_dtmf = pt;
			}
		}
		p = strchr(rtp, '\n');
		if (p) p++;
	}

	if (strcasestr(sdp, "octet-align=1")) {
		ctx->call_octet_aligned = 1;
	}

	ctx->call_has_wb = ctx->call_pt_amrwb > 0;
	ctx->call_has_nb = ctx->call_pt_amr > 0;
	if (ctx->call_pt_amrwb <= 0) ctx->call_pt_amrwb = 106;
	if (ctx->call_pt_amr <= 0) ctx->call_pt_amr = 104;
	if (ctx->call_pt_dtmf <= 0) ctx->call_pt_dtmf = 96;

	fprintf(stderr, "b2q-imsd: remote SDP codecs: AMR-WB %s, AMR %s, DTMF PT %d, octet-align=%d\n",
		ctx->call_has_wb ? "yes" : "no", ctx->call_has_nb ? "yes" : "no",
		ctx->call_pt_dtmf, ctx->call_octet_aligned);
}

static int get_ims_ipv6(char *buf, size_t len)
{
	struct ifaddrs *ifaddr, *ifa;
	int found = 0;

	if (getifaddrs(&ifaddr) == -1)
		return -errno;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (strcmp(ifa->ifa_name, IMSD_IMS_IFACE) != 0)
			continue;

		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
			continue;

		if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, len)) {
			found = 1;
			break;
		}
	}
	freeifaddrs(ifaddr);
	return found ? 0 : -ENODEV;
}

static int send_sip_msg(struct imsd_sip_ctx *ctx, const void *buf, size_t len)
{
	ssize_t sent = sendto(ctx->fd, buf, len, 0,
			      (struct sockaddr *)&ctx->pcscf_addr,
			      sizeof(ctx->pcscf_addr));
	if (sent < 0) {
		fprintf(stderr, "b2q-imsd: sendto failed: %s\n", strerror(errno));
		return -errno;
	}
	return 0;
}

int imsd_sip_register(struct imsd_sip_ctx *ctx)
{
	char branch[32];
	snprintf(branch, sizeof(branch), "z9hG4bK%08x", (unsigned)rand());

	char req[1024];
	int len = snprintf(req, sizeof(req),
		"REGISTER sip:" IMSD_DOMAIN " SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [%s]:%u;branch=%s;rport\r\n"
		"From: <%s>;tag=%s\r\n"
		"To: <%s>\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %u REGISTER\r\n"
		"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\";+g.3gpp.smsip\r\n"
		"Authorization: Digest username=\"%s\", realm=\"" IMSD_DOMAIN "\", nonce=\"\", uri=\"sip:" IMSD_DOMAIN "\", response=\"\"\r\n"
		"Max-Forwards: 70\r\n"
		"Expires: 600000\r\n"
		"Supported: path\r\n"
		"P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500600000000000\r\n"
		"User-Agent: " IMSD_USER_AGENT "\r\n"
		"Content-Length: 0\r\n\r\n",
		ctx->local_ip, IMSD_SIP_PORT, branch, ctx->impu, ctx->reg_from_tag, ctx->impu, ctx->reg_call_id, ctx->reg_cseq++, ctx->impu_user, ctx->local_ip, IMSD_SIP_PORT, ctx->impi);

	/* A refresh keeps the account usable; only the first REGISTER is "registering". */
	if (ctx->reg_state != IMSD_UP)
		ctx->reg_state = IMSD_REGISTERING;
	fprintf(stderr, "b2q-imsd: sending REGISTER (CSeq %u)...\n", ctx->reg_cseq - 1);
	return send_sip_msg(ctx, req, len);
}

static int handle_401_challenge(struct imsd_sip_ctx *ctx, const char *msg)
{
	char auth_hdr[512];
	if (find_header(msg, "WWW-Authenticate", auth_hdr, sizeof(auth_hdr)) < 0) {
		fprintf(stderr, "b2q-imsd: 401 missing WWW-Authenticate\n");
		return -EINVAL;
	}

	char nonce_str[128] = "";
	char realm_str[64] = IMSD_DOMAIN;
	char alg_str[32] = "AKAv1-MD5";
	find_param(auth_hdr, "nonce", nonce_str, sizeof(nonce_str));
	find_param(auth_hdr, "realm", realm_str, sizeof(realm_str));
	find_param(auth_hdr, "algorithm", alg_str, sizeof(alg_str));

	if (!nonce_str[0]) {
		fprintf(stderr, "b2q-imsd: 401 missing nonce\n");
		return -EINVAL;
	}

	unsigned char nonce_bin[64];
	int nonce_len = b64_decode(nonce_str, strlen(nonce_str), nonce_bin, sizeof(nonce_bin));
	if (nonce_len < 32) {
		fprintf(stderr, "b2q-imsd: nonce decode failed or too short (%d bytes)\n", nonce_len);
		return -EINVAL;
	}

	struct imsd_aka_challenge ch;
	struct imsd_aka_result res;
	memcpy(ch.rand, nonce_bin, 16);
	memcpy(ch.autn, nonce_bin + 16, 16);

	fprintf(stderr, "b2q-imsd: executing AKA on ISIM via QMI UIM...\n");
	int r = imsd_aka_run_isim(&ch, &res);
	if (r < 0 || !res.success) {
		fprintf(stderr, "b2q-imsd: imsd_aka_run_isim failed: %d\n", r);
		return -EIO;
	}

	char branch[32];
	snprintf(branch, sizeof(branch), "z9hG4bK%08x", (unsigned)rand());

	char auth_line[512];
	if (res.is_sync_failure) {
		char auts_b64[64];
		b64_encode(res.auts, res.auts_len, auts_b64, sizeof(auts_b64));

		/* RFC 3310 empty password digest */
		char ha1_in[128];
		snprintf(ha1_in, sizeof(ha1_in), "%s:%s:",
		ctx->impi, realm_str);
		char ha1[33];
		md5_hex(ha1_in, strlen(ha1_in), ha1);

		char ha2_in[128];
		snprintf(ha2_in, sizeof(ha2_in), "REGISTER:sip:%s", IMSD_DOMAIN);
		char ha2[33];
		md5_hex(ha2_in, strlen(ha2_in), ha2);

		char resp_in[128];
		snprintf(resp_in, sizeof(resp_in), "%s:%s:%s", ha1, nonce_str, ha2);
		char resp_digest[33];
		md5_hex(resp_in, strlen(resp_in), resp_digest);

		snprintf(auth_line, sizeof(auth_line),
			"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"sip:" IMSD_DOMAIN "\", response=\"%s\", algorithm=%s, auts=\"%s\"\r\n",
		ctx->impi, realm_str, nonce_str, resp_digest, alg_str, auts_b64);
		fprintf(stderr, "b2q-imsd: resending REGISTER with AUTS...\n");
	} else {
		/* HA1 = MD5(username:realm:RES_BIN) */
		unsigned char ha1_raw[256];
		int ha1_len = snprintf((char *)ha1_raw, sizeof(ha1_raw), "%s:%s:",
		ctx->impi, realm_str);
		memcpy(ha1_raw + ha1_len, res.res, res.res_len);
		ha1_len += res.res_len;

		char ha1[33];
		md5_hex(ha1_raw, ha1_len, ha1);

		char ha2_in[128];
		snprintf(ha2_in, sizeof(ha2_in), "REGISTER:sip:%s", IMSD_DOMAIN);
		char ha2[33];
		md5_hex(ha2_in, strlen(ha2_in), ha2);

		char resp_in[128];
		snprintf(resp_in, sizeof(resp_in), "%s:%s:%s", ha1, nonce_str, ha2);
		char resp_digest[33];
		md5_hex(resp_in, strlen(resp_in), resp_digest);

		snprintf(auth_line, sizeof(auth_line),
			"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"sip:" IMSD_DOMAIN "\", response=\"%s\", algorithm=%s\r\n",
		ctx->impi, realm_str, nonce_str, resp_digest, alg_str);
		fprintf(stderr, "b2q-imsd: sending authenticated REGISTER (RES len %zu)...\n", res.res_len);
	}

	char req[1500];
	int len = snprintf(req, sizeof(req),
		"REGISTER sip:" IMSD_DOMAIN " SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [%s]:%u;branch=%s;rport\r\n"
		"From: <%s>;tag=%s\r\n"
		"To: <%s>\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %u REGISTER\r\n"
		"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\";+g.3gpp.smsip\r\n"
		"%s"
		"Max-Forwards: 70\r\n"
		"Expires: 600000\r\n"
		"Supported: path\r\n"
		"P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500600000000000\r\n"
		"User-Agent: " IMSD_USER_AGENT "\r\n"
		"Content-Length: 0\r\n\r\n",
		ctx->local_ip, IMSD_SIP_PORT, branch, ctx->impu, ctx->reg_from_tag, ctx->impu, ctx->reg_call_id, ctx->reg_cseq++, ctx->impu_user, ctx->local_ip, IMSD_SIP_PORT, auth_line);

	return send_sip_msg(ctx, req, len);
}

static int on_reg_timer(sd_event_source *s, uint64_t usec, void *userdata)
{
	(void)s; (void)usec;
	struct imsd_sip_ctx *ctx = userdata;
	fprintf(stderr, "b2q-imsd: refreshing SIP registration...\n");
	imsd_sip_register(ctx);
	return 0;
}

static void schedule_reg_refresh(struct imsd_sip_ctx *ctx, uint32_t expires)
{
	uint64_t now_usec = 0;
	sd_event_now(ctx->event, CLOCK_MONOTONIC, &now_usec);
	uint64_t refresh_interval_usec = (uint64_t)(expires > 120 ? expires / 2 : 60) * 1000000ULL;

	if (ctx->reg_timer) {
		sd_event_source_set_time(ctx->reg_timer, now_usec + refresh_interval_usec);
		sd_event_source_set_enabled(ctx->reg_timer, SD_EVENT_ONESHOT);
	} else {
		sd_event_add_time(ctx->event, &ctx->reg_timer, CLOCK_MONOTONIC,
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
		fprintf(stderr, "b2q-imsd: inet_pton failed for remote RTP IP '%s'\n", ip);
	} else {
		fprintf(stderr, "b2q-imsd: remote RTP target set to [%s]:%u\n", ip, port);
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

static int on_rtp_tx_timer(sd_event_source *s, uint64_t usec, void *userdata)
{
	struct imsd_sip_ctx *ctx = userdata;
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

	/*
	 * Send what the far end's SDP accepts: AMR-WB if it lists it, else AMR-NB.
	 * An interconnect answer can drop AMR-WB even when early media used it.
	 */
	enum imsd_codec codec = (ctx->call_has_wb || !ctx->call_has_nb) ? IMSD_CODEC_AMRWB : IMSD_CODEC_AMRNB;

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
	}

	ctx->rtp_tx_seq++;
	ctx->rtp_tx_ts += imsd_codec_ticks(codec);
	ctx->rtp_tx_pkts++;

	sendto(ctx->rtp_fd, pkt, pkt_len, 0,
	       (struct sockaddr *)&ctx->remote_rtp_addr, sizeof(ctx->remote_rtp_addr));

	if (ctx->rtp_tx_pkts == 1 || ctx->rtp_tx_pkts % 100 == 0) {
		fprintf(stderr, "b2q-imsd: RTP tx #%" PRIu64 " (ts %u, len %zu) -> [%s]:%u\n",
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
		fprintf(stderr, "b2q-imsd: learned remote RTP endpoint from incoming packet: [%s]:%u\n",
			ctx->remote_rtp_ip, ctx->remote_rtp_port);
	}

	if (n >= 12) {
		uint16_t seq = (buf[2] << 8) | buf[3];
		uint8_t pt = buf[1] & 0x7f;
		if (ctx->rtp_rx_pkts <= 5 || ctx->rtp_rx_pkts % 50 == 1) {
			fprintf(stderr, "b2q-imsd: RTP rx #%" PRIu64 " (pt %u, seq %u, len %zd) [hdr: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x payload: %02x %02x %02x %02x]\n",
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
		int is_wb = pt_rx == ctx->call_pt_amrwb || pt_rx == IMSD_PT_AMRWB;
		int is_nb = pt_rx == ctx->call_pt_amr || pt_rx == IMSD_PT_AMR;
		if (ctx->codec_open && n > 13 && (is_wb || is_nb)) {
			int16_t pcm_out[IMSD_AUDIO_FRAME];
			if (imsd_codec_decode(&ctx->codec, is_wb ? IMSD_CODEC_AMRWB : IMSD_CODEC_AMRNB,
					      buf + 13, n - 13, pcm_out) == 0)
				imsd_audio_downlink(pcm_out);
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
			fprintf(stderr, "b2q-imsd: failed to create RTP socket: %m\n");
			return;
		}

		int on = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		/* Same as the SIP socket: media only from the IMS PDN. */
		setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, IMSD_IMS_IFACE, sizeof(IMSD_IMS_IFACE));

		struct sockaddr_in6 addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(40000);
		inet_pton(AF_INET6, ctx->local_ip, &addr.sin6_addr);

		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			fprintf(stderr, "b2q-imsd: failed to bind RTP socket to port 40000: %m\n");
			close(fd);
			return;
		}

		ctx->rtp_fd = fd;
		ctx->rtp_rx_pkts = 0;
		ctx->rtp_rx_bytes = 0;

		sd_event_add_io(ctx->event, &ctx->rtp_source, ctx->rtp_fd, EPOLLIN, on_rtp_packet, ctx);
		fprintf(stderr, "b2q-imsd: RTP receiver listening on [%s]:40000\n", ctx->local_ip);
	}

	if (!ctx->rtp_tx_timer) {
		uint64_t now_usec = 0;
		sd_event_now(ctx->event, CLOCK_MONOTONIC, &now_usec);
		ctx->rtp_tx_seq = 1000;
		ctx->rtp_tx_ts = 160000;
		ctx->rtp_tx_pkts = 0;
		sd_event_add_time(ctx->event, &ctx->rtp_tx_timer, CLOCK_MONOTONIC,
				  now_usec + 20000, 1000, on_rtp_tx_timer, ctx);
		fprintf(stderr, "b2q-imsd: started RTP TX timer (20ms) for uplink audio\n");
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
		fprintf(stderr, "b2q-imsd: RTP session ended, rx %" PRIu64 " pkts (%" PRIu64 " bytes), tx %" PRIu64 " pkts\n",
			ctx->rtp_rx_pkts, ctx->rtp_rx_bytes, ctx->rtp_tx_pkts);
	}
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
		fprintf(stderr, "b2q-imsd: INVITE retransmission (Call-ID %s)\n", call_id);
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
				"Allow: INVITE, ACK, CANCEL, BYE, PRACK\r\n"
				"Content-Length: 0\r\n\r\n",
				via, from, to, ctx->call_to_tag, call_id, cseq, ctx->impu_user, ctx->local_ip, IMSD_SIP_PORT);
			send_sip_msg(ctx, ringing, rlen);
		}
		return 0;
	}

	char caller[64] = "";
	extract_caller_number(from, caller, sizeof(caller));
	fprintf(stderr, "b2q-imsd: incoming VoLTE call from %s (Call-ID %s)\n", caller, call_id);
	fprintf(stderr, "b2q-imsd: incoming INVITE message:\n%s\n", msg);

	snprintf(ctx->inc_via, sizeof(ctx->inc_via), "%s", via);
	snprintf(ctx->inc_from, sizeof(ctx->inc_from), "%s", from);
	snprintf(ctx->inc_to, sizeof(ctx->inc_to), "%s", to);
	snprintf(ctx->inc_call_id, sizeof(ctx->inc_call_id), "%s", call_id);
	snprintf(ctx->inc_cseq, sizeof(ctx->inc_cseq), "%s", cseq);
	snprintf(ctx->inc_contact, sizeof(ctx->inc_contact), "%s", contact);

	/* Parse remote SDP */
	const char *body = strstr(msg, "\r\n\r\n");
	if (body) {
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
		"Allow: INVITE, ACK, CANCEL, BYE, PRACK\r\n"
		"Content-Length: 0\r\n\r\n",
		via, from, to, ctx->call_to_tag, call_id, cseq, ctx->impu_user, ctx->local_ip, IMSD_SIP_PORT);
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

	fprintf(stderr, "b2q-imsd: caller cancelled incoming call (Call-ID %s)\n", call_id);


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
 * Answer an incoming MESSAGE with 200 OK carrying the RP reply in its body,
 * the way LG U+ expects it (TS 24.341 5.3.2.4 sends it as a new MESSAGE;
 * the carrier accepts it in the response).
 */
static void send_rp_reply(struct imsd_sip_ctx *ctx, const char *via, const char *from,
			  const char *to, const char *tag, const char *call_id, const char *cseq,
			  const unsigned char *rp, size_t rp_len)
{
	unsigned char full[1024];
	int len = snprintf((char *)full, sizeof(full),
		"SIP/2.0 200 OK\r\n"
		"Via: %s\r\n"
		"From: %s\r\n"
		"To: %s;tag=%s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %s\r\n"
		"P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500600000000000\r\n"
		"Content-Type: application/vnd.3gpp.sms\r\n"
		"Content-Length: %zu\r\n\r\n",
		via, from, to, tag, call_id, cseq, rp_len);
	if (len < 0 || (size_t)len + rp_len > sizeof(full))
		return;
	memcpy(full + len, rp, rp_len);
	send_sip_msg(ctx, full, len + rp_len);
}

static int handle_incoming_message(struct imsd_sip_ctx *ctx, const char *msg, size_t msg_len)
{
	char via[256] = "", from[256] = "", to[256] = "", call_id[128] = "", cseq[64] = "";
	find_header(msg, "Via", via, sizeof(via));
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
			fprintf(stderr, "b2q-imsd: could not parse RP-DATA (%d), sending RP-ERROR: %s\n",
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
			fprintf(stderr, "b2q-imsd: duplicate MT-SMS (MR 0x%02x), acked again\n", mr);
			return 0;
		}

		r = imsd_inbox_store(hex, id);
		if (r < 0) {
			fprintf(stderr, "b2q-imsd: cannot store MT-SMS (MR 0x%02x): %s, sending RP-ERROR\n",
				mr, strerror(-r));
			/* RP-ERROR, cause 22: memory capacity exceeded, so the SMSC keeps it */
			const unsigned char rp_err[4] = { 0x04, mr, 0x01, 22 };
			send_rp_reply(ctx, via, from, to, tag, call_id, cseq, rp_err, sizeof(rp_err));
			return 0;
		}

		imsd_inbox_remember(hex);
		const unsigned char rp_ack[2] = { 0x02, mr };
		send_rp_reply(ctx, via, from, to, tag, call_id, cseq, rp_ack, sizeof(rp_ack));
		fprintf(stderr, "b2q-imsd: stored MT-SMS %s (MR 0x%02x, DCS 0x%02x, %zu bytes), sent RP-ACK\n",
			id, mr, dcs, tpdu_len);
		imsd_emit_pdu_received(ctx->bus, id, hex);
		return 0;
	}

	/* Send standard 200 OK for other MESSAGE requests (e.g. carrier RP-ACK) */
	char ok_resp[1024];
	int ok_len = snprintf(ok_resp, sizeof(ok_resp),
		"SIP/2.0 200 OK\r\n"
		"Via: %s\r\n"
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
		fprintf(stderr, "b2q-imsd: received RP-ACK for MO-SMS (MR 0x%02x)\n", mr);
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
		fprintf(stderr, "b2q-imsd: received RP-ERROR for MO-SMS (MR 0x%02x)\n", mr);
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
		fprintf(stderr, "b2q-imsd: received %s\n", status_line);

		if (status_code >= 300) {
			char reason[256] = "", warning[256] = "";
			find_header(buf, "Reason", reason, sizeof(reason));
			find_header(buf, "Warning", warning, sizeof(warning));
			if (reason[0]) fprintf(stderr, "b2q-imsd: Reason: %s\n", reason);
			if (warning[0]) fprintf(stderr, "b2q-imsd: Warning: %s\n", warning);
			fprintf(stderr, "b2q-imsd: full error response (%d):\n%s\n", status_code, buf);
		}

		if (status_code == 401) {
			handle_401_challenge(ctx, buf);
		} else if (status_code == 200) {
			char cseq[64] = "";
			find_header(buf, "CSeq", cseq, sizeof(cseq));
			if (strstr(cseq, "REGISTER")) {
				char exp_str[32] = "10800";
				find_header(buf, "Expires", exp_str, sizeof(exp_str));
				ctx->reg_expires = (uint32_t)atoi(exp_str);
				if (!ctx->reg_expires) ctx->reg_expires = 10800;
				find_header(buf, "Service-Route", ctx->reg_service_route, sizeof(ctx->reg_service_route));
				find_header(buf, "P-Associated-URI", ctx->reg_associated_uri, sizeof(ctx->reg_associated_uri));
				ctx->reg_state = IMSD_UP;
				fprintf(stderr, "b2q-imsd: registered successfully! (expires %u s)\n", ctx->reg_expires);
				fprintf(stderr, "b2q-imsd: REGISTER 200 OK headers:\n%s\n", buf);
				if (ctx->reg_service_route[0])
					fprintf(stderr, "b2q-imsd: learned Service-Route: %s\n", ctx->reg_service_route);
				if (ctx->reg_associated_uri[0])
					fprintf(stderr, "b2q-imsd: learned P-Associated-URI: %s\n", ctx->reg_associated_uri);
				imsd_emit_state_changed(ctx->bus, IMSD_UP);
				schedule_reg_refresh(ctx, ctx->reg_expires);
			} else if (strstr(cseq, "PRACK")) {
				fprintf(stderr, "b2q-imsd: PRACK acknowledged (200 OK)\n");
			} else if (strstr(cseq, "INVITE")) {
				/* 200 OK for Call -> Send ACK */
				const char *body = strstr(buf, "\r\n\r\n");
				fprintf(stderr, "b2q-imsd: INVITE answered (200 OK):\n%s\n", buf);
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
		ruri, ctx->local_ip, IMSD_SIP_PORT, branch, ctx->impu, ctx->call_from_tag, ctx->call_remote, ctx->call_to_tag, ctx->call_id, ctx->call_invite_cseq);
				send_sip_msg(ctx, ack, ack_len);
				fprintf(stderr, "b2q-imsd: sent ACK:\n%.*s\n", ack_len, ack);
				ctx->call_state = IMSD_CALL_ACTIVE;
				imsd_emit_call_state_changed(ctx->bus, ctx->active_call_id, 4, 0);
			}
		} else if (status_code == 183 || status_code == 180) {
			/* Session Progress / Ringing */
			const char *body = strstr(buf, "\r\n\r\n");
			if (body && body[4]) {
				char remote_ip[INET6_ADDRSTRLEN] = "";
				uint16_t remote_port = 0;
				fprintf(stderr, "b2q-imsd: early media SDP (%d):\n%s\n", status_code, body + 4);
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
		ruri, ctx->local_ip, IMSD_SIP_PORT, prack_branch, ctx->impu, ctx->call_from_tag, to_hdr, ctx->call_id, ctx->call_cseq, rseq_hdr, ctx->call_invite_cseq);
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
				fprintf(stderr, "b2q-imsd: SIP MESSAGE rejected by carrier (SIP %d)\n", status_code);
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
		ruri, ctx->local_ip, IMSD_SIP_PORT, ctx->call_branch, ctx->impu, ctx->call_from_tag, to_hdr, ctx->call_id, ctx->call_invite_cseq);
				send_sip_msg(ctx, ack, ack_len);
				ctx->call_state = IMSD_CALL_TERMINATED;
				imsd_rtp_stop(ctx);
				imsd_emit_call_state_changed(ctx->bus, ctx->active_call_id, 6, 0);
			}
		}
	} else if (strncmp(buf, "INVITE ", 7) == 0) {
		handle_incoming_invite(ctx, buf, (size_t)n);
	} else if (strncmp(buf, "CANCEL ", 7) == 0) {
		handle_incoming_cancel(ctx, buf, (size_t)n);
	} else if (strncmp(buf, "ACK ", 4) == 0) {
		fprintf(stderr, "b2q-imsd: received ACK for incoming call dialog\n");
	} else if (strncmp(buf, "MESSAGE ", 8) == 0) {
		handle_incoming_message(ctx, buf, (size_t)n);
	} else if (strncmp(buf, "BYE ", 4) == 0) {
		char via[256] = "", from[256] = "", to[256] = "", call_id[128] = "", cseq[64] = "";
		find_header(buf, "Via", via, sizeof(via));
		find_header(buf, "From", from, sizeof(from));
		find_header(buf, "To", to, sizeof(to));
		find_header(buf, "Call-ID", call_id, sizeof(call_id));
		find_header(buf, "CSeq", cseq, sizeof(cseq));
		char reason[160] = "";
		find_header(buf, "Reason", reason, sizeof(reason));
		fprintf(stderr, "b2q-imsd: remote hung up (BYE)%s%s\n", reason[0] ? ", Reason: " : "", reason);
		char ok_resp[1024];
		int ok_len = snprintf(ok_resp, sizeof(ok_resp),
			"SIP/2.0 200 OK\r\n"
			"Via: %s\r\n"
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
	}

	return 0;
}

static int on_sms_timeout(sd_event_source *s, uint64_t usec, void *userdata)
{
	(void)s; (void)usec;
	struct imsd_sip_ctx *ctx = userdata;
	ctx->sms_timeout_timer = NULL;
	if (ctx->pending_sms_msg) {
		fprintf(stderr, "b2q-imsd: SMS delivery timeout (no carrier RP-ACK received)\n");
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
		fprintf(stderr, "b2q-imsd: rejecting MO-SMS, previous SMS still pending ack\n");
		return -EBUSY;
	}

	ctx->sms_mr++;
	if (ctx->sms_mr == 0)
		ctx->sms_mr = 1;

	unsigned char rp_buf[512];
	int rp_len = imsd_sms_encode_rp_data(dest_number, text, ctx->sms_mr, rp_buf, sizeof(rp_buf));
	if (rp_len < 0) {
		fprintf(stderr, "b2q-imsd: failed to encode SMS RP-DATA: %d\n", rp_len);
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
	if (has_plus && strncmp(clean_dest, "82", 2) == 0 && c_idx > 2) {
		snprintf(sip_dest, sizeof(sip_dest), "0%s", clean_dest + 2);
	} else if (has_plus) {
		snprintf(sip_dest, sizeof(sip_dest), "+%s", clean_dest);
	} else {
		snprintf(sip_dest, sizeof(sip_dest), "%s", clean_dest);
	}

	char req_hdr[1024];
	int hdr_len = snprintf(req_hdr, sizeof(req_hdr),
		"MESSAGE sip:%s@" IMSD_DOMAIN ";user=phone SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [%s]:%u;branch=z9hG4bK%s;rport\r\n"
		"From: <%s>;tag=%s\r\n"
		"To: <sip:%s@" IMSD_DOMAIN ";user=phone>\r\n"
		"Call-ID: %s@" IMSD_DOMAIN "\r\n"
		"CSeq: 1 MESSAGE\r\n"
		"Max-Forwards: 70\r\n"
		"P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500600000000000\r\n"
		"P-Preferred-Identity: <%s>\r\n"
		"P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel.smsip\r\n"
		"User-Agent: " IMSD_USER_AGENT "\r\n"
		"Accept-Contact: *;+g.3gpp.smsip;require;explicit\r\n"
		"Content-Type: application/vnd.3gpp.sms\r\n"
		"Content-Length: %d\r\n\r\n",
		sip_dest, ctx->local_ip, IMSD_SIP_PORT, branch, ctx->impu, tag, sip_dest, cid, ctx->impu, rp_len);

	unsigned char full_msg[1536];
	memcpy(full_msg, req_hdr, hdr_len);
	memcpy(full_msg + hdr_len, rp_buf, rp_len);

	fprintf(stderr, "b2q-imsd: sending MO-SMS (MR 0x%02x) to %s (%d bytes)...\n",
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
	snprintf(ctx->call_id, sizeof(ctx->call_id), "%s@" IMSD_DOMAIN, cid_rnd);
	ctx->call_cseq = 1;
	ctx->call_invite_cseq = 1;
	ctx->call_is_incoming = 0;
	ctx->call_state = IMSD_CALL_DIALING;
	ctx->call_to_tag[0] = '\0';
	ctx->call_remote_contact[0] = '\0';

	char branch[32];
	rand_hex(branch, 8);
	snprintf(ctx->call_branch, sizeof(ctx->call_branch), "z9hG4bK%s", branch);

	/*
	 * Fixed payload types, never the previous call's. telephone-event must
	 * run at the speech codec's clock (RFC 4733 2.1), so AMR-WB needs a
	 * telephone-event/16000 next to it: with only /8000 offered, an answerer
	 * that keeps DTMF can only pick AMR-NB (what LG U+ answered with).
	 * Ordered like the stock profile: AMR-WB, AMR, DTMF WB, DTMF NB.
	 */
	ctx->call_pt_amrwb = IMSD_PT_AMRWB;
	ctx->call_pt_amr = IMSD_PT_AMR;
	ctx->call_has_wb = ctx->call_has_nb = 1;

	char sdp[1024];
	time_t now = time(NULL);
	int sdp_len = snprintf(sdp, sizeof(sdp),
		"v=0\r\n"
		"o=- %lu %lu IN IP6 %s\r\n"
		"s=-\r\n"
		"c=IN IP6 %s\r\n"
		"t=0 0\r\n"
		"m=audio 40000 RTP/AVP %d %d %d %d\r\n"
		"b=AS:41\r\n"
		"a=rtpmap:%d AMR-WB/16000/1\r\n"
		"a=fmtp:%d octet-align=1;mode-set=0,1,2\r\n"
		"a=rtpmap:%d AMR/8000/1\r\n"
		"a=fmtp:%d octet-align=1;mode-set=0,2,4,7\r\n"
		"a=rtpmap:%d telephone-event/16000\r\n"
		"a=fmtp:%d 0-15\r\n"
		"a=rtpmap:%d telephone-event/8000\r\n"
		"a=fmtp:%d 0-15\r\n"
		"a=ptime:20\r\n"
		"a=sendrecv\r\n",
		(unsigned long)now, (unsigned long)now, ctx->local_ip, ctx->local_ip,
		IMSD_PT_AMRWB, IMSD_PT_AMR, IMSD_PT_DTMF_WB, IMSD_PT_DTMF,
		IMSD_PT_AMRWB, IMSD_PT_AMRWB,
		IMSD_PT_AMR, IMSD_PT_AMR,
		IMSD_PT_DTMF_WB, IMSD_PT_DTMF_WB,
		IMSD_PT_DTMF, IMSD_PT_DTMF);

	char clean_dest[64];
	size_t c_idx = 0;
	int has_plus = (dest_number[0] == '+');
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
	char target_ruri[160];
	char target_to[160];
	if (strncmp(dest_number, "sip:", 4) == 0 || strncmp(dest_number, "tel:", 4) == 0) {
		snprintf(target_ruri, sizeof(target_ruri), "%s", dest_number);
	} else if (has_plus && strncmp(clean_dest, "82", 2)) {
		/* International number outside Korea: a global tel: URI. */
		snprintf(target_ruri, sizeof(target_ruri), "tel:+%s", clean_dest);
	} else {
		/*
		 * Domestic, service code (114) or +82: the national form as a local
		 * number. A global tel:+82... got 503 from LG U+.
		 */
		char national[64];
		const char *number = clean_dest;
		if (has_plus) {
			snprintf(national, sizeof(national), "0%s", clean_dest + 2);
			number = national;
		}
		snprintf(target_ruri, sizeof(target_ruri), "tel:%s;phone-context=" IMSD_DOMAIN, number);
	}
	snprintf(target_to, sizeof(target_to), "<%s>", target_ruri);

	/* In-dialog ACK, CANCEL and BYE must carry the INVITE's To (RFC 3261 9.1, 12.2.1.1). */
	snprintf(ctx->call_remote, sizeof(ctx->call_remote), "%s", target_to);

	snprintf(ctx->call_remote_uri, sizeof(ctx->call_remote_uri), "%s", target_ruri);

	char route_hdr[300] = "";
	if (ctx->reg_service_route[0]) {
		snprintf(route_hdr, sizeof(route_hdr), "Route: %s\r\n", ctx->reg_service_route);
	}

	char req[1800];
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
		"P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500600000000000\r\n"
		"P-Preferred-Identity: <%s>\r\n"
		"P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel\r\n"
		"User-Agent: " IMSD_USER_AGENT "\r\n"
		"P-Early-Media: supported\r\n"
		"Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\";require;explicit\r\n"
		"Allow: INVITE, ACK, CANCEL, BYE, PRACK\r\n"
		"Supported: 100rel, timer\r\n"
		"Session-Expires: 1800\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: %d\r\n\r\n"
		"%s",
		target_ruri, ctx->local_ip, IMSD_SIP_PORT, branch, route_hdr, ctx->impu, ctx->call_from_tag, target_to, ctx->call_id, ctx->call_cseq, ctx->impu_user, ctx->local_ip, IMSD_SIP_PORT, ctx->impu, sdp_len, sdp);

	fprintf(stderr, "b2q-imsd: placing VoLTE call to %s with INVITE:\n%s\n", dest_number, req);
	imsd_rtp_start(ctx);
	imsd_emit_call_added(ctx->bus, ctx->active_call_id, dest_number, 2);
	imsd_emit_call_state_changed(ctx->bus, ctx->active_call_id, 2, 0);
	return send_sip_msg(ctx, req, req_len);
}

int imsd_sip_answer_call(struct imsd_sip_ctx *ctx)
{
	if (!ctx->call_is_incoming || ctx->call_state != IMSD_CALL_RINGING)
		return -EINVAL;


	/*
	 * Fixed payload types, never the previous call's. telephone-event must
	 * run at the speech codec's clock (RFC 4733 2.1), so AMR-WB needs a
	 * telephone-event/16000 next to it: with only /8000 offered, an answerer
	 * that keeps DTMF can only pick AMR-NB (what LG U+ answered with).
	 * Ordered like the stock profile: AMR-WB, AMR, DTMF WB, DTMF NB.
	 */
	ctx->call_pt_amrwb = IMSD_PT_AMRWB;
	ctx->call_pt_amr = IMSD_PT_AMR;
	ctx->call_has_wb = ctx->call_has_nb = 1;

	char sdp[1024];
	time_t now = time(NULL);
	int sdp_len = snprintf(sdp, sizeof(sdp),
		"v=0\r\n"
		"o=- %lu %lu IN IP6 %s\r\n"
		"s=-\r\n"
		"c=IN IP6 %s\r\n"
		"t=0 0\r\n"
		"m=audio 40000 RTP/AVP %d %d %d %d\r\n"
		"b=AS:41\r\n"
		"a=rtpmap:%d AMR-WB/16000/1\r\n"
		"a=fmtp:%d octet-align=1;mode-set=0,1,2\r\n"
		"a=rtpmap:%d AMR/8000/1\r\n"
		"a=fmtp:%d octet-align=1;mode-set=0,2,4,7\r\n"
		"a=rtpmap:%d telephone-event/16000\r\n"
		"a=fmtp:%d 0-15\r\n"
		"a=rtpmap:%d telephone-event/8000\r\n"
		"a=fmtp:%d 0-15\r\n"
		"a=ptime:20\r\n"
		"a=sendrecv\r\n",
		(unsigned long)now, (unsigned long)now, ctx->local_ip, ctx->local_ip,
		IMSD_PT_AMRWB, IMSD_PT_AMR, IMSD_PT_DTMF_WB, IMSD_PT_DTMF,
		IMSD_PT_AMRWB, IMSD_PT_AMRWB,
		IMSD_PT_AMR, IMSD_PT_AMR,
		IMSD_PT_DTMF_WB, IMSD_PT_DTMF_WB,
		IMSD_PT_DTMF, IMSD_PT_DTMF);

	char resp[3072];
	int len = snprintf(resp, sizeof(resp),
		"SIP/2.0 200 OK\r\n"
		"%s"
		"From: %s\r\n"
		"To: %s;tag=%s\r\n"
		"Call-ID: %s\r\n"
		"CSeq: %s\r\n"
		"Contact: <sip:%s@[%s]:%u>;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\"\r\n"
		"Allow: INVITE, ACK, CANCEL, BYE, PRACK\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: %d\r\n\r\n"
		"%s",
		ctx->inc_via, ctx->inc_from, ctx->inc_to, ctx->call_to_tag, ctx->inc_call_id, ctx->inc_cseq, ctx->impu_user, ctx->local_ip, IMSD_SIP_PORT, sdp_len, sdp);

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
			fprintf(stderr, "b2q-imsd: declined incoming call (603)\n");
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
				ruri, ctx->local_ip, IMSD_SIP_PORT, bye_branch,
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
		ruri, ctx->local_ip, IMSD_SIP_PORT, ctx->call_branch, ctx->impu, ctx->call_from_tag, ctx->call_remote, ctx->call_id, ctx->call_invite_cseq);
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
		ruri, ctx->local_ip, IMSD_SIP_PORT, bye_branch, ctx->impu, ctx->call_from_tag, ctx->call_remote, ctx->call_to_tag, ctx->call_id, ++ctx->call_cseq);
			send_sip_msg(ctx, req, len);
		}
	}

	uint32_t cid = ctx->active_call_id;
	ctx->call_state = IMSD_CALL_IDLE;
	imsd_emit_call_state_changed(ctx->bus, cid, 6, 0);
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

	/*
	 * Who we are comes from the ISIM (TS 31.103 EF_IMPI/EF_IMPU/EF_DOMAIN),
	 * not from constants: the same build works for any SIM, and no
	 * subscriber identity lives in the source.
	 */
	struct imsd_isim_identity id;
	int r = imsd_isim_read_identity(&id);
	if (r < 0) {
		fprintf(stderr, "b2q-imsd: cannot read the identity from the ISIM: %s\n", strerror(-r));
		return r;
	}
	if (strncmp(id.impu, "sip:", 4) != 0 || !strchr(id.impu, '@')) {
		fprintf(stderr, "b2q-imsd: ISIM public identity is not a SIP URI\n");
		return -EPROTO;
	}
	if (strcmp(id.domain, IMSD_DOMAIN) != 0)
		fprintf(stderr, "b2q-imsd: ISIM home domain %s differs from %s\n", id.domain, IMSD_DOMAIN);
	snprintf(ctx->impi, sizeof(ctx->impi), "%s", id.impi);
	snprintf(ctx->impu, sizeof(ctx->impu), "%s", id.impu);
	snprintf(ctx->impu_user, sizeof(ctx->impu_user), "%.*s",
		 (int)(strchr(id.impu, '@') - (id.impu + 4)), id.impu + 4);
	fprintf(stderr, "b2q-imsd: identity read from the ISIM\n");

	r = get_ims_ipv6(ctx->local_ip, sizeof(ctx->local_ip));
	if (r < 0) {
		fprintf(stderr, "b2q-imsd: failed to find IPv6 on %s: %d\n", IMSD_IMS_IFACE, r);
		return r;
	}

	ctx->fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (ctx->fd < 0) {
		fprintf(stderr, "b2q-imsd: socket failed: %s\n", strerror(errno));
		return -errno;
	}

	int val = 1;
	setsockopt(ctx->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	/*
	 * Linux takes a packet for a local address on any interface, so without
	 * this a host on Wi-Fi could hand us SIP (and fake SMS) for the IMS
	 * address. Only the carrier's side of the IMS PDN may reach this socket.
	 */
	if (setsockopt(ctx->fd, SOL_SOCKET, SO_BINDTODEVICE, IMSD_IMS_IFACE, sizeof(IMSD_IMS_IFACE)) < 0) {
		fprintf(stderr, "b2q-imsd: SO_BINDTODEVICE %s failed: %s\n", IMSD_IMS_IFACE, strerror(errno));
		int r = -errno;
		close(ctx->fd);
		ctx->fd = -1;
		return r;
	}

	struct sockaddr_in6 bind_addr;
	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_addr.sin6_family = AF_INET6;
	bind_addr.sin6_port = htons(IMSD_SIP_PORT);
	inet_pton(AF_INET6, ctx->local_ip, &bind_addr.sin6_addr);

	if (bind(ctx->fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
		int r = -errno;
		fprintf(stderr, "b2q-imsd: bind %s:%u failed: %s\n",
			ctx->local_ip, IMSD_SIP_PORT, strerror(-r));
		close(ctx->fd);
		ctx->fd = -1;
		return r;
	}

	memset(&ctx->pcscf_addr, 0, sizeof(ctx->pcscf_addr));
	ctx->pcscf_addr.sin6_family = AF_INET6;
	ctx->pcscf_addr.sin6_port = htons(IMSD_PCSCF_PORT);
	inet_pton(AF_INET6, IMSD_PCSCF_IP, &ctx->pcscf_addr.sin6_addr);

	rand_hex(ctx->reg_from_tag, 8);
	char cid_rnd[32];
	rand_hex(cid_rnd, 16);
	snprintf(ctx->reg_call_id, sizeof(ctx->reg_call_id), "%s@" IMSD_DOMAIN, cid_rnd);
	ctx->reg_cseq = 1;

	sd_event_source *io_src = NULL;
	r = sd_event_add_io(event, &io_src, ctx->fd, EPOLLIN, on_sip_packet, ctx);
	if (r < 0) {
		fprintf(stderr, "b2q-imsd: sd_event_add_io failed: %d\n", r);
		close(ctx->fd);
		return r;
	}

	fprintf(stderr, "b2q-imsd: SIP UDP socket bound to [%s]:%u\n", ctx->local_ip, IMSD_SIP_PORT);
	return imsd_sip_register(ctx);
}

void imsd_sip_destroy(struct imsd_sip_ctx *ctx)
{
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
	if (ctx->fd >= 0) {
		close(ctx->fd);
		ctx->fd = -1;
	}
}
