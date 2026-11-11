// SPDX-License-Identifier: GPL-3.0-only
/*
 * Golden-output test for the SIP layer. It includes sip.c, stubs the modem,
 * audio and inbox, plays a fake P-CSCF on loopback and writes every message
 * imsroha sends, in order, to stdout. tests/normalize.sh strips the random
 * fields (branch, tags, Call-ID, SDP session ids), so two builds can be
 * compared byte for byte.
 *
 * The scenario: REGISTER, 401 + AKA, 200 OK, MO-SMS, MO call and CANCEL,
 * MT-SMS, MT call answered and hung up by the far end.
 */
#include "../src/sip.c"

#include <poll.h>

/* --- stubs --------------------------------------------------------------- */

int imsd_aka_run_isim(const struct imsd_aka_challenge *ch, struct imsd_aka_result *out)
{
	(void)ch;
	memset(out, 0, sizeof(*out));
	for (int i = 0; i < 8; i++)
		out->res[i] = (unsigned char)(0xa0 + i);
	out->res_len = 8;
	for (int i = 0; i < 16; i++) {
		out->ck[i] = (unsigned char)i;
		out->ik[i] = (unsigned char)(0x10 + i);
	}
	out->success = 1;
	return 0;
}

int imsd_isim_read_identity(struct imsd_isim_identity *id) { (void)id; return -ENOSYS; }
void imsroha_sim_set_device(const struct imsroha_device *dev) { (void)dev; }
int imsd_audio_init(sd_event *e) { (void)e; return 0; }
void imsd_audio_call_start(void) {}
void imsd_audio_call_end(void) {}
void imsd_audio_downlink(const int16_t pcm[IMSD_AUDIO_FRAME]) { (void)pcm; }
int imsd_audio_uplink(int16_t pcm[IMSD_AUDIO_FRAME]) { memset(pcm, 0, IMSD_AUDIO_FRAME * 2); return 0; }
int imsd_codec_open(struct imsd_codec_state *st) { (void)st; return 0; }
void imsd_codec_close(struct imsd_codec_state *st) { (void)st; }
int imsd_codec_encode(struct imsd_codec_state *st, enum imsd_codec c, const int16_t pcm[IMSD_PCM_FRAME],
		      uint8_t *out, size_t out_size) { (void)st; (void)c; (void)pcm; (void)out; (void)out_size; return 0; }
int imsd_codec_decode(struct imsd_codec_state *st, enum imsd_codec c, const uint8_t *f, size_t len,
		      int16_t pcm[IMSD_PCM_FRAME]) { (void)st; (void)c; (void)f; (void)len; memset(pcm, 0, IMSD_PCM_FRAME * 2); return 0; }
int imsd_inbox_init(void) { return 0; }
int imsd_inbox_store(const char *pdu, char id[IMSD_INBOX_ID_LEN]) { (void)pdu; snprintf(id, IMSD_INBOX_ID_LEN, "0000000000000000-000000"); return 0; }
int imsd_inbox_remove(const char *id) { (void)id; return 0; }
int imsd_inbox_seen(const char *pdu) { (void)pdu; return 0; }
void imsd_inbox_remember(const char *pdu) { (void)pdu; }
void imsd_emit_state_changed(sd_bus *b, int s) { (void)b; (void)s; }
void imsd_emit_pdu_received(sd_bus *b, const char *id, const char *pdu) { (void)b; (void)id; (void)pdu; }
void imsd_emit_call_added(sd_bus *b, uint32_t c, const char *n, int d) { (void)b; (void)c; (void)n; (void)d; }
void imsd_emit_call_state_changed(sd_bus *b, uint32_t c, int s, int r) { (void)b; (void)c; (void)s; (void)r; }

/* --- the fake P-CSCF ---------------------------------------------------- */

static int pcscf_fd;              /* the P-CSCF's plain port */
static int pcscf_ps = -1, pcscf_pc = -1; /* its protected ports, for sec-agree */
static struct sockaddr_in6 ue_addr;
static int step;
#define FAKE_PORT_PS 6100
#define FAKE_PORT_PC 6101

/* The P-CSCF socket that has something from the UE, or -1. */
static int ready_fd(int timeout_ms)
{
	struct pollfd p[3] = { { .fd = pcscf_fd, .events = POLLIN },
			       { .fd = pcscf_ps, .events = POLLIN },
			       { .fd = pcscf_pc, .events = POLLIN } };
	if (poll(p, 3, timeout_ms) <= 0)
		return -1;
	for (int i = 0; i < 3; i++)
		if (p[i].revents & POLLIN)
			return p[i].fd;
	return -1;
}

/* Everything the UE sent since the last call, each message framed. */
static void drain(const char *label)
{
	char buf[8192];
	printf("===== step %d: %s\n", ++step, label);
	for (;;) {
		int fd = ready_fd(50);
		if (fd < 0)
			break;
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		if (n <= 0)
			break;
		printf("----- %zd bytes%s\n", n, fd == pcscf_ps ? " (to port-s)" : fd == pcscf_pc ? " (to port-c)" : "");
		for (ssize_t i = 0; i < n; i++) {
			unsigned char c = (unsigned char)buf[i];
			if (c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f))
				putchar(c);
			else
				printf("\\x%02x", c);
		}
		printf("\n");
	}
	fflush(stdout);
}

/*
 * Hands the UE what just went to fd, once it is there: through real ESP the
 * kernel's crypto delivers it a moment after sendto() returns.
 */
static void deliver(struct imsd_sip_ctx *ctx, int fd)
{
	struct pollfd p = { .fd = fd, .events = POLLIN };
	if (poll(&p, 1, 2000) > 0)
		on_sip_packet(NULL, fd, EPOLLIN, ctx);
	else
		fprintf(stderr, "golden: nothing arrived on fd %d\n", fd);
}

/*
 * Over sec-agree, the P-CSCF answers from port_ps to the UE's port_uc and
 * sends its own requests from port_pc to the UE's port_us; before, from its
 * plain port to the UE's.
 */
static void to_ue(struct imsd_sip_ctx *ctx, const void *msg, size_t len)
{
	fflush(stdout);
	if (ctx->sec_state == IMSD_SEC_PROTECTED) {
		int response = !memcmp(msg, "SIP/2.0 ", 8);
		struct sockaddr_in6 to = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT,
			.sin6_port = htons(response ? ctx->sec.port_uc : ctx->sec.port_us) };
		sendto(response ? pcscf_ps : pcscf_pc, msg, len, 0, (struct sockaddr *)&to, sizeof(to));
		deliver(ctx, response ? ctx->fd_c : ctx->fd_s);
		return;
	}
	sendto(pcscf_fd, msg, len, 0, (struct sockaddr *)&ue_addr, sizeof(ue_addr));
	deliver(ctx, ctx->fd);
}

static void to_ue_str(struct imsd_sip_ctx *ctx, const char *msg)
{
	to_ue(ctx, msg, strlen(msg));
}

/* The UE's Call-ID/branch/tag of the last request, for responses that echo them. */
static char last[8192];
static void capture_last(void)
{
	last[0] = 0;
	int fd = ready_fd(50);
	if (fd >= 0) {
		ssize_t n = recv(fd, last, sizeof(last) - 1, MSG_PEEK);
		if (n > 0)
			last[n] = 0;
	}
}

static void hdr(const char *name, char *out, size_t size)
{
	out[0] = 0;
	find_header(last, name, out, size);
}

#include "golden-setup.h"

int main(void)
{
	struct imsd_sip_ctx ctx;
	sd_event *event = NULL;
	char resp[4096], via[1024], from[256], to[256], cid[256], cseq[64];

	srand(1);
	sd_event_default(&event);

	pcscf_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	struct sockaddr_in6 pa = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
	bind(pcscf_fd, (struct sockaddr *)&pa, sizeof(pa));
	socklen_t pl = sizeof(pa);
	getsockname(pcscf_fd, (struct sockaddr *)&pa, &pl);

	int ue_fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	ue_addr = (struct sockaddr_in6){ .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
	bind(ue_fd, (struct sockaddr *)&ue_addr, sizeof(ue_addr));
	pl = sizeof(ue_addr);
	getsockname(ue_fd, (struct sockaddr *)&ue_addr, &pl);

	golden_setup(&ctx, event, ue_fd, &pa);
	if (ctx.sec_state == IMSD_SEC_OFFERED) {
		/* The UE's protected sockets, as imsd_sip_init() opens them, and the P-CSCF's. */
		struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
		ctx.fd_c = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		a.sin6_port = htons(ctx.sec.port_uc);
		bind(ctx.fd_c, (struct sockaddr *)&a, sizeof(a));
		ctx.fd_s = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		a.sin6_port = htons(ctx.sec.port_us);
		bind(ctx.fd_s, (struct sockaddr *)&a, sizeof(a));
		pcscf_ps = socket(AF_INET6, SOCK_DGRAM, 0);
		a.sin6_port = htons(FAKE_PORT_PS);
		bind(pcscf_ps, (struct sockaddr *)&a, sizeof(a));
		pcscf_pc = socket(AF_INET6, SOCK_DGRAM, 0);
		a.sin6_port = htons(FAKE_PORT_PC);
		bind(pcscf_pc, (struct sockaddr *)&a, sizeof(a));
	}

	/* 1. initial REGISTER */
	imsd_sip_register(&ctx);
	capture_last();
	drain("initial REGISTER");

	/* 2. 401 with an AKA nonce (RAND || AUTN), then the authenticated REGISTER */
	hdr("Via", via, sizeof(via)); hdr("From", from, sizeof(from)); hdr("To", to, sizeof(to));
	hdr("Call-ID", cid, sizeof(cid)); hdr("CSeq", cseq, sizeof(cseq));
	snprintf(resp, sizeof(resp),
		"SIP/2.0 401 Unauthorized\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=pcscf1\r\nCall-ID: %s\r\nCSeq: %s\r\n"
		"WWW-Authenticate: Digest realm=\"%s\", nonce=\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\", algorithm=AKAv1-MD5, qop=\"auth\"\r\n"
		"%s"
		"Content-Length: 0\r\n\r\n", via, from, to, cid, cseq, ctx.domain,
		ctx.sec_state == IMSD_SEC_OFFERED ?
		"Security-Server: ipsec-3gpp;q=0.1;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=4444;spi-s=5555;port-c=6101;port-s=6100\r\n" : "");
	to_ue_str(&ctx, resp);
	if (getenv("GOLDEN_REAL_IP") && ctx.sec.installed) {
		/*
		 * Both ends share one kernel here: the P-CSCF's sockets need out
		 * policies mirroring the UE's in policies, so its packets to the UE
		 * are ESP too. The UE's own policies and SAs are imsroha's.
		 */
		char cmd[512];
		snprintf(cmd, sizeof(cmd),
			 "ip -6 xfrm policy add src ::1/128 dst ::1/128 proto udp sport %u dport %u dir out "
			 "tmpl src ::1 dst ::1 proto esp spi 0x%08x mode transport && "
			 "ip -6 xfrm policy add src ::1/128 dst ::1/128 proto udp sport %u dport %u dir out "
			 "tmpl src ::1 dst ::1 proto esp spi 0x%08x mode transport",
			 ctx.sec.port_ps, ctx.sec.port_uc, ctx.sec.spi_uc,
			 ctx.sec.port_pc, ctx.sec.port_us, ctx.sec.spi_us);
		if (system(cmd) != 0)
			fprintf(stderr, "golden: mirror policies failed\n");
	}
	capture_last();
	drain("authenticated REGISTER");

	/* 3. 200 OK */
	hdr("Via", via, sizeof(via)); hdr("From", from, sizeof(from)); hdr("To", to, sizeof(to));
	hdr("Call-ID", cid, sizeof(cid)); hdr("CSeq", cseq, sizeof(cseq));
	snprintf(resp, sizeof(resp),
		"SIP/2.0 200 OK\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=pcscf1\r\nCall-ID: %s\r\nCSeq: %s\r\n"
		"Service-Route: <sip:scscf.%s;lr>\r\nP-Associated-URI: <sip:01000000000@%s>\r\n"
		"Contact: <sip:x@[::1]>;expires=3600\r\nExpires: 3600\r\nContent-Length: 0\r\n\r\n",
		via, from, to, cid, cseq, ctx.domain, ctx.domain);
	to_ue_str(&ctx, resp);
	drain("after 200 OK to REGISTER");

	/* 4. MO-SMS */
	imsd_sip_send_sms(&ctx, "+821012345678", "hi", NULL);
	drain("MO-SMS MESSAGE");

	/* 5. MO call, then hang up before an answer (CANCEL) */
	uint32_t call_id = 0;
	imsd_sip_place_call(&ctx, "01012345678", &call_id);
	capture_last();
	drain("MO INVITE");
	hdr("Via", via, sizeof(via)); hdr("From", from, sizeof(from)); hdr("To", to, sizeof(to));
	hdr("Call-ID", cid, sizeof(cid)); hdr("CSeq", cseq, sizeof(cseq));
	snprintf(resp, sizeof(resp),
		"SIP/2.0 180 Ringing\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=far1\r\nCall-ID: %s\r\nCSeq: %s\r\n"
		"Contact: <sip:far@[::1]:5060>\r\nContent-Length: 0\r\n\r\n", via, from, to, cid, cseq);
	to_ue_str(&ctx, resp);
	drain("after 180");
	imsd_sip_hangup(&ctx);
	drain("CANCEL");

	/* 6. MT-SMS (RP-DATA, SMS-DELIVER "hi" from 01012345678) */
	static const unsigned char rp[] = {
		0x01, 0x05, 0x07, 0x91, 0x28, 0x01, 0x02, 0x29, 0x81, 0x72, 0x00, 21,
		0x04, 0x0b, 0x81, 0x10, 0x10, 0x32, 0x54, 0x76, 0xf8, 0x00, 0x00,
		0x52, 0x11, 0x11, 0x21, 0x43, 0x00, 0x00, 0x02, 0xe8, 0x34,
	};
	char mt[2048];
	int hl = snprintf(mt, sizeof(mt),
		"MESSAGE sip:01000000000@[::1] SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [::1]:5060;branch=z9hG4bKmt1\r\n"
		"From: <tel:+821020921827>;tag=smsc1\r\nTo: <sip:01000000000@%s>\r\n"
		"Call-ID: mt-sms-1@%s\r\nCSeq: 1 MESSAGE\r\n"
		"Content-Type: application/vnd.3gpp.sms\r\nContent-Length: %zu\r\n\r\n",
		ctx.domain, ctx.domain, sizeof(rp));
	memcpy(mt + hl, rp, sizeof(rp));
	to_ue(&ctx, mt, hl + sizeof(rp));
	drain("MT-SMS answers");

	/* 7. MT call: INVITE with AMR-WB 100 / AMR 96 / DTMF, answer, far end BYE */
	static const char sdp[] =
		"v=0\r\no=- 1 1 IN IP6 ::1\r\ns=-\r\nc=IN IP6 ::1\r\nt=0 0\r\n"
		"m=audio 41000 RTP/AVP 100 96 101 102\r\n"
		"a=rtpmap:100 AMR-WB/16000\r\na=fmtp:100 mode-change-capability=2;max-red=0\r\n"
		"a=rtpmap:96 AMR/8000\r\na=fmtp:96 mode-change-capability=2;max-red=0\r\n"
		"a=rtpmap:101 telephone-event/16000\r\na=rtpmap:102 telephone-event/8000\r\n"
		"a=ptime:20\r\na=sendrecv\r\n";
	snprintf(resp, sizeof(resp),
		"INVITE sip:01000000000@[::1]:5060 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [::1]:5060;branch=z9hG4bKmtcall1\r\n"
		"From: <tel:01012345678;phone-context=%s>;tag=far2\r\nTo: <sip:01000000000@%s>\r\n"
		"Call-ID: mt-call-1@%s\r\nCSeq: 1 INVITE\r\nContact: <sip:far@[::1]:5060>\r\n"
		"Content-Type: application/sdp\r\nContent-Length: %zu\r\n\r\n%s",
		ctx.domain, ctx.domain, ctx.domain, strlen(sdp), sdp);
	to_ue_str(&ctx, resp);
	drain("MT INVITE provisional");
	imsd_sip_answer_call(&ctx);
	drain("MT answer");
	snprintf(resp, sizeof(resp),
		"BYE sip:01000000000@[::1]:5060 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [::1]:5060;branch=z9hG4bKbye1\r\n"
		"From: <tel:01012345678;phone-context=%s>;tag=far2\r\nTo: <sip:01000000000@%s>;tag=%s\r\n"
		"Call-ID: mt-call-1@%s\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n",
		ctx.domain, ctx.domain, ctx.call_to_tag, ctx.domain);
	to_ue_str(&ctx, resp);
	drain("MT BYE answer");
	if (getenv("GOLDEN_REAL_IP"))
		/* Proof that the kernel carried it as ESP: per-SA packet counters. */
		system("ip -s -6 xfrm state | grep -E '^\\s+proto esp|packets' 1>&2");
	return 0;
}
