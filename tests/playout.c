// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Downlink playout across a change of RTP source, as on LG U+ when the callee
 * declines an outgoing call: the ringback (SSRC d823ef70) is replaced by an
 * announcement server (SSRC c178d905) whose timestamps carry on from the
 * ringback's but sit 110 ticks off its 320-tick grid. The headers below are
 * the ones in the Flip3's log of 2026-11-19 03:01:40-03:02:03.
 */
#include "../src/sip.c"

#include <assert.h>

/* --- stubs, as in sip-golden.c ----------------------------------------- */

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
void imsd_emit_port_pdu_received(sd_bus *b, uint16_t port, const char *pdu) { (void)b; (void)port; (void)pdu; }
void imsd_emit_call_added(sd_bus *b, uint32_t c, const char *n, int d) { (void)b; (void)c; (void)n; (void)d; }
void imsd_emit_call_state_changed(sd_bus *b, uint32_t c, int s, int r) { (void)b; (void)c; (void)s; (void)r; }


static uint8_t wb_frame[33] = { 0x14 };	/* AMR-WB 12.65 kbit/s, ToC then 32 bytes */

/* one 20 ms tick with one frame arriving; returns 1 if a received frame was played */
static int tick(struct imsd_sip_ctx *ctx, int put, uint32_t ssrc, uint32_t ts)
{
	uint64_t filled = ctx->playout_filled;

	if (put)
		playout_put(ctx, ssrc, ts, 1, wb_frame, sizeof(wb_frame));
	playout_tick(ctx);
	return ctx->playout_filled == filled;
}

static struct imsd_sip_ctx *new_ctx(void)
{
	struct imsd_sip_ctx *ctx = calloc(1, sizeof(*ctx));

	assert(ctx);
	assert(imsd_codec_open(&ctx->codec) == 0);
	ctx->codec_open = 1;
	return ctx;
}

int main(void)
{
	const uint32_t ring = 0xd823ef70, annc = 0xc178d905;
	uint32_t ts = 0xfd251b79;
	struct imsd_sip_ctx *ctx = new_ctx();
	int played = 0, i;

	/*
	 * 21 s of ringback, up to the switch: rx #1001 was seq 1249, ts fd29fd79,
	 * and the ringback ran on to the frame just before the announcement's
	 * first, 210 ticks before it: inside the playout window, off its grid.
	 */
	for (i = 0; i < 1055; i++, ts += 320)
		played += tick(ctx, 1, ring, ts);
	printf("ringback: %d of 1055 ticks played\n", played);
	assert(played >= 1055 - IMSD_PLAYOUT_DELAY);
	uint32_t ring_ts = ts;

	/* the announcement, its first timestamp as logged */
	ts = 0xfd2a41cb;
	assert(ts - ring_ts == 210 - 320);
	played = 0;
	for (i = 0; i < 150; i++, ts += 320, ring_ts += 320) {
		played += tick(ctx, 1, annc, ts);
		/* a ringback packet still in flight now and then */
		if (i % 20 == 5)
			playout_put(ctx, ring, ring_ts, 1, wb_frame, sizeof(wb_frame));
	}
	printf("announcement: %d of 150 ticks played, %" PRIu64 " resyncs\n", played,
	       ctx->playout_resyncs);
	assert(played >= 150 - IMSD_PLAYOUT_DELAY);
	assert(ctx->playout_resyncs == 1);

	/* a late frame on the grid is late, not a new timeline */
	playout_put(ctx, annc, ctx->playout_ts - 2 * 320, 1, wb_frame, sizeof(wb_frame));
	assert(ctx->playout_resyncs == 1);
	assert(ctx->playout_late == 1);

	imsd_codec_close(&ctx->codec);
	free(ctx);
	printf("ok\n");
	return 0;
}
