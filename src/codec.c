// SPDX-License-Identifier: MIT
#include "codec.h"

#include <errno.h>
#include <string.h>

#include <opencore-amrnb/interf_dec.h>
#include <opencore-amrnb/interf_enc.h>
#include <opencore-amrwb/dec_if.h>
#include <vo-amrwbenc/enc_if.h>

/* AMR-WB mode 2 (12.65 kbit/s) and AMR-NB MR122 (12.2 kbit/s): both inside
 * the mode-sets imsd offers and LG U+ answers with. */
#define WB_MODE 2
#define NB_MODE MR122

/*
 * 15-tap half-band low-pass, cut-off at a quarter of 16 kHz, Q15. Used both
 * to band-limit before dropping to 8 kHz and to interpolate on the way up.
 * Taps sum to 32768 (unity gain at DC).
 */
static const int32_t hb[15] = {
	-347, 0, 1078, 0, -2644, 0, 10105, 16384, 10105, 0, -2644, 0, 1078, 0, -347,
};

static int16_t sat16(int32_t v)
{
	return v > 32767 ? 32767 : v < -32768 ? -32768 : (int16_t)v;
}

/* 320 samples at 16 kHz -> 160 at 8 kHz. */
static void downsample(struct imsd_codec_state *st, const int16_t *in, int16_t *out)
{
	int16_t buf[14 + IMSD_PCM_FRAME];

	memcpy(buf, st->down_hist, sizeof(st->down_hist));
	memcpy(buf + 14, in, IMSD_PCM_FRAME * sizeof(int16_t));
	for (int n = 0; n < IMSD_PCM_FRAME / 2; n++) {
		int64_t acc = 0;
		const int16_t *x = buf + 2 * n; /* x[14] is the newest input sample */
		for (int k = 0; k < 15; k++)
			acc += (int64_t)hb[k] * x[14 - k];
		out[n] = sat16((int32_t)((acc + 16384) >> 15));
	}
	memcpy(st->down_hist, buf + IMSD_PCM_FRAME, sizeof(st->down_hist));
}

/* 160 samples at 8 kHz -> 320 at 16 kHz: zero-stuff, then filter with gain 2. */
static void upsample(struct imsd_codec_state *st, const int16_t *in, int16_t *out)
{
	int16_t buf[14 + IMSD_PCM_FRAME];

	memcpy(buf, st->up_hist, sizeof(st->up_hist));
	for (int n = 0; n < IMSD_PCM_FRAME / 2; n++) {
		buf[14 + 2 * n] = in[n];
		buf[14 + 2 * n + 1] = 0;
	}
	for (int n = 0; n < IMSD_PCM_FRAME; n++) {
		int64_t acc = 0;
		const int16_t *x = buf + n;
		for (int k = 0; k < 15; k++)
			acc += (int64_t)hb[k] * x[14 - k];
		out[n] = sat16((int32_t)((2 * acc + 16384) >> 15));
	}
	memcpy(st->up_hist, buf + IMSD_PCM_FRAME, sizeof(st->up_hist));
}

int imsd_codec_open(struct imsd_codec_state *st)
{
	memset(st, 0, sizeof(*st));
	st->wb_dec = D_IF_init();
	st->wb_enc = E_IF_init();
	st->nb_dec = Decoder_Interface_init();
	st->nb_enc = Encoder_Interface_init(0);
	if (!st->wb_dec || !st->wb_enc || !st->nb_dec || !st->nb_enc) {
		imsd_codec_close(st);
		return -ENOMEM;
	}
	return 0;
}

void imsd_codec_close(struct imsd_codec_state *st)
{
	if (st->wb_dec)
		D_IF_exit(st->wb_dec);
	if (st->wb_enc)
		E_IF_exit(st->wb_enc);
	if (st->nb_dec)
		Decoder_Interface_exit(st->nb_dec);
	if (st->nb_enc)
		Encoder_Interface_exit(st->nb_enc);
	memset(st, 0, sizeof(*st));
}

int imsd_codec_encode(struct imsd_codec_state *st, enum imsd_codec codec,
		      const int16_t pcm[IMSD_PCM_FRAME], uint8_t *out, size_t out_size)
{
	uint8_t frame[64];
	int len;

	if (codec == IMSD_CODEC_AMRNB) {
		int16_t pcm8[IMSD_PCM_FRAME / 2];
		if (!st->nb_enc)
			return -EINVAL;
		downsample(st, pcm, pcm8);
		len = Encoder_Interface_Encode(st->nb_enc, NB_MODE, pcm8, frame, 0);
	} else {
		if (!st->wb_enc)
			return -EINVAL;
		len = E_IF_encode(st->wb_enc, WB_MODE, pcm, frame, 0);
	}
	if (len <= 0 || (size_t)len > out_size)
		return -EMSGSIZE;
	memcpy(out, frame, len);
	return len;
}

int imsd_codec_decode(struct imsd_codec_state *st, enum imsd_codec codec,
		      const uint8_t *frame, size_t len, int16_t pcm[IMSD_PCM_FRAME])
{
	if (len < 1)
		return -EINVAL;
	if (codec == IMSD_CODEC_AMRNB) {
		int16_t pcm8[IMSD_PCM_FRAME / 2];
		if (!st->nb_dec)
			return -EINVAL;
		Decoder_Interface_Decode(st->nb_dec, frame, pcm8, 0);
		upsample(st, pcm8, pcm);
	} else {
		if (!st->wb_dec)
			return -EINVAL;
		D_IF_decode(st->wb_dec, frame, pcm, 0);
	}
	return 0;
}
