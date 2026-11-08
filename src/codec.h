#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Speech codecs for a call: AMR-WB (16 kHz) and AMR-NB (8 kHz). The audio
 * bridge always works at 16 kHz, 320 samples per 20 ms; AMR-NB frames are
 * resampled on the way in and out. Frames are in the AMR storage format
 * (first byte FT << 3 | Q << 2), which is also the octet-aligned RTP ToC.
 */

#define IMSD_PCM_FRAME 320 /* 20 ms at 16 kHz */

enum imsd_codec {
	IMSD_CODEC_AMRWB,
	IMSD_CODEC_AMRNB,
};

struct imsd_codec_state {
	void *wb_dec, *wb_enc, *nb_dec, *nb_enc;
	int16_t down_hist[14]; /* 16 -> 8 kHz FIR history */
	int16_t up_hist[14];   /* 8 -> 16 kHz FIR history (zero-stuffed signal) */
};

int imsd_codec_open(struct imsd_codec_state *st);
void imsd_codec_close(struct imsd_codec_state *st);

/* One 20 ms frame in, one storage-format frame out. Returns its length or < 0. */
int imsd_codec_encode(struct imsd_codec_state *st, enum imsd_codec codec,
		      const int16_t pcm[IMSD_PCM_FRAME], uint8_t *out, size_t out_size);

/* One storage-format frame in, 20 ms of 16 kHz PCM out. Returns 0 or < 0. */
int imsd_codec_decode(struct imsd_codec_state *st, enum imsd_codec codec,
		      const uint8_t *frame, size_t len, int16_t pcm[IMSD_PCM_FRAME]);

/* RTP clock ticks per 20 ms frame. */
static inline uint32_t imsd_codec_ticks(enum imsd_codec codec)
{
	return codec == IMSD_CODEC_AMRNB ? 160 : 320;
}
