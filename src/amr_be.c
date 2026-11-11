// SPDX-License-Identifier: GPL-3.0-only
#include "amr_be.h"

#include <errno.h>
#include <string.h>

/* Speech bits per frame type (TS 26.101 / 26.201): FT 0-7 (AMR) or 0-8 (AMR-WB), then SID. */
static const unsigned short nb_bits[16] = { 95, 103, 118, 134, 148, 159, 204, 244, 39 };
static const unsigned short wb_bits[16] = { 132, 177, 253, 285, 317, 365, 397, 461, 477, 40 };

int imsroha_amr_frame_bits(int wb, unsigned ft)
{
	if (ft == 15)
		return 0; /* NO_DATA */
	if (ft > 15)
		return -EINVAL;
	unsigned short b = wb ? wb_bits[ft] : nb_bits[ft];
	return b ? b : -EINVAL;
}

struct bitw {
	uint8_t *p;
	size_t size, bit;
};

static int put(struct bitw *w, unsigned v, unsigned n)
{
	for (unsigned i = 0; i < n; i++) {
		size_t byte = w->bit / 8;
		if (byte >= w->size)
			return -ENOSPC;
		if (w->bit % 8 == 0)
			w->p[byte] = 0;
		if (v >> (n - 1 - i) & 1)
			w->p[byte] |= (uint8_t)(0x80 >> (w->bit % 8));
		w->bit++;
	}
	return 0;
}

static unsigned get(const uint8_t *p, size_t bit)
{
	return p[bit / 8] >> (7 - bit % 8) & 1;
}

int imsroha_amr_be_pack(int wb, const uint8_t *storage, size_t len, unsigned cmr,
			uint8_t *out, size_t size)
{
	if (len < 1)
		return -EINVAL;
	unsigned ft = storage[0] >> 3 & 0x0f, q = storage[0] >> 2 & 1;
	int bits = imsroha_amr_frame_bits(wb, ft);
	if (bits < 0 || len < 1 + (size_t)(bits + 7) / 8)
		return -EINVAL;

	/* RFC 4867 4.3: CMR (4), then one ToC entry F (1) FT (4) Q (1), then the speech bits. */
	struct bitw w = { out, size, 0 };
	if (put(&w, cmr & 0x0f, 4) || put(&w, 0, 1) || put(&w, ft, 4) || put(&w, q, 1))
		return -ENOSPC;
	for (int i = 0; i < bits; i++)
		if (put(&w, get(storage + 1, (size_t)i), 1))
			return -ENOSPC;
	/* Pad to a whole octet with zeros. */
	while (w.bit % 8)
		if (put(&w, 0, 1))
			return -ENOSPC;
	return (int)(w.bit / 8);
}

int imsroha_amr_be_unpack(int wb, const uint8_t *payload, size_t len, uint8_t *storage, size_t size)
{
	size_t bit = 4; /* past the CMR */
	unsigned f, ft = 15, q = 1;
	int first = 1;

	if (len < 2)
		return -EINVAL;
	/* The ToC: entries while F = 1. Only the first frame is kept (ptime 20, one frame). */
	do {
		if (bit + 6 > len * 8)
			return -EINVAL;
		f = get(payload, bit);
		unsigned t = 0;
		for (int i = 0; i < 4; i++)
			t = t << 1 | get(payload, bit + 1 + (size_t)i);
		unsigned qq = get(payload, bit + 5);
		bit += 6;
		if (first) {
			ft = t;
			q = qq;
			first = 0;
		}
	} while (f);

	int bits = imsroha_amr_frame_bits(wb, ft);
	if (bits < 0 || bit + (size_t)bits > len * 8)
		return -EINVAL;
	size_t need = 1 + (size_t)(bits + 7) / 8;
	if (need > size)
		return -ENOSPC;
	memset(storage, 0, need);
	storage[0] = (uint8_t)(ft << 3 | q << 2);
	for (int i = 0; i < bits; i++)
		if (get(payload, bit + (size_t)i))
			storage[1 + i / 8] |= (uint8_t)(0x80 >> (i % 8));
	return (int)need;
}
