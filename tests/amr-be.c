// SPDX-License-Identifier: GPL-3.0-only
/*
 * Bandwidth-efficient AMR packing: every frame type round-trips through
 * pack/unpack bit for bit, and one AMR-WB 12.65 frame packs to the layout
 * RFC 4867 4.3 gives (CMR, F, FT, Q, then the bits with no gap).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/amr_be.h"

static int fail;

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("FAIL: %s\n", what);
		fail = 1;
	}
}

int main(void)
{
	uint8_t st[64], pl[80], back[64];
	srand(7);
	for (int wb = 0; wb <= 1; wb++) {
		for (unsigned ft = 0; ft < 16; ft++) {
			int bits = imsroha_amr_frame_bits(wb, ft);
			if (bits < 0)
				continue;
			size_t sl = 1 + (size_t)(bits + 7) / 8;
			memset(st, 0, sizeof(st));
			st[0] = (uint8_t)(ft << 3 | 1 << 2);
			for (int i = 0; i < bits; i++)
				if (rand() & 1)
					st[1 + i / 8] |= (uint8_t)(0x80 >> (i % 8));
			int pn = imsroha_amr_be_pack(wb, st, sl, 15, pl, sizeof(pl));
			check(pn == (10 + bits + 7) / 8, "packed length is CMR + ToC + bits, padded");
			int bn = imsroha_amr_be_unpack(wb, pl, (size_t)pn, back, sizeof(back));
			char what[64];
			snprintf(what, sizeof(what), "%s FT %u round trip", wb ? "AMR-WB" : "AMR", ft);
			check(bn == (int)sl && !memcmp(st, back, sl), what);
		}
	}
	/* AMR-WB FT 2, Q 1, first speech bits 1,0,1,1: CMR 1111, F 0, FT 0010, Q 1, then 1011... */
	memset(st, 0, sizeof(st));
	st[0] = 2 << 3 | 1 << 2;
	st[1] = 0xb0;
	int pn = imsroha_amr_be_pack(1, st, 1 + 32, 15, pl, sizeof(pl));
	check(pn == 33, "AMR-WB 12.65: 4 + 6 + 253 bits = 33 octets");
	check(pl[0] == 0xf1 && pl[1] == 0x6c, "AMR-WB 12.65 header bits");
	puts(fail ? "amr-be: FAILED" : "amr-be: all frame types round-trip");
	return fail;
}
