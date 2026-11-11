// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * RFC 4867 bandwidth-efficient AMR / AMR-WB payloads, from and to the
 * storage format the codec speaks (a header byte FT << 3 | Q << 2, then the
 * speech bits, MSB first, padded to octets). TTAK.KO-06.0357 6.2.5 wants
 * both payload formats; the octet-aligned one is CMR byte + storage frame.
 */

/* Speech bits of a frame type, 0 for NO_DATA, < 0 for a reserved type. */
int imsroha_amr_frame_bits(int wb, unsigned ft);

/* Storage frame -> RTP payload (CMR, one ToC entry, bits). Returns its length or < 0. */
int imsroha_amr_be_pack(int wb, const uint8_t *storage, size_t len, unsigned cmr,
			uint8_t *out, size_t size);

/* RTP payload -> the first frame in storage format. Returns its length or < 0. */
int imsroha_amr_be_unpack(int wb, const uint8_t *payload, size_t len, uint8_t *storage, size_t size);
