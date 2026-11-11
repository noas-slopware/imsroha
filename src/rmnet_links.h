// SPDX-License-Identifier: GPL-3.0-only
#pragma once

/*
 * Deletes every rmnet link on parent that uses mux_id, whatever its name:
 * a bearer stopped without cleaning up (another IMS stack, an older
 * imsroha with another ims-netdev, b2q-imsd's qmapmux0.3) keeps the mux id
 * busy, and the kernel then refuses a new link on it ("MUX ID already
 * exists"). Returns how many links it deleted, or < 0 when ip failed.
 */
int imsroha_rmnet_clear_mux(const char *parent, int mux_id);
