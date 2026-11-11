// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>

struct imsroha_device;

/* The modem's IMEI over QMI DMS. 0, or a negative errno. */
int imsroha_read_imei(const struct imsroha_device *dev, char *out, size_t size);
/* "352099001761481" -> "urn:gsma:imei:35209900-176148-0" (TS 23.003 13.8). */
int imsroha_imei_urn(const char *imei, char *out, size_t size);
