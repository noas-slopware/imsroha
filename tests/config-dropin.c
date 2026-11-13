// SPDX-License-Identifier: GPL-3.0-only
/* imsroha.conf.d: drop-ins merge in name order, imsroha.conf wins, and
 * IMSROHA_CONF alone (as the other tests set it) reads no drop-ins. */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define D GOLDEN_SRCDIR "/tests/config-dropin"

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void)
{
	struct imsroha_device dev;
	struct imsroha_config cfg;

	setenv("IMSROHA_CONF", D "/imsroha.conf", 1);
	setenv("IMSROHA_CONF_DIR", D, 1);
	setenv("IMSROHA_CARRIERS", D "/none", 1);
	CHECK(imsroha_config_load_device(&dev) == 0);
	CHECK(dev.qrtr_node == 1);
	CHECK(dev.mux_id == 5);
	CHECK(!strcmp(dev.model, "SM-TEST"));
	CHECK(!strcmp(dev.operator_, "LGU"));
	CHECK(imsroha_config_load(&cfg, "450", "06") == 0);
	CHECK(cfg.rcs_enabled == 1);
	CHECK(cfg.dev.mux_id == 5);

	unsetenv("IMSROHA_CONF_DIR");
	CHECK(imsroha_config_load_device(&dev) == 0);
	CHECK(dev.qrtr_node == 0);
	CHECK(dev.mux_id == 3);
	CHECK(!strcmp(dev.model, "imsroha"));
	CHECK(!strcmp(dev.operator_, "LGU"));

	setenv("IMSROHA_CONF_DIR", "", 1);
	setenv("IMSROHA_CONF", D "/missing.conf", 1);
	CHECK(imsroha_config_load_device(&dev) == 0);
	CHECK(!strcmp(dev.operator_, "OMD"));

	return fails ? 1 : 0;
}
