// SPDX-License-Identifier: GPL-3.0-only
#include "rmnet_links.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

int imsroha_rmnet_clear_mux(const char *parent, int mux_id)
{
	const char *const show[] = { "ip", "-o", "-d", "link", "show", NULL };
	char *out = NULL;
	int status = 0, n = 0;
	char want[32];

	if (!g_spawn_sync(NULL, (char **)show, NULL, G_SPAWN_SEARCH_PATH | G_SPAWN_STDERR_TO_DEV_NULL,
			  NULL, NULL, &out, NULL, &status, NULL) || !g_spawn_check_wait_status(status, NULL)) {
		g_free(out);
		return -EIO;
	}
	/* One line per link: "7: name@parent: <...> ... rmnet mux_id 3 <...> ..." */
	snprintf(want, sizeof(want), " rmnet mux_id %d ", mux_id);
	for (char *save = NULL, *line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		char *p = strstr(line, ": ");
		if (!p || !strstr(line, want))
			continue;
		p += 2;
		char *at = strchr(p, '@'), *colon = strchr(p, ':');
		if (!at || !colon || at > colon)
			continue;
		*at = '\0';
		*colon = '\0';
		if (strcmp(at + 1, parent))
			continue;
		const char *const del[] = { "ip", "link", "del", p, NULL };
		if (g_spawn_sync(NULL, (char **)del, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, NULL, NULL,
				 &status, NULL) && g_spawn_check_wait_status(status, NULL)) {
			fprintf(stderr, "imsroha-bearer: deleted %s, which held mux id %d on %s\n", p, mux_id, parent);
			n++;
		}
	}
	g_free(out);
	return n;
}
