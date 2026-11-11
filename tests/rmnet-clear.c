// SPDX-License-Identifier: GPL-3.0-only
/* Run inside a namespace by tests/rmnet-clear.sh: clears mux 3 on d0, keeps mux 4. */
#include <stdio.h>
#include "../src/rmnet_links.h"

int main(void)
{
	int n = imsroha_rmnet_clear_mux("d0", 3);
	printf("deleted %d\n", n);
	return n == 1 ? 0 : 1;
}
