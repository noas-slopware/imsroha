// SPDX-License-Identifier: GPL-3.0-only
/* A retransmitted MT-SMS is the same message whatever TP-MMS and TP-LP say. */
#include <stdio.h>
#include "inbox.h"

static int fails;
static void expect(const char *what, int ok)
{
	printf("%s %s\n", ok ? "ok  " : "FAIL", what);
	fails += !ok;
}

int main(void)
{
	/* 00 | 40 DELIVER+UDHI+MMS=0 (more to send) | ... */
	const char *a = "0040048121430008521111310000000400310032";
	/* the same message, TP-MMS=1 (no more) and TP-LP set */
	const char *b = "004C048121430008521111310000000400310032";
	/* another message: other text */
	const char *c = "0044048121430008521111310000000400310033";

	expect("unseen at first", !imsd_inbox_seen(a));
	imsd_inbox_remember(a);
	expect("same TPDU is seen", imsd_inbox_seen(a));
	expect("TP-MMS/TP-LP changed: still the same message", imsd_inbox_seen(b));
	expect("other text is a new message", !imsd_inbox_seen(c));
	return fails ? 1 : 0;
}
