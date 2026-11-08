#pragma once

#include <stddef.h>

/*
 * Durable inbox for mobile-terminated SMS PDUs.
 *
 * An entry is written and fsynced before the RP-ACK goes to the network, and
 * removed only when ModemManager has taken the part (AckPdu). Anything still
 * here after a crash, a ModemManager restart or a reboot is handed over again
 * through GetPendingPdus.
 */

#define IMSD_INBOX_ID_LEN 24 /* 16 hex digits of CLOCK_REALTIME ns + "-" + 6, NUL */

int imsd_inbox_init(void);
int imsd_inbox_store(const char *pdu_hex, char id[IMSD_INBOX_ID_LEN]);
int imsd_inbox_remove(const char *id);

/*
 * Duplicate suppression. A network retry of an MT-SMS (a SIP retransmission
 * queued while the phone slept, or the SMSC trying again after a late ack)
 * carries the identical SMS-DELIVER TPDU, SMSC timestamp included, while two
 * different messages never do. imsd_inbox_seen() says whether a TPDU was
 * already accepted; imsd_inbox_remember() records one after it was stored.
 * The last few hundred survive a restart (STATE_DIRECTORY/seen).
 */
int imsd_inbox_seen(const char *pdu_hex);
void imsd_inbox_remember(const char *pdu_hex);

/* Calls cb for every pending entry, oldest first. Stops on a negative return. */
int imsd_inbox_for_each(int (*cb)(const char *id, const char *pdu_hex, void *userdata),
			void *userdata);
