// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <gio/gio.h>

/*
 * The client certificate of MSRP over TLS. Carriers that run MSRPoTLS (LG U+
 * does) want the client to present one and to name its hash in the SDP
 * (a=fingerprint, RFC 4572/8122), as Samsung's stack does: a self-signed RSA
 * certificate for the user's address, made once and kept under the SIM's
 * state directory, made again when it is about to expire or the address
 * changes.
 *
 * rcs_cert_ensure() loads or makes it, from the main thread; 0 on success.
 * After that, rcs_cert_get() is a new reference to the certificate (with its
 * key), callable from any thread, and rcs_cert_fingerprint() the SDP value,
 * "SHA-1 AA:BB:...", valid on the main thread until the next
 * rcs_cert_ensure(). Both are NULL before the first success.
 */
int rcs_cert_ensure(const char *dir, const char *aor, GError **error);
GTlsCertificate *rcs_cert_get(void);
const char *rcs_cert_fingerprint(void);
