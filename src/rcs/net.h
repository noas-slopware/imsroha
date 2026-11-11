// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stdint.h>
#include <gio/gio.h>
#include "rcs_config.h"

/* tls: 0 = plain TCP, 1 = TLS, RCS_TLS_CLIENT_CERT = TLS presenting the MSRP
 * client certificate (cert.h) when there is one. */
#define RCS_TLS_CLIENT_CERT 2

/*
 * Every RCS connection: TCP to host:port, bound to [rcs] interface= (and
 * interface-ipv4= for IPv4) when set, then TLS when asked for, with the
 * server certificate checked against host. Blocking, with a timeout: call it
 * from a thread, or through rcs_net_connect_async().
 */
GIOStream *rcs_net_connect(const struct rcs_config *cfg, const char *host, uint16_t port,
			   int tls, unsigned timeout_s, GCancellable *cancel, GError **error);

void rcs_net_connect_async(const struct rcs_config *cfg, const char *host, uint16_t port,
			   int tls, unsigned timeout_s, GCancellable *cancel,
			   GAsyncReadyCallback cb, gpointer userdata);
GIOStream *rcs_net_connect_finish(GAsyncResult *res, GError **error);

/* The local address of a connection, as text, for Via/Contact/SDP. */
int rcs_net_local_address(GIOStream *s, char *addr, size_t size, uint16_t *port, int *v6);
/* Read/write timeout of the underlying socket, 0 = none. */
void rcs_net_set_timeout(GIOStream *s, unsigned timeout_s);
