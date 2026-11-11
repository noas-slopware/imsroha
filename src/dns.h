// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <netinet/in.h>
#include <stddef.h>

/*
 * AAAA lookup over the IMS PDN: the query goes to the PDN's own DNS servers,
 * from the IMS address, on the IMS link (the system resolver knows neither).
 * Used once at start for P-CSCF names; each server gets one try of
 * timeout_ms. Returns the number of addresses written, or a negative errno.
 */
int imsroha_dns_aaaa(const char *name, const char *servers, const char *src_addr,
		     const char *iface, struct in6_addr *out, size_t max, int timeout_ms);
