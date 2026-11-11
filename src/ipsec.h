// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * sec-agree with IPsec ESP on the Gm interface (TS 33.203 7, TS 24.229
 * 5.1.1.2, RFC 3329). The UE offers its SPIs and protected ports in
 * Security-Client, the P-CSCF answers its own in the 401's Security-Server,
 * and four transport-mode SAs carry everything after that:
 *
 *   UE port_uc -> P-CSCF port_ps   SPI spi_ps   requests from the UE
 *   P-CSCF port_ps -> UE port_uc   SPI spi_uc   responses to them
 *   P-CSCF port_pc -> UE port_us   SPI spi_us   requests from the network
 *   UE port_us -> P-CSCF port_pc   SPI spi_pc   responses to them
 *
 * The kernel does the ESP; this file builds and parses the headers and
 * installs the SAs and policies with ip xfrm.
 */

struct imsroha_ipsec {
	/* ours */
	uint32_t spi_uc, spi_us;
	uint16_t port_uc, port_us;
	char offer_alg[64];      /* comma separated, in preference order */
	char offer_ealg[64];
	/* the P-CSCF's, from Security-Server */
	uint32_t spi_pc, spi_ps;
	uint16_t port_pc, port_ps;
	char alg[24], ealg[24];
	char server_line[512];   /* the chosen Security-Server value, for Security-Verify */
	/* what is installed */
	int installed;
	char ue[64], pcscf[64];
};

/* New client SPIs (one per registration attempt that may be challenged). */
void imsroha_ipsec_new_spis(struct imsroha_ipsec *s);

/* The Security-Client value: one ipsec-3gpp entry per alg x ealg offered. */
int imsroha_ipsec_client_header(const struct imsroha_ipsec *s, char *out, size_t size);

/*
 * Picks the P-CSCF's most preferred mechanism (highest q) that matches our
 * offer, from the Security-Server header value(s). 0 on success, -ENOENT when
 * none matches or the header is missing.
 */
int imsroha_ipsec_parse_server(struct imsroha_ipsec *s, const char *value);

/*
 * Installs the four SAs and their policies for UE address ue and P-CSCF pcscf
 * (IPv6, as text), with IK and CK from AKA. Removes a set installed before.
 */
int imsroha_ipsec_install(struct imsroha_ipsec *s, const char *ue, const char *pcscf,
			  const unsigned char ik[16], const unsigned char ck[16]);
void imsroha_ipsec_remove(struct imsroha_ipsec *s);
