// SPDX-License-Identifier: GPL-3.0-only
/*
 * Sets the context up through imsd_sip_setup() exactly as imsroha does at
 * start, from data/carriers.conf and tests/imsroha-flip3.conf, with the
 * P-CSCF on loopback. GOLDEN_CARRIER picks the SIM:
 *
 *   LGU (default)  an LG U+ card with an ISIM, the recorded PDN
 *   KT             a KT card without an ISIM: identity from the IMSI,
 *                  sec-agree with IPsec, the RP-ACK in its own MESSAGE
 */
#define GOLDEN_DOMAIN "lte-lguplus.co.kr"

static void golden_setup(struct imsd_sip_ctx *ctx, sd_event *event, int ue_fd,
			 const struct sockaddr_in6 *pcscf)
{
	struct imsroha_config cfg;
	struct imsd_isim_identity id = { 0 };
	struct imsroha_pdn pdn = { .mtu = 1428 };
	char pcscf_str[64];
	const char *carrier = getenv("GOLDEN_CARRIER");
	int kt = carrier && !strcmp(carrier, "KT");

	memset(ctx, 0, sizeof(*ctx));
	ctx->event = event;
	ctx->fd = ue_fd;
	ctx->rtp_fd = -1;
	ctx->reg_state = IMSD_DOWN;
	ctx->call_state = IMSD_CALL_IDLE;

	setenv("IMSROHA_CARRIERS", GOLDEN_SRCDIR "/data/carriers.conf", 1);
	setenv("IMSROHA_CONF", GOLDEN_SRCDIR "/tests/imsroha-flip3.conf", 1);
	/*
	 * sec-agree installs SAs through "ip": the test logs the calls instead,
	 * unless GOLDEN_REAL_IP is set (tests/esp-loopback.sh, in a namespace).
	 */
	if (!getenv("GOLDEN_REAL_IP"))
		setenv("IMSROHA_IP", GOLDEN_SRCDIR "/tests/fake-ip.sh", 1);

	snprintf(id.mcc, sizeof(id.mcc), "450");
	snprintf(id.mnc, sizeof(id.mnc), kt ? "08" : "06");
	if (imsroha_config_load(&cfg, id.mcc, id.mnc) < 0 || strcmp(cfg.car.name, kt ? "KT" : "LG U+")) {
		fprintf(stderr, "golden: the carrier profile did not load\n");
		exit(1);
	}
	if (kt) {
		/* What imsd_isim_read_identity() derives from a USIM-only card. */
		id.has_isim = 0;
		snprintf(id.imsi, sizeof(id.imsi), "450081234567890");
		snprintf(id.impi, sizeof(id.impi), "450081234567890@ims.mnc008.mcc450.3gppnetwork.org");
		snprintf(id.impu, sizeof(id.impu), "sip:450081234567890@ims.mnc008.mcc450.3gppnetwork.org");
		snprintf(id.smsc, sizeof(id.smsc), "+821000000000");
	} else {
		id.has_isim = 1;
		snprintf(id.impi, sizeof(id.impi), "450061234567890@" GOLDEN_DOMAIN);
		snprintf(id.impu, sizeof(id.impu), "sip:01000000000@" GOLDEN_DOMAIN);
		snprintf(id.domain, sizeof(id.domain), GOLDEN_DOMAIN);
	}
	snprintf(pdn.iface, sizeof(pdn.iface), "lo");
	snprintf(pdn.addr, sizeof(pdn.addr), "::1");
	inet_ntop(AF_INET6, &pcscf->sin6_addr, pcscf_str, sizeof(pcscf_str));
	/* The PCO's P-CSCF: the fake one. The carrier's fallbacks come after it. */
	snprintf(pdn.pcscf, sizeof(pdn.pcscf), "%s", pcscf_str);
	cfg.car.pcscf_port = ntohs(pcscf->sin6_port);
	/* No DNS in the test: KT's fallback P-CSCF is a name. */
	if (kt)
		cfg.car.pcscf[0] = '\0';

	if (imsd_sip_setup(ctx, &id, &cfg, &pdn) < 0) {
		fprintf(stderr, "golden: setup failed\n");
		exit(1);
	}
}
