// SPDX-License-Identifier: GPL-3.0-only
/*
 * Sets the context up through imsd_sip_setup() exactly as imsroha does at
 * start, from data/carriers.conf and tests/imsroha-flip3.conf, for an LG U+
 * SIM with an ISIM and the recorded PDN, but with the P-CSCF on loopback.
 */
#define GOLDEN_DOMAIN "lte-lguplus.co.kr"

static void golden_setup(struct imsd_sip_ctx *ctx, sd_event *event, int ue_fd,
			 const struct sockaddr_in6 *pcscf)
{
	struct imsroha_config cfg;
	struct imsd_isim_identity id = { .has_isim = 1 };
	struct imsroha_pdn pdn = { .mtu = 1428 };
	char pcscf_str[64];

	memset(ctx, 0, sizeof(*ctx));
	ctx->event = event;
	ctx->fd = ue_fd;
	ctx->rtp_fd = -1;
	ctx->reg_state = IMSD_DOWN;
	ctx->call_state = IMSD_CALL_IDLE;

	setenv("IMSROHA_CARRIERS", GOLDEN_SRCDIR "/data/carriers.conf", 1);
	setenv("IMSROHA_CONF", GOLDEN_SRCDIR "/tests/imsroha-flip3.conf", 1);
	if (imsroha_config_load(&cfg, "450", "06") < 0 || strcmp(cfg.car.name, "LG U+")) {
		fprintf(stderr, "golden: the LG U+ profile did not load\n");
		exit(1);
	}

	snprintf(id.impi, sizeof(id.impi), "450061234567890@" GOLDEN_DOMAIN);
	snprintf(id.impu, sizeof(id.impu), "sip:01000000000@" GOLDEN_DOMAIN);
	snprintf(id.domain, sizeof(id.domain), GOLDEN_DOMAIN);
	snprintf(id.mcc, sizeof(id.mcc), "450");
	snprintf(id.mnc, sizeof(id.mnc), "06");
	snprintf(pdn.iface, sizeof(pdn.iface), "lo");
	snprintf(pdn.addr, sizeof(pdn.addr), "::1");
	inet_ntop(AF_INET6, &pcscf->sin6_addr, pcscf_str, sizeof(pcscf_str));
	/* The PCO's P-CSCF: the fake one. The carrier's fallback comes after it. */
	snprintf(pdn.pcscf, sizeof(pdn.pcscf), "%s", pcscf_str);
	cfg.car.pcscf_port = ntohs(pcscf->sin6_port);

	if (imsd_sip_setup(ctx, &id, &cfg, &pdn) < 0) {
		fprintf(stderr, "golden: setup failed\n");
		exit(1);
	}
}
