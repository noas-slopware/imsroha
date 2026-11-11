// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <net/if.h>
#include <stdint.h>

/*
 * Configuration. Three layers, later ones win:
 *
 *   1. built-in defaults (3GPP behaviour, nothing carrier-specific),
 *   2. the carrier profile from carriers.conf whose plmn= list holds the
 *      SIM's MCC+MNC,
 *   3. /etc/imsroha/imsroha.conf: [device] for the hardware, [carrier] for
 *      overriding any carrier key on this machine.
 *
 * IMSROHA_CONF and IMSROHA_CARRIERS in the environment replace the two paths
 * (tests use them).
 */

#define IMSROHA_CONF_PATH "/etc/imsroha/imsroha.conf"
#define IMSROHA_CARRIERS_PATH "/usr/share/imsroha/carriers.conf"
#define IMSROHA_PDN_FILE "pdn" /* in the runtime directory, written by imsroha-bearer */

struct imsroha_device {
	/* How to reach the modem's QMI services: a QRTR node (SoC modems), or a
	 * QMI character device (USB and PCIe modems, /dev/cdc-wdmN, /dev/wwan0qmi0). */
	int qrtr_node;              /* default 0; ignored when qmi_path is set */
	char qmi_path[128];

	/* The IMS PDN's data path. */
	char data_netdev[IFNAMSIZ]; /* the rmnet parent: rmnet_ipa0, rmnet_mhi0, wwan0; "" = find it */
	int ep_type;                /* QmiDataEndpointType, -1 = derive from the parent */
	int ep_iface;               /* endpoint interface number, -1 = derive */
	int mux_id;                 /* QMAP mux id of the IMS PDN */
	char ims_netdev[IFNAMSIZ];  /* the rmnet link imsroha-bearer creates */
	int profile;                /* 3GPP profile index, 0 = the one whose APN is apn */
	char apn[64];
	int route_table;            /* policy routing table for traffic from the IMS address */
	int route_priority;         /* priority of the "from <IMS address>" rule */

	/* User-Agent placeholders that describe this device. */
	char model[64];             /* [PRODUCT_MODEL] */
	char build[64];             /* [BUILD_VERSION] */
};

struct imsroha_carrier {
	char name[32];              /* the carriers.conf group, "" when none matched */
	char domain[128];           /* home domain when the SIM has no ISIM; "" = derive from the PLMN */
	char pcscf[512];            /* fallback P-CSCFs after PCO: space separated, addr | [addr]:port | fqdn[:port] */
	uint16_t pcscf_port;        /* default P-CSCF port */
	uint16_t sip_port;          /* our own SIP port */
	char user_agent[256];       /* template: [UICC_VERSION] [PRODUCT_MODEL] [BUILD_VERSION] [OMCCODE] */
	char uicc_version[16];
	char operator_code[16];
	int sms_over_ip;            /* carry SMS (Contact +g.3gpp.smsip, MESSAGE) */
	int sms_rp_in_response;     /* MT-SMS RP-ACK in the 200 OK body, not as its own MESSAGE */
	int ipsec;                  /* sec-agree with IPsec ESP (TS 33.203) */
	char ealg[32];              /* offered ESP encryption: null, aes-cbc, or "null,aes-cbc" */
	char alg[48];               /* offered integrity: hmac-sha-1-96, hmac-md5-96 */
	int pt_amrwb, pt_amr, pt_dtmf_wb, pt_dtmf; /* payload types we offer */
	uint16_t rtp_port;
	unsigned session_expires;
	/* Home country code: +<cc> numbers are dialled and texted in national form (0...). */
	char country_code[8];
	char smsc[24];              /* +E.164 SMSC that wins over the SIM's EF_SMSP, "" = the SIM's */
	char sms_psi[128];          /* MO-SMS Request-URI (TS 24.341 5.3.1.2), "" = the destination */
	int reg_event;              /* SUBSCRIBE to the reg event package (TS 24.229 5.1.1.3) */
	int sip_instance;           /* +sip.instance with the IMEI URN in Contact (TS 24.229 5.1.1.2) */
};

struct imsroha_config {
	struct imsroha_device dev;
	struct imsroha_carrier car;
};

/* Device section only: what imsroha-bearer and the VSS helper need. */
int imsroha_config_load_device(struct imsroha_device *dev);

/*
 * Everything, with the carrier picked by MCC/MNC (mnc as on the SIM, 2 or 3
 * digits). mcc/mnc may be NULL when the PLMN is unknown: then only the
 * defaults and the local [carrier] overrides apply.
 */
int imsroha_config_load(struct imsroha_config *cfg, const char *mcc, const char *mnc);

/* Expands the carrier's User-Agent template for this device. */
void imsroha_config_user_agent(const struct imsroha_config *cfg, char *out, size_t size);

/* The 3GPP home domain derived from a PLMN (TS 23.003 13.2). */
void imsroha_derived_domain(const char *mcc, const char *mnc, char *out, size_t size);

/* The PDN hand-off from imsroha-bearer to imsroha (key=value lines). */
struct imsroha_pdn {
	char iface[IFNAMSIZ];
	char addr[64];
	char pcscf[512];            /* space separated IPv6 addresses from PCO */
	char pcscf_fqdn[512];       /* space separated FQDNs from PCO */
	char dns[256];              /* space separated */
	unsigned mtu;
};

int imsroha_pdn_write(const char *dir, const struct imsroha_pdn *pdn);
int imsroha_pdn_read(const char *dir, struct imsroha_pdn *pdn);
/* The runtime directory: $RUNTIME_DIRECTORY's first entry, else /run/imsroha. */
const char *imsroha_runtime_dir(void);
