// SPDX-License-Identifier: GPL-3.0-only
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

#ifndef IMSROHA_VERSION
#define IMSROHA_VERSION "0"
#endif

static const char *conf_path(void)
{
	const char *p = getenv("IMSROHA_CONF");
	return p && *p ? p : IMSROHA_CONF_PATH;
}

static const char *carriers_path(void)
{
	const char *p = getenv("IMSROHA_CARRIERS");
	return p && *p ? p : IMSROHA_CARRIERS_PATH;
}

/* A missing file is not an error; a broken one is. */
static GKeyFile *load_keyfile(const char *path, int *err)
{
	GKeyFile *kf = g_key_file_new();
	GError *e = NULL;

	if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, &e)) {
		if (!g_error_matches(e, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			fprintf(stderr, "imsroha: %s: %s\n", path, e->message);
			*err = -EINVAL;
		}
		g_error_free(e);
		g_key_file_free(kf);
		return NULL;
	}
	return kf;
}

static void get_str(GKeyFile *kf, const char *group, const char *key, char *out, size_t size)
{
	if (!kf || !g_key_file_has_key(kf, group, key, NULL))
		return;
	char *v = g_key_file_get_string(kf, group, key, NULL);
	if (v) {
		g_strstrip(v);
		snprintf(out, size, "%s", v);
		g_free(v);
	}
}

static void get_int(GKeyFile *kf, const char *group, const char *key, int *out)
{
	GError *e = NULL;
	if (!kf || !g_key_file_has_key(kf, group, key, NULL))
		return;
	int v = g_key_file_get_integer(kf, group, key, &e);
	if (e) {
		fprintf(stderr, "imsroha: [%s] %s is not a number, ignored\n", group, key);
		g_error_free(e);
		return;
	}
	*out = v;
}

static void get_bool(GKeyFile *kf, const char *group, const char *key, int *out)
{
	GError *e = NULL;
	if (!kf || !g_key_file_has_key(kf, group, key, NULL))
		return;
	gboolean v = g_key_file_get_boolean(kf, group, key, &e);
	if (e) {
		fprintf(stderr, "imsroha: [%s] %s is not true/false, ignored\n", group, key);
		g_error_free(e);
		return;
	}
	*out = v ? 1 : 0;
}

static void get_u16(GKeyFile *kf, const char *group, const char *key, uint16_t *out)
{
	int v = -1;
	get_int(kf, group, key, &v);
	if (v > 0 && v < 65536)
		*out = (uint16_t)v;
}

static void get_uint(GKeyFile *kf, const char *group, const char *key, unsigned *out)
{
	int v = -1;
	get_int(kf, group, key, &v);
	if (v >= 0)
		*out = (unsigned)v;
}

/* "data-endpoint-type": the names libqmi uses, or a number. */
static void get_ep_type(GKeyFile *kf, const char *group, const char *key, int *out)
{
	char v[32] = "";
	get_str(kf, group, key, v, sizeof(v));
	if (!v[0])
		return;
	static const struct { const char *name; int type; } names[] = {
		{ "hsic", 1 }, { "hsusb", 2 }, { "pcie", 3 }, { "embedded", 4 }, { "bam-dmux", 5 },
	};
	for (size_t i = 0; i < G_N_ELEMENTS(names); i++)
		if (!g_ascii_strcasecmp(v, names[i].name)) {
			*out = names[i].type;
			return;
		}
	char *end;
	long n = strtol(v, &end, 0);
	if (*end || n < 0)
		fprintf(stderr, "imsroha: [%s] %s=%s is not an endpoint type, ignored\n", group, key, v);
	else
		*out = (int)n;
}

static void device_defaults(struct imsroha_device *dev)
{
	memset(dev, 0, sizeof(*dev));
	dev->qrtr_node = 0;
	dev->ep_type = -1;
	dev->ep_iface = -1;
	dev->mux_id = 3;
	snprintf(dev->ims_netdev, sizeof(dev->ims_netdev), "imsroha0");
	snprintf(dev->apn, sizeof(dev->apn), "ims");
	dev->route_table = 1042;
	dev->route_priority = 1042;
	snprintf(dev->model, sizeof(dev->model), "imsroha");
	snprintf(dev->operator_, sizeof(dev->operator_), "OMD");
	snprintf(dev->build, sizeof(dev->build), "IMSroha-%s", IMSROHA_VERSION);
	snprintf(dev->device_type, sizeof(dev->device_type), "Linux_Phone");
}

static void device_from(GKeyFile *kf, struct imsroha_device *dev)
{
	const char *g = "device";
	get_int(kf, g, "qrtr-node", &dev->qrtr_node);
	get_str(kf, g, "qmi-device", dev->qmi_path, sizeof(dev->qmi_path));
	get_str(kf, g, "data-netdev", dev->data_netdev, sizeof(dev->data_netdev));
	get_ep_type(kf, g, "data-endpoint-type", &dev->ep_type);
	get_int(kf, g, "data-endpoint-iface", &dev->ep_iface);
	get_int(kf, g, "mux-id", &dev->mux_id);
	get_str(kf, g, "ims-netdev", dev->ims_netdev, sizeof(dev->ims_netdev));
	get_int(kf, g, "profile", &dev->profile);
	get_str(kf, g, "apn", dev->apn, sizeof(dev->apn));
	get_int(kf, g, "route-table", &dev->route_table);
	get_int(kf, g, "route-priority", &dev->route_priority);
	get_str(kf, g, "model", dev->model, sizeof(dev->model));
	get_str(kf, g, "operator", dev->operator_, sizeof(dev->operator_));
	get_str(kf, g, "build", dev->build, sizeof(dev->build));
	get_str(kf, g, "device-type", dev->device_type, sizeof(dev->device_type));
}

int imsroha_config_load_device(struct imsroha_device *dev)
{
	int err = 0;
	device_defaults(dev);
	GKeyFile *kf = load_keyfile(conf_path(), &err);
	if (kf) {
		device_from(kf, dev);
		g_key_file_free(kf);
	}
	return err;
}

/* Plain 3GPP: P-CSCF from PCO only, IPsec, SMS over IP, no carrier quirks. */
static void carrier_defaults(struct imsroha_carrier *car)
{
	memset(car, 0, sizeof(*car));
	car->pcscf_port = 5060;
	car->sip_port = 5060;
	snprintf(car->user_agent, sizeof(car->user_agent), "[PRODUCT_MODEL]/[BUILD_VERSION]");
	car->sms_over_ip = 1;
	car->ipsec = 1;
	snprintf(car->ealg, sizeof(car->ealg), "aes-cbc,null");
	snprintf(car->alg, sizeof(car->alg), "hmac-sha-1-96");
	car->pt_amrwb = 106;
	car->pt_amr = 104;
	car->pt_dtmf_wb = 107;
	car->pt_dtmf = 101;
	car->session_expires = 1800;
	car->rtp_port = 40000;
	car->reg_event = 1;
	car->sip_instance = 1;
}

static void carrier_from(GKeyFile *kf, const char *g, struct imsroha_carrier *car)
{
	get_str(kf, g, "domain", car->domain, sizeof(car->domain));
	get_str(kf, g, "pcscf", car->pcscf, sizeof(car->pcscf));
	get_u16(kf, g, "pcscf-port", &car->pcscf_port);
	get_u16(kf, g, "sip-port", &car->sip_port);
	get_str(kf, g, "user-agent", car->user_agent, sizeof(car->user_agent));
	get_str(kf, g, "uicc-version", car->uicc_version, sizeof(car->uicc_version));
	get_str(kf, g, "operator-code", car->operator_code, sizeof(car->operator_code));
	get_bool(kf, g, "sms-over-ip", &car->sms_over_ip);
	char rp[16] = "";
	get_str(kf, g, "sms-rp-ack", rp, sizeof(rp));
	if (!strcmp(rp, "response"))
		car->sms_rp_in_response = 1;
	else if (!strcmp(rp, "message"))
		car->sms_rp_in_response = 0;
	else if (rp[0])
		fprintf(stderr, "imsroha: [%s] sms-rp-ack=%s is neither response nor message, ignored\n", g, rp);
	get_bool(kf, g, "ipsec", &car->ipsec);
	get_str(kf, g, "ipsec-ealg", car->ealg, sizeof(car->ealg));
	get_str(kf, g, "ipsec-alg", car->alg, sizeof(car->alg));
	get_int(kf, g, "pt-amr-wb", &car->pt_amrwb);
	get_int(kf, g, "pt-amr", &car->pt_amr);
	get_int(kf, g, "pt-dtmf-wb", &car->pt_dtmf_wb);
	get_int(kf, g, "pt-dtmf", &car->pt_dtmf);
	get_uint(kf, g, "session-expires", &car->session_expires);
	get_u16(kf, g, "rtp-port", &car->rtp_port);
	get_int(kf, g, "pt-amr-wb-be", &car->pt_amrwb_be);
	get_int(kf, g, "pt-amr-be", &car->pt_amr_be);
	get_bool(kf, g, "tta", &car->tta);
	get_str(kf, g, "country-code", car->country_code, sizeof(car->country_code));
	get_str(kf, g, "smsc", car->smsc, sizeof(car->smsc));
	get_str(kf, g, "sms-psi", car->sms_psi, sizeof(car->sms_psi));
	get_bool(kf, g, "reg-event", &car->reg_event);
	get_bool(kf, g, "sip-instance", &car->sip_instance);
}

/* The carriers.conf group whose plmn= list holds mcc+mnc, or NULL. */
static char *find_carrier(GKeyFile *kf, const char *mcc, const char *mnc)
{
	char plmn[8];
	gsize n = 0;

	if (!kf || !mcc || !mnc)
		return NULL;
	snprintf(plmn, sizeof(plmn), "%s%s", mcc, mnc);
	char **groups = g_key_file_get_groups(kf, &n);
	char *hit = NULL;
	for (gsize i = 0; i < n && !hit; i++) {
		gsize m = 0;
		char **list = g_key_file_get_string_list(kf, groups[i], "plmn", &m, NULL);
		for (gsize j = 0; list && j < m; j++)
			if (!strcmp(g_strstrip(list[j]), plmn)) {
				hit = g_strdup(groups[i]);
				break;
			}
		g_strfreev(list);
	}
	g_strfreev(groups);
	return hit;
}

int imsroha_config_load(struct imsroha_config *cfg, const char *mcc, const char *mnc)
{
	int err = imsroha_config_load_device(&cfg->dev);

	carrier_defaults(&cfg->car);
	GKeyFile *carriers = load_keyfile(carriers_path(), &err);
	char *group = find_carrier(carriers, mcc, mnc);
	if (group) {
		carrier_from(carriers, group, &cfg->car);
		snprintf(cfg->car.name, sizeof(cfg->car.name), "%s", group);
		g_free(group);
	}
	if (carriers)
		g_key_file_free(carriers);

	GKeyFile *local = load_keyfile(conf_path(), &err);
	if (local) {
		carrier_from(local, "carrier", &cfg->car);
		g_key_file_free(local);
	}
	return err;
}

static void replace_all(char *buf, size_t size, const char *from, const char *to)
{
	char tmp[512];
	char *p;
	size_t flen = strlen(from);

	while ((p = strstr(buf, from))) {
		snprintf(tmp, sizeof(tmp), "%.*s%s%s", (int)(p - buf), buf, to, p + flen);
		snprintf(buf, size, "%s", tmp);
	}
}

void imsroha_config_user_agent(const struct imsroha_config *cfg, char *out, size_t size)
{
	snprintf(out, size, "%s", cfg->car.user_agent);
	replace_all(out, size, "[UICC_VERSION]", cfg->car.uicc_version);
	replace_all(out, size, "[PRODUCT_MODEL]", cfg->dev.model);
	replace_all(out, size, "[BUILD_VERSION]", cfg->dev.build);
	replace_all(out, size, "[DEVICE_TYPE]", cfg->dev.device_type);
	replace_all(out, size, "[OMCCODE]", cfg->car.operator_code);
	replace_all(out, size, "[OPERATOR]", cfg->dev.operator_);
}

void imsroha_derived_domain(const char *mcc, const char *mnc, char *out, size_t size)
{
	/* TS 23.003 13.2: the MNC always has three digits here. */
	snprintf(out, size, "ims.mnc%s%s.mcc%s.3gppnetwork.org",
		 strlen(mnc) == 2 ? "0" : "", mnc, mcc);
}

const char *imsroha_runtime_dir(void)
{
	static char dir[256];
	const char *e = getenv("RUNTIME_DIRECTORY");

	if (!e || !*e)
		return "/run/imsroha";
	snprintf(dir, sizeof(dir), "%s", e);
	char *colon = strchr(dir, ':');
	if (colon)
		*colon = '\0';
	return dir;
}

int imsroha_pdn_write(const char *dir, const struct imsroha_pdn *pdn)
{
	char path[512], tmp[512];
	snprintf(path, sizeof(path), "%s/" IMSROHA_PDN_FILE, dir);
	snprintf(tmp, sizeof(tmp), "%s/." IMSROHA_PDN_FILE ".tmp", dir);

	FILE *f = fopen(tmp, "we");
	if (!f)
		return -errno;
	fprintf(f, "IFACE=%s\nADDR=%s\nPCSCF=%s\nPCSCF_FQDN=%s\nDNS=%s\nMTU=%u\n",
		pdn->iface, pdn->addr, pdn->pcscf, pdn->pcscf_fqdn, pdn->dns, pdn->mtu);
	if (fflush(f) || fsync(fileno(f))) {
		int r = -errno;
		fclose(f);
		unlink(tmp);
		return r;
	}
	fclose(f);
	return rename(tmp, path) < 0 ? -errno : 0;
}

int imsroha_pdn_read(const char *dir, struct imsroha_pdn *pdn)
{
	char path[512], line[1024];
	snprintf(path, sizeof(path), "%s/" IMSROHA_PDN_FILE, dir);
	memset(pdn, 0, sizeof(*pdn));

	FILE *f = fopen(path, "re");
	if (!f)
		return -errno;
	while (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\n")] = '\0';
		char *eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq++ = '\0';
		if (!strcmp(line, "IFACE"))
			snprintf(pdn->iface, sizeof(pdn->iface), "%s", eq);
		else if (!strcmp(line, "ADDR"))
			snprintf(pdn->addr, sizeof(pdn->addr), "%s", eq);
		else if (!strcmp(line, "PCSCF"))
			snprintf(pdn->pcscf, sizeof(pdn->pcscf), "%s", eq);
		else if (!strcmp(line, "PCSCF_FQDN"))
			snprintf(pdn->pcscf_fqdn, sizeof(pdn->pcscf_fqdn), "%s", eq);
		else if (!strcmp(line, "DNS"))
			snprintf(pdn->dns, sizeof(pdn->dns), "%s", eq);
		else if (!strcmp(line, "MTU"))
			pdn->mtu = (unsigned)strtoul(eq, NULL, 10);
	}
	fclose(f);
	return pdn->iface[0] && pdn->addr[0] ? 0 : -ENODATA;
}
