// SPDX-License-Identifier: GPL-3.0-only
#include "rcs_config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

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

static GKeyFile *load(const char *path, int *err)
{
	GKeyFile *kf = g_key_file_new();
	GError *e = NULL;

	if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, &e)) {
		if (!g_error_matches(e, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			fprintf(stderr, "imsroha-rcs: %s: %s\n", path, e->message);
			*err = -EINVAL;
		}
		g_error_free(e);
		g_key_file_free(kf);
		return NULL;
	}
	return kf;
}

static void str(GKeyFile *kf, const char *g, const char *k, char *out, size_t size)
{
	if (!kf || !g_key_file_has_key(kf, g, k, NULL))
		return;
	char *v = g_key_file_get_string(kf, g, k, NULL);
	if (v) {
		g_strstrip(v);
		snprintf(out, size, "%s", v);
		g_free(v);
	}
}

static void boolean(GKeyFile *kf, const char *g, const char *k, int *out)
{
	GError *e = NULL;
	if (!kf || !g_key_file_has_key(kf, g, k, NULL))
		return;
	gboolean v = g_key_file_get_boolean(kf, g, k, &e);
	if (e) {
		fprintf(stderr, "imsroha-rcs: [%s] %s is not true/false, ignored\n", g, k);
		g_error_free(e);
		return;
	}
	*out = v ? 1 : 0;
}

static void integer(GKeyFile *kf, const char *g, const char *k, long min, long max, long *out)
{
	GError *e = NULL;
	if (!kf || !g_key_file_has_key(kf, g, k, NULL))
		return;
	int v = g_key_file_get_integer(kf, g, k, &e);
	if (e || v < min || v > max) {
		fprintf(stderr, "imsroha-rcs: [%s] %s is not a number in %ld..%ld, ignored\n", g, k, min, max);
		if (e)
			g_error_free(e);
		return;
	}
	*out = v;
}

static void defaults(struct rcs_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	snprintf(cfg->client_vendor, sizeof(cfg->client_vendor), "IMSR");
	/* R9 6.3.1.1.1: Platform-Major.Minor, from imsroha's own version */
	unsigned major = 0, minor = 0;
	sscanf(IMSROHA_VERSION, "%u.%u", &major, &minor);
	snprintf(cfg->client_version, sizeof(cfg->client_version), "RCSLinux-%u.%u", major, minor);
	cfg->default_sms_app = 1;
	cfg->assume_mobile = 1;
	cfg->otp_timeout = 300;
	snprintf(cfg->state_dir, sizeof(cfg->state_dir), "%s", RCS_STATE_DIR);
	snprintf(cfg->profile, sizeof(cfg->profile), "UP_2.4");
	snprintf(cfg->provisioning_version, sizeof(cfg->provisioning_version), "5.0");
	snprintf(cfg->app, sizeof(cfg->app), "ap2001,ap2002,urn:oma:mo:ext-3gpp-ims:1.0");
	snprintf(cfg->user_agent, sizeof(cfg->user_agent),
		 "IM-client/OMA1.0 [PRODUCT_MODEL]/[BUILD_VERSION] %s", cfg->client_version);
	cfg->sip_port = 5061;
	cfg->iscomposing_cpim = 1;
	cfg->standalone = 1;
	cfg->reg_expires = 3600;
}

/* The local switch: never anything from carriers.conf. */
static void rcs_local(GKeyFile *kf, struct rcs_config *cfg)
{
	const char *g = "rcs";
	long v;

	boolean(kf, g, "enable", &cfg->enable);
	str(kf, g, "interface", cfg->interface, sizeof(cfg->interface));
	str(kf, g, "interface-ipv4", cfg->interface4, sizeof(cfg->interface4));
	str(kf, g, "msisdn", cfg->msisdn, sizeof(cfg->msisdn));
	str(kf, g, "ca-file", cfg->ca_file, sizeof(cfg->ca_file));
	str(kf, g, "client-vendor", cfg->client_vendor, sizeof(cfg->client_vendor));
	str(kf, g, "client-version", cfg->client_version, sizeof(cfg->client_version));
	v = cfg->default_sms_app;
	integer(kf, g, "default-sms-app", 0, 2, &v);
	cfg->default_sms_app = (int)v;
	boolean(kf, g, "assume-mobile", &cfg->assume_mobile);
	v = cfg->otp_timeout;
	integer(kf, g, "otp-timeout", 10, 3600, &v);
	cfg->otp_timeout = (unsigned)v;
	str(kf, g, "state-dir", cfg->state_dir, sizeof(cfg->state_dir));
}

static void rcs_carrier(GKeyFile *kf, const char *g, struct rcs_config *cfg)
{
	long v;
	char type[16] = "";

	str(kf, g, "rcs-acs-url", cfg->acs_url, sizeof(cfg->acs_url));
	str(kf, g, "rcs-acs-https-url", cfg->acs_https_url, sizeof(cfg->acs_https_url));
	v = cfg->otp_port;
	integer(kf, g, "rcs-otp-port", 0, 65535, &v);
	cfg->otp_port = (uint16_t)v;
	str(kf, g, "rcs-otp-type", type, sizeof(type));
	if (!strcmp(type, "text"))
		cfg->otp_text = 1;
	else if (!strcmp(type, "binary"))
		cfg->otp_text = 0;
	else if (type[0])
		fprintf(stderr, "imsroha-rcs: [%s] rcs-otp-type=%s is neither binary nor text, ignored\n", g, type);
	str(kf, g, "rcs-otp-regex", cfg->otp_regex, sizeof(cfg->otp_regex));
	str(kf, g, "rcs-profile", cfg->profile, sizeof(cfg->profile));
	str(kf, g, "rcs-provisioning-version", cfg->provisioning_version, sizeof(cfg->provisioning_version));
	str(kf, g, "rcs-version", cfg->rcs_version, sizeof(cfg->rcs_version));
	str(kf, g, "rcs-app", cfg->app, sizeof(cfg->app));
	str(kf, g, "rcs-user-agent", cfg->user_agent, sizeof(cfg->user_agent));
	str(kf, g, "rcs-http-user-agent", cfg->http_user_agent, sizeof(cfg->http_user_agent));
	str(kf, g, "rcs-accept-language", cfg->accept_language, sizeof(cfg->accept_language));
	v = cfg->sip_port;
	integer(kf, g, "rcs-sip-port", 1, 65535, &v);
	cfg->sip_port = (uint16_t)v;
	boolean(kf, g, "rcs-iscomposing-cpim", &cfg->iscomposing_cpim);
	boolean(kf, g, "rcs-standalone", &cfg->standalone);
	v = cfg->reg_expires;
	integer(kf, g, "rcs-reg-expires", 60, 3600 * 24 * 30, &v);
	cfg->reg_expires = (unsigned)v;
}

int rcs_config_load_switch(struct rcs_config *cfg)
{
	int err = 0;
	defaults(cfg);
	GKeyFile *local = load(conf_path(), &err);
	if (local) {
		rcs_local(local, cfg);
		g_key_file_free(local);
	}
	const char *sd = getenv("IMSROHA_RCS_STATE");
	if (sd && *sd)
		snprintf(cfg->state_dir, sizeof(cfg->state_dir), "%s", sd);
	return err;
}

int rcs_config_load(struct rcs_config *cfg, const char *mcc, const char *mnc)
{
	int err = rcs_config_load_switch(cfg);
	int e2 = imsroha_config_load(&cfg->base, mcc, mnc);
	if (e2 && !err)
		err = e2;

	GKeyFile *carriers = load(carriers_path(), &err);
	if (carriers && cfg->base.car.name[0])
		rcs_carrier(carriers, cfg->base.car.name, cfg);
	if (carriers)
		g_key_file_free(carriers);

	GKeyFile *local = load(conf_path(), &err);
	if (local) {
		rcs_carrier(local, "carrier", cfg);
		str(local, "device", "vendor", cfg->terminal_vendor, sizeof(cfg->terminal_vendor));
		g_key_file_free(local);
	}
	if (!cfg->http_user_agent[0])
		snprintf(cfg->http_user_agent, sizeof(cfg->http_user_agent), "%s", cfg->user_agent);

	/* RCS rides the internet PDN or Wi-Fi, never the IMS PDN (R9 A.3.1). */
	const char *ims = cfg->base.dev.ims_netdev;
	if (ims[0] && (!strcmp(cfg->interface, ims) || !strcmp(cfg->interface4, ims))) {
		fprintf(stderr, "imsroha-rcs: [rcs] interface=%s is the IMS PDN's netdev; RCS uses the internet PDN\n", ims);
		return -EINVAL;
	}
	return err;
}

static void replace_all(char *buf, size_t size, const char *from, const char *to)
{
	char tmp[512];
	char *p, *start = buf;
	size_t flen = strlen(from), tlen = strlen(to);

	while ((p = strstr(start, from))) {
		size_t off = (size_t)(p - buf);
		snprintf(tmp, sizeof(tmp), "%.*s%s%s", (int)off, buf, to, p + flen);
		snprintf(buf, size, "%s", tmp);
		if (off + tlen >= strlen(buf))
			break;
		start = buf + off + tlen;
	}
}

void rcs_config_expand_ua(const struct rcs_config *cfg, const char *tmpl, char *out, size_t size)
{
	snprintf(out, size, "%s", tmpl);
	replace_all(out, size, "[PRODUCT_MODEL]", cfg->base.dev.model);
	replace_all(out, size, "[BUILD_VERSION]", cfg->base.dev.build);
	replace_all(out, size, "[OPERATOR]", cfg->base.dev.operator_);
}
