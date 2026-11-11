// SPDX-License-Identifier: GPL-3.0-only
/*
 * imsroha-rcs: RCS (GSMA Universal Profile; Korea's Chatting+) next to
 * imsroha's VoLTE, on the internet PDN.
 *
 * Off unless /etc/imsroha/imsroha.conf has [rcs] enable=true. Off, it exits
 * before it opens anything; the one exception is the "disabled by the user"
 * request (rcs_state=-4) right after RCS was on and configured, which stock
 * sends too so the carrier delivers this number's messages as SMS again.
 *
 * GLib main loop only: the ACS run blocks in a worker thread, the rest is
 * event-driven (D-Bus signals, socket reads, one-shot timers).
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <glib-unix.h>
#include <gio/gio.h>

#include "acs.h"
#include "aka.h"
#include "imei.h"
#include "rcs_config.h"
#include "rcsd.h"
#include "smsport.h"

#define IMSD_BUS_NAME "codes.noa.IMSroha"
#define IMSD_BUS_PATH "/codes/noa/IMSroha"

static struct rcsd d;

static const char *const state_names[] = {
	[RCSD_CONFIGURING] = "configuring",
	[RCSD_WAITING_OTP] = "waiting-otp",
	[RCSD_REGISTERING] = "registering",
	[RCSD_REGISTERED] = "registered",
	[RCSD_UNREGISTERED] = "unregistered",
	[RCSD_DISABLED] = "disabled-by-network",
};

const char *rcsd_state_name(enum rcsd_state s)
{
	return state_names[s];
}

void rcsd_set_state(struct rcsd *r, enum rcsd_state s)
{
	if (r->state == s)
		return;
	r->state = s;
	fprintf(stderr, "imsroha-rcs: %s\n", state_names[s]);
	rcsd_dbus_state_changed(r);
}

/* ---- OTP and network-initiated requests from imsroha's MT-SMS path ----- */

static int otp_wait(void *ud, char *otp, size_t size, unsigned timeout_s)
{
	struct rcsd *r = ud;
	/* Anything that came before we asked is stale. */
	char *old;
	while ((old = g_async_queue_try_pop(r->otp_q)))
		g_free(old);
	g_atomic_int_set(&r->waiting_otp, 1);
	char *v = g_async_queue_timeout_pop(r->otp_q, (guint64)timeout_s * G_USEC_PER_SEC);
	g_atomic_int_set(&r->waiting_otp, 0);
	if (!v)
		return -ETIMEDOUT;
	snprintf(otp, size, "%s", v);
	g_free(v);
	return 0;
}

static void acs_start(struct rcsd *r, int disable);

static void otp_text_candidate(struct rcsd *r, const char *text)
{
	/* rcs-otp-type=text: an SMS matching rcs-otp-regex; the OTP is its first digit run. */
	if (!r->cfg.otp_regex[0] || !g_regex_match_simple(r->cfg.otp_regex, text, G_REGEX_CASELESS, 0))
		return;
	const char *p = text;
	while (*p && !g_ascii_isdigit(*p))
		p++;
	size_t n = strspn(p, "0123456789");
	if (n >= 4)
		g_async_queue_push(r->otp_q, g_strndup(p, n));
}

static void on_pdu(GDBusConnection *c, const char *sender, const char *path, const char *iface,
		   const char *signal, GVariant *params, gpointer ud)
{
	(void)c; (void)sender; (void)path; (void)iface; (void)signal;
	struct rcsd *r = ud;
	const char *id = NULL, *hex = NULL;
	g_variant_get(params, "(&s&s)", &id, &hex);
	struct sms_deliver sms;
	if (sms_parse_deliver_hex(hex, &sms) < 0)
		return;

	if (r->cfg.otp_text) {
		if (g_atomic_int_get(&r->waiting_otp))
			otp_text_candidate(r, sms.text);
		return;
	}
	if (sms.dest_port != r->cfg.otp_port || !r->cfg.otp_port)
		return;

	/* R9 6.3.1.1.2: "<IMSI>-rcscfg" asks for a run, "<IMPI>-rcscfg" for a full one. */
	char want[160];
	snprintf(want, sizeof(want), "%s-rcscfg", r->id.imsi);
	if (!strcmp(sms.text, want)) {
		fprintf(stderr, "imsroha-rcs: the ACS asks for a configuration run (%s)\n", id);
		rcsd_ua_stop(r);
		acs_start(r, 0);
		return;
	}
	const char *impi = r->xml ? acs_xml_get(r->xml, "Private_User_Identity") : NULL;
	if (impi) {
		snprintf(want, sizeof(want), "%s-rcscfg", impi);
		if (!strcmp(sms.text, want)) {
			fprintf(stderr, "imsroha-rcs: the ACS asks for a full reconfiguration (%s)\n", id);
			rcsd_ua_stop(r);
			r->st.rcscfg_force = 1;
			r->st.version = 0;
			r->st.validity = 0;
			acs_start(r, 0);
			return;
		}
	}
	if (g_atomic_int_get(&r->waiting_otp)) {
		fprintf(stderr, "imsroha-rcs: OTP SMS on port %d (%s)\n", sms.dest_port, id);
		g_async_queue_push(r->otp_q, g_strdup(sms.text));
	}
}

/* ---- autoconfiguration -------------------------------------------------- */

static gboolean on_acs_timer(gpointer ud)
{
	struct rcsd *r = ud;
	r->acs_timer = 0;
	acs_start(r, 0);
	return G_SOURCE_REMOVE;
}

static void arm_acs_timer(struct rcsd *r)
{
	if (r->acs_timer)
		g_source_remove(r->acs_timer);
	r->acs_timer = 0;
	if (!r->st.next_run)
		return;
	int64_t now = (int64_t)time(NULL);
	int64_t in = r->st.next_run > now ? r->st.next_run - now : 0;
	if (in > G_MAXUINT / 2)
		in = G_MAXUINT / 2;
	r->acs_timer = g_timeout_add_seconds((guint)in, on_acs_timer, r);
	fprintf(stderr, "imsroha-rcs: next configuration run in %lld s\n", (long long)in);
}

static int load_xml(struct rcsd *r)
{
	size_t len = 0;
	char *xml = acs_config_load(&r->cfg, r->id.imsi, &len);
	acs_xml_free(r->xml);
	r->xml = NULL;
	if (!xml)
		return -ENOENT;
	r->xml = acs_xml_parse(xml, len, NULL);
	g_free(xml);
	return r->xml ? 0 : -EBADMSG;
}

struct acs_job {
	struct rcsd *r;
	int disable;
	enum acs_outcome out;
};

static void acs_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)src;
	struct acs_job *j = data;
	j->out = acs_run(&j->r->cfg, &j->r->id, &j->r->st, j->disable, otp_wait, j->r, cancel);
	g_task_return_boolean(task, TRUE);
}

static void acs_done(GObject *src, GAsyncResult *res, gpointer ud)
{
	(void)src; (void)ud;
	struct acs_job *j = g_task_get_task_data(G_TASK(res));
	struct rcsd *r = j->r;
	r->acs_running = 0;

	if (j->disable) {
		g_main_loop_quit(r->loop);
		return;
	}
	switch (j->out) {
	case ACS_ACTIVE:
		if (load_xml(r) == 0) {
			rcsd_ua_start(r);
		} else {
			fprintf(stderr, "imsroha-rcs: the stored configuration is unreadable\n");
			rcsd_set_state(r, RCSD_UNREGISTERED);
		}
		break;
	case ACS_STOPPED:
		rcsd_ua_stop(r);
		acs_xml_free(r->xml);
		r->xml = NULL;
		rcsd_set_state(r, RCSD_DISABLED);
		break;
	case ACS_DORMANT:
		rcsd_ua_stop(r);
		rcsd_set_state(r, RCSD_UNREGISTERED);
		break;
	case ACS_NONE:
		/* Keep a configuration we still have (table 6-2: unreachable, 500). */
		if (r->st.version > 0 && load_xml(r) == 0)
			rcsd_ua_start(r);
		else
			rcsd_set_state(r, RCSD_UNREGISTERED);
		break;
	}
	arm_acs_timer(r);
}

static void acs_start(struct rcsd *r, int disable)
{
	if (r->acs_running)
		return;
	r->acs_running = 1;
	if (!disable)
		rcsd_set_state(r, RCSD_CONFIGURING);
	struct acs_job *j = g_new0(struct acs_job, 1);
	j->r = r;
	j->disable = disable;
	GTask *t = g_task_new(NULL, NULL, acs_done, NULL);
	g_task_set_task_data(t, j, g_free);
	g_task_run_in_thread(t, acs_thread);
	g_object_unref(t);
}

void rcsd_reconfigure(struct rcsd *r)
{
	acs_start(r, 0);
}

/* ---- identity ----------------------------------------------------------- */

static void msisdn_from_mm(struct rcsd *r)
{
	GError *e = NULL;
	GVariant *v = g_dbus_connection_call_sync(r->bus, "org.freedesktop.ModemManager1",
		"/org/freedesktop/ModemManager1", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects",
		NULL, G_VARIANT_TYPE("(a{oa{sa{sv}}})"), G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &e);
	if (!v) {
		g_error_free(e);
		return;
	}
	GVariantIter *objs;
	const char *path;
	GVariant *ifaces;
	g_variant_get(v, "(a{oa{sa{sv}}})", &objs);
	while (!r->id.msisdn[0] && g_variant_iter_next(objs, "{&o@a{sa{sv}}}", &path, &ifaces)) {
		GVariant *modem = g_variant_lookup_value(ifaces, "org.freedesktop.ModemManager1.Modem", NULL);
		if (modem) {
			GVariant *nums = g_variant_lookup_value(modem, "OwnNumbers", G_VARIANT_TYPE("as"));
			if (nums && g_variant_n_children(nums)) {
				const char *n;
				g_variant_get_child(nums, 0, "&s", &n);
				if (n[0] == '+')
					snprintf(r->id.msisdn, sizeof(r->id.msisdn), "%s", n);
				else if (n[0] && r->cfg.base.car.country_code[0] && n[0] == '0')
					snprintf(r->id.msisdn, sizeof(r->id.msisdn), "+%s%s",
						 r->cfg.base.car.country_code, n + 1);
				else if (n[0])
					snprintf(r->id.msisdn, sizeof(r->id.msisdn), "+%s", n);
			}
			if (nums)
				g_variant_unref(nums);
			g_variant_unref(modem);
		}
		g_variant_unref(ifaces);
	}
	g_variant_iter_free(objs);
	g_variant_unref(v);
}

/* The SIM's IMSI and PLMN, the modem's IMEI (QMI), or IMSROHA_RCS_IMSI/IMEI. */
static int read_identity(struct rcsd *r)
{
	const char *imsi = getenv("IMSROHA_RCS_IMSI"), *imei = getenv("IMSROHA_RCS_IMEI");
	if (imsi && *imsi) {
		snprintf(r->id.imsi, sizeof(r->id.imsi), "%s", imsi);
		snprintf(r->id.mcc, sizeof(r->id.mcc), "%.3s", imsi);
		const char *mnc_len = getenv("IMSROHA_RCS_MNC_LEN");
		int ml = mnc_len ? atoi(mnc_len) : 2;
		snprintf(r->id.mnc, sizeof(r->id.mnc), "%.*s", ml == 3 ? 3 : 2, imsi + 3);
	} else {
		struct imsd_isim_identity sim;
		imsroha_sim_set_device(&r->cfg.base.dev);
		int e = imsd_isim_read_identity(&sim);
		if (e < 0) {
			fprintf(stderr, "imsroha-rcs: cannot read the SIM: %s\n", strerror(-e));
			return e;
		}
		snprintf(r->id.imsi, sizeof(r->id.imsi), "%s", sim.imsi);
		snprintf(r->id.mcc, sizeof(r->id.mcc), "%s", sim.mcc);
		snprintf(r->id.mnc, sizeof(r->id.mnc), "%s", sim.mnc);
	}
	if (imei && *imei) {
		snprintf(r->id.imei, sizeof(r->id.imei), "%s", imei);
	} else {
		int e = imsroha_read_imei(&r->cfg.base.dev, r->id.imei, sizeof(r->id.imei));
		if (e < 0) {
			fprintf(stderr, "imsroha-rcs: cannot read the IMEI: %s\n", strerror(-e));
			return e;
		}
	}
	return 0;
}

/* ---- main --------------------------------------------------------------- */

static gboolean on_signal(gpointer ud)
{
	struct rcsd *r = ud;
	fprintf(stderr, "imsroha-rcs: stopping\n");
	rcsd_ua_stop(r);
	g_main_loop_quit(r->loop);
	return G_SOURCE_REMOVE;
}

static GDBusConnection *open_bus(void)
{
	const char *which = getenv("IMSROHA_RCS_BUS");
	GError *e = NULL;
	GDBusConnection *c = g_bus_get_sync(which && !strcmp(which, "session") ? G_BUS_TYPE_SESSION
										: G_BUS_TYPE_SYSTEM, NULL, &e);
	if (!c) {
		fprintf(stderr, "imsroha-rcs: no D-Bus: %s\n", e->message);
		g_error_free(e);
	}
	return c;
}

/*
 * RCS is off. Never on before (no state, or nothing configured): exit at once,
 * having opened nothing. On and configured before: tell the ACS once.
 */
static int run_off(struct rcsd *r)
{
	if (!acs_any_pending_disable(&r->cfg)) {
		fprintf(stderr, "imsroha-rcs: RCS is off ([rcs] enable=true in imsroha.conf turns it on)\n");
		return 0;
	}
	rcs_config_load(&r->cfg, NULL, NULL);
	if (read_identity(r) < 0)
		return 1;
	if (rcs_config_load(&r->cfg, r->id.mcc, r->id.mnc) < 0)
		return 1;
	if (acs_state_load(&r->cfg, r->id.imsi, &r->st) < 0 || !r->st.contacted || r->st.version <= 0 ||
	    r->st.disable_sent || r->st.permanent) {
		fprintf(stderr, "imsroha-rcs: RCS is off; nothing to tell the ACS for this SIM\n");
		return 0;
	}
	fprintf(stderr, "imsroha-rcs: RCS was turned off: telling the ACS (rcs_state=-4)\n");
	snprintf(r->id.msisdn, sizeof(r->id.msisdn), "%s", r->cfg.msisdn);
	if (!r->id.msisdn[0] && (r->bus = open_bus()))
		msisdn_from_mm(r);
	r->loop = g_main_loop_new(NULL, FALSE);
	r->otp_q = g_async_queue_new_full(g_free);
	acs_start(r, 1);
	g_main_loop_run(r->loop);
	return 0;
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv;
	struct rcsd *r = &d;

	rcs_config_load_switch(&r->cfg);
	if (!r->cfg.enable)
		return run_off(r);

	if (rcs_config_load(&r->cfg, NULL, NULL) < 0)
		return 1;
	if (read_identity(r) < 0)
		return 1;
	if (rcs_config_load(&r->cfg, r->id.mcc, r->id.mnc) < 0)
		return 1;
	if (!r->cfg.acs_url[0]) {
		fprintf(stderr, "imsroha-rcs: the carrier profile (%s) has no rcs-acs-url; nothing to do\n",
			r->cfg.base.car.name[0] ? r->cfg.base.car.name : "none for this SIM");
		return 0;
	}
	if (!r->cfg.terminal_vendor[0]) {
		fprintf(stderr, "imsroha-rcs: set [device] vendor= (terminal_vendor; SEC for Samsung)\n");
		return 1;
	}
	snprintf(r->id.msisdn, sizeof(r->id.msisdn), "%s", r->cfg.msisdn);
	fprintf(stderr, "imsroha-rcs: carrier %s, ACS %s\n", r->cfg.base.car.name, r->cfg.acs_url);

	r->loop = g_main_loop_new(NULL, FALSE);
	r->otp_q = g_async_queue_new_full(g_free);
	r->bus = open_bus();
	if (!r->bus)
		return 1;
	if (!r->id.msisdn[0])
		msisdn_from_mm(r);

	g_dbus_connection_signal_subscribe(r->bus, NULL, IMSD_BUS_NAME, "PduReceived", IMSD_BUS_PATH, NULL,
					   G_DBUS_SIGNAL_FLAGS_NONE, on_pdu, r, NULL);
	g_unix_signal_add(SIGINT, on_signal, r);
	g_unix_signal_add(SIGTERM, on_signal, r);
	if (rcsd_dbus_init(r) < 0)
		return 1;

	acs_state_load(&r->cfg, r->id.imsi, &r->st);
	int64_t now = (int64_t)time(NULL);
	if (r->st.permanent) {
		fprintf(stderr, "imsroha-rcs: the ACS refused this SIM permanently (-1); "
				"delete %s/%s to ask again\n", r->cfg.state_dir, r->id.imsi);
		rcsd_set_state(r, RCSD_DISABLED);
	} else if (r->st.version > 0 && r->st.next_run > now && !r->st.disable_sent && load_xml(r) == 0) {
		/* Still valid: no ACS request before the validity runs out. */
		rcsd_ua_start(r);
		arm_acs_timer(r);
	} else {
		/* Turned on again after a -4: the user enabled it. */
		r->st.disable_sent = 0;
		acs_start(r, 0);
	}
	g_main_loop_run(r->loop);
	rcsd_ua_stop(r);
	return 0;
}
