// SPDX-License-Identifier: MIT
/*
 * b2q-ims-bearer: bring up the IMS PDN (WDS profile 4, IPv6) on mux id 3 and
 * hold it as qmapmux0.3 for b2q-imsd.
 *
 * Every failure exits nonzero so systemd retries it (Restart=on-failure): at
 * boot the modem answers Start Network with OutOfCall until it has attached.
 * Once the bearer is up, the process sleeps in the main loop and exits as soon
 * as one of these events says the bearer is gone:
 *
 *   - WDS Packet Service Status indication reporting "disconnected",
 *   - the QRTR node going away (modem crash or restart),
 *   - RTM_DELLINK for qmapmux0.3 or RTM_DELADDR of its address (ModemManager
 *     deletes every rmnet link when it sets up its own data port).
 *
 * READY=1 goes to systemd only after the interface carries the address, so
 * b2q-imsd (After= and BindsTo= this unit) never starts on a missing link.
 */

#include <errno.h>
#include <stdarg.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <glib-unix.h>
#include <libqmi-glib.h>
#include <libqrtr-glib.h>
#include <systemd/sd-daemon.h>

#define IMS_IFACE	"qmapmux0.3"
#define IMS_MUX_ID	3
#define IMS_PROFILE	4
/*
 * Used only when the modem reports no MTU for the PDN. 1428 is the stock
 * LG U+ IMS profile (CSC customer.xml); the old fixed 1400 made every INVITE
 * to an 11-digit number IPv6-fragmented, and LG U+ answers those with
 * 404/503 most of the time.
 */
#define IMS_MTU_FALLBACK 1428

static GMainLoop *loop;
static QmiDevice *g_dev;
static QmiClientWds *g_wds;
static int exit_code;

static struct in6_addr ims_addr;
static unsigned int ims_ifindex;

static void die(const char *fmt, ...) G_GNUC_PRINTF(1, 2);

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "b2q-ims-bearer: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	sd_notify(0, "STATUS=failed, exiting for a restart");
	exit_code = 1;
	g_main_loop_quit(loop);
}

/* Run an argv without a shell. Returns 0 when it exited with status 0. */
static int run(const char *const argv[])
{
	GError *error = NULL;
	int status = 0;

	if (!g_spawn_sync(NULL, (char **)argv, NULL, G_SPAWN_SEARCH_PATH,
			  NULL, NULL, NULL, NULL, &status, &error)) {
		fprintf(stderr, "b2q-ims-bearer: %s: %s\n", argv[0], error->message);
		g_error_free(error);
		return -1;
	}
	if (!g_spawn_check_wait_status(status, &error)) {
		fprintf(stderr, "b2q-ims-bearer: '%s %s %s' failed: %s\n",
			argv[0], argv[1], argv[2] ? argv[2] : "", error->message);
		g_error_free(error);
		return -1;
	}
	return 0;
}

static const char *const ims_routes[] = {
	"2001:4430::/32",
	"2001:4430:4:401::/64",
	"2001:4430:5:319::/64",
	"2001:4430:5:321::/64",
	"2001:4430:4:601::1",
	"2001:4430:5:601:2::1",
};

static int configure_network(const char *addr, guint8 prefix_len, guint32 mtu)
{
	char cidr[INET6_ADDRSTRLEN + 4];
	char mtu_str[16];

	snprintf(mtu_str, sizeof(mtu_str), "%u", mtu);

	snprintf(cidr, sizeof(cidr), "%s/%u", addr, prefix_len ? prefix_len : 64);
	printf("b2q-ims-bearer: configuring " IMS_IFACE " with %s, MTU %u\n", cidr, mtu);

	/*
	 * Start from a fresh link: an interface left behind by an earlier run
	 * still carries the previous PDN's address, and b2q-imsd binds to the
	 * first global address it finds.
	 */
	const char *const del[] = { "ip", "link", "del", IMS_IFACE, NULL };
	if (if_nametoindex(IMS_IFACE))
		run(del);

	const char *const add[] = { "ip", "link", "add", "link", "rmnet_ipa0",
		"name", IMS_IFACE, "type", "rmnet", "mux_id", G_STRINGIFY(IMS_MUX_ID),
		"ingress-deaggregation", "on", "ingress-mapv5-checksum", "on",
		"egress-mapv5-checksum", "on", NULL };
	const char *const up[] = { "ip", "link", "set", IMS_IFACE, "mtu", mtu_str,
		"up", NULL };
	const char *const ad[] = { "ip", "-6", "addr", "replace", cidr, "dev",
		IMS_IFACE, NULL };

	if (run(add) || run(up) || run(ad))
		return -1;

	for (size_t i = 0; i < G_N_ELEMENTS(ims_routes); i++) {
		const char *const rt[] = { "ip", "-6", "route", "replace",
			ims_routes[i], "dev", IMS_IFACE, NULL };
		if (run(rt))
			return -1;
	}

	ims_ifindex = if_nametoindex(IMS_IFACE);
	if (!ims_ifindex)
		return -1;
	return 0;
}

/* ---- netlink: notice the link or its address disappearing ---- */

static gboolean on_netlink(gint fd, GIOCondition cond, gpointer user_data)
{
	char buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));
	ssize_t len;

	(void)user_data;

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		die("netlink socket closed");
		return G_SOURCE_REMOVE;
	}

	len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (len < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return G_SOURCE_CONTINUE;
		/* ENOBUFS: events were dropped, so the state is unknown. */
		die("netlink recv: %s", strerror(errno));
		return G_SOURCE_REMOVE;
	}

	for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (size_t)len);
	     nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_type == RTM_DELLINK) {
			struct ifinfomsg *ifi = NLMSG_DATA(nh);
			if ((unsigned int)ifi->ifi_index == ims_ifindex) {
				die(IMS_IFACE " was deleted");
				return G_SOURCE_REMOVE;
			}
		} else if (nh->nlmsg_type == RTM_DELADDR) {
			struct ifaddrmsg *ifa = NLMSG_DATA(nh);
			int rtlen = IFA_PAYLOAD(nh);

			if (ifa->ifa_family != AF_INET6 || ifa->ifa_index != ims_ifindex)
				continue;
			for (struct rtattr *rta = IFA_RTA(ifa); RTA_OK(rta, rtlen);
			     rta = RTA_NEXT(rta, rtlen)) {
				if (rta->rta_type == IFA_ADDRESS &&
				    RTA_PAYLOAD(rta) == sizeof(ims_addr) &&
				    !memcmp(RTA_DATA(rta), &ims_addr, sizeof(ims_addr))) {
					die("the IMS address was removed from " IMS_IFACE);
					return G_SOURCE_REMOVE;
				}
			}
		}
	}
	return G_SOURCE_CONTINUE;
}

static int watch_netlink(void)
{
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK | RTMGRP_IPV6_IFADDR,
	};
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);

	if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "b2q-ims-bearer: netlink: %s\n", strerror(errno));
		if (fd >= 0)
			close(fd);
		return -1;
	}
	g_unix_fd_add(fd, G_IO_IN | G_IO_ERR | G_IO_HUP, on_netlink, NULL);
	return 0;
}

/* ---- QMI ---- */

static void on_packet_service_status(QmiClientWds *wds,
				     QmiIndicationWdsPacketServiceStatusOutput *ind,
				     gpointer user_data)
{
	QmiWdsConnectionStatus status;
	QmiWdsCallEndReason reason = QMI_WDS_CALL_END_REASON_GENERIC_UNSPECIFIED;

	(void)wds;
	(void)user_data;

	if (!qmi_indication_wds_packet_service_status_output_get_connection_status(
		    ind, &status, NULL, NULL))
		return;
	if (status != QMI_WDS_CONNECTION_STATUS_DISCONNECTED)
		return;

	qmi_indication_wds_packet_service_status_output_get_call_end_reason(ind, &reason, NULL);
	die("IMS PDN disconnected (%s)", qmi_wds_call_end_reason_get_string(reason));
}

static void on_device_removed(QmiDevice *dev, gpointer user_data)
{
	(void)dev;
	(void)user_data;
	die("QMI device removed");
}

static void on_settings_done(QmiClientWds *wds, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	QmiMessageWdsGetCurrentSettingsOutput *out;
	GArray *addr16 = NULL;
	guint8 prefix_len = 0;
	char addr[INET6_ADDRSTRLEN];

	(void)user_data;

	out = qmi_client_wds_get_current_settings_finish(wds, res, &error);
	if (!out || !qmi_message_wds_get_current_settings_output_get_result(out, &error)) {
		die("get_current_settings failed: %s", error->message);
		goto out;
	}
	if (!qmi_message_wds_get_current_settings_output_get_ipv6_address(
		    out, &addr16, &prefix_len, NULL) || addr16->len != 8) {
		die("no IPv6 address in the current settings");
		goto out;
	}

	guint32 mtu = 0;
	if (!qmi_message_wds_get_current_settings_output_get_mtu(out, &mtu, NULL) || mtu < 1280 || mtu > 1500) {
		printf("b2q-ims-bearer: no usable MTU from the modem (%u), using %u\n", mtu, IMS_MTU_FALLBACK);
		mtu = IMS_MTU_FALLBACK;
	}

	/* libqmi hands the address over as eight host-order 16-bit words. */
	for (guint i = 0; i < 8; i++)
		ims_addr.s6_addr16[i] = g_htons(g_array_index(addr16, guint16, i));
	inet_ntop(AF_INET6, &ims_addr, addr, sizeof(addr));

	if (configure_network(addr, prefix_len, mtu)) {
		die("failed to configure " IMS_IFACE);
		goto out;
	}
	if (watch_netlink()) {
		die("cannot watch " IMS_IFACE);
		goto out;
	}

	printf("b2q-ims-bearer: IMS PDN up on " IMS_IFACE " (%s)\n", addr);
	sd_notifyf(0, "READY=1\nSTATUS=IMS PDN up on " IMS_IFACE " (%s)", addr);
out:
	g_clear_error(&error);
	if (out)
		qmi_message_wds_get_current_settings_output_unref(out);
}

static void on_start_network_done(QmiClientWds *wds, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	QmiMessageWdsStartNetworkOutput *out;
	guint32 handle = 0;

	(void)user_data;

	out = qmi_client_wds_start_network_finish(wds, res, &error);
	if (!out) {
		die("start_network: %s", error->message);
		g_error_free(error);
		return;
	}

	if (!qmi_message_wds_start_network_output_get_result(out, &error)) {
		QmiWdsCallEndReason reason = QMI_WDS_CALL_END_REASON_GENERIC_UNSPECIFIED;
		QmiWdsVerboseCallEndReasonType vtype;
		gint16 vreason;

		qmi_message_wds_start_network_output_get_call_end_reason(out, &reason, NULL);
		if (qmi_message_wds_start_network_output_get_verbose_call_end_reason(
			    out, &vtype, &vreason, NULL))
			die("start_network failed: %s (call end: %s, verbose: %s)", error->message,
			    qmi_wds_call_end_reason_get_string(reason),
			    qmi_wds_verbose_call_end_reason_get_string(vtype, vreason));
		else
			die("start_network failed: %s (call end: %s)", error->message,
			    qmi_wds_call_end_reason_get_string(reason));
		g_error_free(error);
		qmi_message_wds_start_network_output_unref(out);
		return;
	}

	qmi_message_wds_start_network_output_get_packet_data_handle(out, &handle, NULL);
	qmi_message_wds_start_network_output_unref(out);
	if (!handle) {
		die("start_network returned packet data handle 0");
		return;
	}
	printf("b2q-ims-bearer: start_network ok, handle %u\n", handle);

	g_signal_connect(g_wds, "packet-service-status",
			 G_CALLBACK(on_packet_service_status), NULL);

	QmiMessageWdsGetCurrentSettingsInput *inp = qmi_message_wds_get_current_settings_input_new();
	qmi_message_wds_get_current_settings_input_set_requested_settings(inp,
		QMI_WDS_REQUESTED_SETTINGS_IP_ADDRESS | QMI_WDS_REQUESTED_SETTINGS_IP_FAMILY |
		QMI_WDS_REQUESTED_SETTINGS_MTU, NULL);
	qmi_client_wds_get_current_settings(g_wds, inp, 10, NULL,
					    (GAsyncReadyCallback)on_settings_done, NULL);
	qmi_message_wds_get_current_settings_input_unref(inp);
}

static void start_network(void)
{
	QmiMessageWdsStartNetworkInput *inp = qmi_message_wds_start_network_input_new();

	qmi_message_wds_start_network_input_set_profile_index_3gpp(inp, IMS_PROFILE, NULL);
	qmi_message_wds_start_network_input_set_ip_family_preference(inp, QMI_WDS_IP_FAMILY_IPV6, NULL);
	qmi_client_wds_start_network(g_wds, inp, 60, NULL,
				     (GAsyncReadyCallback)on_start_network_done, NULL);
	qmi_message_wds_start_network_input_unref(inp);
}

static void on_set_ip_family_done(QmiClientWds *wds, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	QmiMessageWdsSetIpFamilyOutput *out;

	(void)user_data;

	/* Advisory only: Start Network carries the family preference as well. */
	out = qmi_client_wds_set_ip_family_finish(wds, res, &error);
	if (!out || !qmi_message_wds_set_ip_family_output_get_result(out, &error))
		fprintf(stderr, "b2q-ims-bearer: set_ip_family: %s (continuing)\n", error->message);
	g_clear_error(&error);
	if (out)
		qmi_message_wds_set_ip_family_output_unref(out);

	start_network();
}

static void on_bind_mux_done(QmiClientWds *wds, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	QmiMessageWdsBindMuxDataPortOutput *out;

	(void)user_data;

	out = qmi_client_wds_bind_mux_data_port_finish(wds, res, &error);
	if (!out || !qmi_message_wds_bind_mux_data_port_output_get_result(out, &error)) {
		die("bind_mux_data_port: %s", error->message);
		g_error_free(error);
		if (out)
			qmi_message_wds_bind_mux_data_port_output_unref(out);
		return;
	}
	qmi_message_wds_bind_mux_data_port_output_unref(out);

	QmiMessageWdsSetIpFamilyInput *inp = qmi_message_wds_set_ip_family_input_new();
	qmi_message_wds_set_ip_family_input_set_preference(inp, QMI_WDS_IP_FAMILY_IPV6, NULL);
	qmi_client_wds_set_ip_family(g_wds, inp, 10, NULL,
				     (GAsyncReadyCallback)on_set_ip_family_done, NULL);
	qmi_message_wds_set_ip_family_input_unref(inp);
}

static void on_client_ready(QmiDevice *dev, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	QmiClient *client;

	(void)user_data;

	client = qmi_device_allocate_client_finish(dev, res, &error);
	if (!client) {
		die("allocating a WDS client: %s", error->message);
		g_error_free(error);
		return;
	}
	g_wds = QMI_CLIENT_WDS(client);

	QmiMessageWdsBindMuxDataPortInput *b = qmi_message_wds_bind_mux_data_port_input_new();
	qmi_message_wds_bind_mux_data_port_input_set_mux_id(b, IMS_MUX_ID, NULL);
	qmi_message_wds_bind_mux_data_port_input_set_endpoint_info(b,
		QMI_DATA_ENDPOINT_TYPE_EMBEDDED, 1, NULL);
	qmi_client_wds_bind_mux_data_port(g_wds, b, 10, NULL,
					  (GAsyncReadyCallback)on_bind_mux_done, NULL);
	qmi_message_wds_bind_mux_data_port_input_unref(b);
}

static void on_open_ready(QmiDevice *dev, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;

	(void)user_data;

	if (!qmi_device_open_finish(dev, res, &error)) {
		die("opening the QMI device: %s", error->message);
		g_error_free(error);
		return;
	}
	g_signal_connect(dev, QMI_DEVICE_SIGNAL_REMOVED, G_CALLBACK(on_device_removed), NULL);
	qmi_device_allocate_client(dev, QMI_SERVICE_WDS, QMI_CID_NONE, 10, NULL,
				   (GAsyncReadyCallback)on_client_ready, NULL);
}

static void on_device_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;

	(void)source;
	(void)user_data;

	g_dev = qmi_device_new_from_node_finish(res, &error);
	if (!g_dev) {
		die("creating the QMI device: %s", error->message);
		g_error_free(error);
		return;
	}
	qmi_device_open(g_dev, QMI_DEVICE_OPEN_FLAGS_EXPECT_INDICATIONS, 10, NULL,
			(GAsyncReadyCallback)on_open_ready, NULL);
}

static void on_node_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	QrtrNode *node;

	(void)user_data;

	node = qrtr_bus_wait_for_node_finish(QRTR_BUS(source), res, &error);
	if (!node) {
		die("modem QRTR node 0: %s", error->message);
		g_error_free(error);
		return;
	}
	qmi_device_new_from_node(node, NULL, (GAsyncReadyCallback)on_device_ready, NULL);
	g_object_unref(node);
}

static void on_bus_ready(GObject *source, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	QrtrBus *bus;

	(void)source;
	(void)user_data;

	bus = qrtr_bus_new_finish(res, &error);
	if (!bus) {
		die("opening the QRTR bus: %s", error->message);
		g_error_free(error);
		return;
	}
	/* The bus stays referenced for the life of the process. */
	qrtr_bus_wait_for_node(bus, 0, 10000, NULL, on_node_ready, NULL);
}

static gboolean on_sigterm(gpointer user_data)
{
	(void)user_data;
	g_main_loop_quit(loop);
	return G_SOURCE_REMOVE;
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);

	loop = g_main_loop_new(NULL, FALSE);
	g_unix_signal_add(SIGTERM, on_sigterm, NULL);
	g_unix_signal_add(SIGINT, on_sigterm, NULL);

	qrtr_bus_new(3000, NULL, on_bus_ready, NULL);
	g_main_loop_run(loop);

	/*
	 * No explicit Stop Network: closing the QRTR socket on exit releases the
	 * WDS client, and the modem tears down the call that client owns.
	 */
	return exit_code;
}
