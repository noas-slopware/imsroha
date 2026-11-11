// SPDX-License-Identifier: GPL-3.0-only
/*
 * imsroha-bearer: bring up the IMS PDN and hold it for imsroha.
 *
 * Nothing here is specific to one phone. The modem is reached as [device]
 * in imsroha.conf says (QRTR node or QMI character device), the rmnet parent
 * is found from its driver the way ModemManager does it (ipa, mhi_net,
 * qmi_wwan, bam-dmux), the checksum offload follows the QMAP version the
 * modem negotiated (WDA Get Data Format), and the profile is the one whose
 * APN is "ims" unless profile= names one.
 *
 * Once the PDN is up, the link carries its address, traffic from that address
 * is policy-routed into its own table (default route over the link), and
 * $RUNTIME_DIRECTORY/pdn tells imsroha the interface, the address, and the
 * P-CSCFs and DNS servers the network sent in the PCO. Only then READY=1.
 *
 * Every failure exits nonzero so systemd retries it: at boot the modem answers
 * Start Network with OutOfCall until it has attached. Once up, the process
 * sleeps in the main loop and exits when the bearer goes away:
 *
 *   - WDS Packet Service Status indication reporting "disconnected",
 *   - the QMI device going away (modem crash or restart),
 *   - RTM_DELLINK of the link or RTM_DELADDR of its address.
 */

#include <errno.h>
#include <stdarg.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <glib-unix.h>
#include <libqmi-glib.h>
#include <systemd/sd-daemon.h>

#include "config.h"
#include "qmidev.h"
#include "rmnet_links.h"

/*
 * Used only when the modem reports no MTU for the PDN. 1428 is what the stock
 * LG U+ IMS profile (CSC customer.xml) uses; a fixed 1400 made every INVITE
 * to an 11-digit number IPv6-fragmented, and LG U+ answers those with
 * 404/503 most of the time.
 */
#define IMS_MTU_FALLBACK 1428

/* WDS Get Current Settings, raw: libqmi has no getter for the IPv6 P-CSCF list. */
#define WDS_GET_CURRENT_SETTINGS 0x002D
#define TLV_RESULT		0x02
#define TLV_PCSCF_VIA_PCO	0x22
#define TLV_PCSCF_FQDN_LIST	0x24
#define TLV_IPV6_ADDRESS	0x25
#define TLV_IPV6_DNS1		0x27
#define TLV_IPV6_DNS2		0x28
#define TLV_MTU			0x29
/*
 * Qualcomm's IPv6 P-CSCF list: a count byte, then 16 bytes per address, in
 * PCO order. libqmi skips this id (0x2D, then 0x2F); the layout is the one
 * the Fairphone 6 IMS daemon (Catcrafts/imsd) reads off its modem.
 */
#define TLV_PCSCF_IPV6_LIST	0x2E

static struct imsroha_device dev;
static GMainLoop *loop;
static QmiDevice *g_dev;
static QmiClientWds *g_wds;
static QmiClientWda *g_wda;
static int exit_code;

static int ep_type, ep_iface;
static QmiWdaDataAggregationProtocol qmap = QMI_WDA_DATA_AGGREGATION_PROTOCOL_DISABLED;

static guint8 profile_index;
static GArray *profiles;
static guint profiles_next;

static struct in6_addr ims_addr;
static unsigned int ims_ifindex;
static struct imsroha_pdn pdn;

static void die(const char *fmt, ...) G_GNUC_PRINTF(1, 2);

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "imsroha-bearer: ");
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
		fprintf(stderr, "imsroha-bearer: %s: %s\n", argv[0], error->message);
		g_error_free(error);
		return -1;
	}
	if (!g_spawn_check_wait_status(status, &error)) {
		GString *cmd = g_string_new(NULL);
		for (int i = 0; argv[i]; i++)
			g_string_append_printf(cmd, "%s%s", i ? " " : "", argv[i]);
		fprintf(stderr, "imsroha-bearer: '%s' failed: %s\n", cmd->str, error->message);
		g_string_free(cmd, TRUE);
		g_error_free(error);
		return -1;
	}
	return 0;
}

/* Like run(), quiet: for commands expected to fail (deleting what may not exist). */
static int run_quiet(const char *const argv[])
{
	int status = 0;
	if (!g_spawn_sync(NULL, (char **)argv, NULL,
			  G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
			  NULL, NULL, NULL, NULL, &status, NULL))
		return -1;
	return g_spawn_check_wait_status(status, NULL) ? 0 : -1;
}

/* ---- the rmnet parent and its endpoint ---- */

/* The kernel driver behind a netdev, as ModemManager reads it. */
static int netdev_driver(const char *ifname, char *out, size_t size)
{
	char path[256];
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", ifname);
	char *target = g_file_read_link(path, NULL);
	if (!target)
		return -1;
	char *base = g_path_get_basename(target);
	snprintf(out, size, "%s", base);
	g_free(base);
	g_free(target);
	return 0;
}

static int driver_endpoint(const char *driver)
{
	if (!strcmp(driver, "ipa"))
		return QMI_DATA_ENDPOINT_TYPE_EMBEDDED;
	if (!strcmp(driver, "mhi_net"))
		return QMI_DATA_ENDPOINT_TYPE_PCIE;
	if (!strcmp(driver, "qmi_wwan"))
		return QMI_DATA_ENDPOINT_TYPE_HSUSB;
	if (!strcmp(driver, "bam-dmux"))
		return QMI_DATA_ENDPOINT_TYPE_BAM_DMUX;
	return -1;
}

static int usb_interface_number(const char *ifname)
{
	char path[256], *s = NULL;
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/bInterfaceNumber", ifname);
	if (!g_file_get_contents(path, &s, NULL, NULL))
		return -1;
	int n = (int)strtol(s, NULL, 16);
	g_free(s);
	return n;
}

/* Fills dev.data_netdev (when empty), ep_type and ep_iface. */
static int find_data_path(void)
{
	char driver[64] = "";

	if (!dev.data_netdev[0]) {
		GDir *d = g_dir_open("/sys/class/net", 0, NULL);
		const char *name;
		while (d && (name = g_dir_read_name(d))) {
			if (netdev_driver(name, driver, sizeof(driver)) == 0 && driver_endpoint(driver) >= 0) {
				snprintf(dev.data_netdev, sizeof(dev.data_netdev), "%s", name);
				break;
			}
		}
		if (d)
			g_dir_close(d);
		if (!dev.data_netdev[0]) {
			fprintf(stderr, "imsroha-bearer: no modem data netdev (ipa, mhi_net, qmi_wwan, bam-dmux); set data-netdev=\n");
			return -1;
		}
	} else if (netdev_driver(dev.data_netdev, driver, sizeof(driver)) < 0) {
		driver[0] = '\0';
	}

	ep_type = dev.ep_type >= 0 ? dev.ep_type : driver_endpoint(driver);
	if (ep_type < 0) {
		fprintf(stderr, "imsroha-bearer: %s (driver '%s'): unknown endpoint, set data-endpoint-type=\n",
			dev.data_netdev, driver);
		return -1;
	}
	if (dev.ep_iface >= 0)
		ep_iface = dev.ep_iface;
	else if (ep_type == QMI_DATA_ENDPOINT_TYPE_EMBEDDED)
		ep_iface = 1;
	else if (ep_type == QMI_DATA_ENDPOINT_TYPE_PCIE)
		ep_iface = 4; /* Qualcomm's magic number, as in ModemManager */
	else if (ep_type == QMI_DATA_ENDPOINT_TYPE_HSUSB)
		ep_iface = usb_interface_number(dev.data_netdev);
	else
		ep_iface = 0;
	if (ep_iface < 0) {
		fprintf(stderr, "imsroha-bearer: no endpoint interface number for %s, set data-endpoint-iface=\n",
			dev.data_netdev);
		return -1;
	}
	printf("imsroha-bearer: data path %s (driver %s), endpoint %s/%d, mux id %d\n",
	       dev.data_netdev, driver[0] ? driver : "?",
	       qmi_data_endpoint_type_get_string(ep_type), ep_iface, dev.mux_id);
	return 0;
}

/* ---- the link ---- */

static int configure_network(const char *addr, guint8 prefix_len, guint32 mtu)
{
	char cidr[INET6_ADDRSTRLEN + 4], mtu_str[16], mux_str[16], table[16], prio[16];
	const char *ifn = dev.ims_netdev;

	snprintf(mtu_str, sizeof(mtu_str), "%u", mtu);
	snprintf(mux_str, sizeof(mux_str), "%d", dev.mux_id);
	snprintf(table, sizeof(table), "%d", dev.route_table);
	snprintf(prio, sizeof(prio), "%d", dev.route_priority);
	snprintf(cidr, sizeof(cidr), "%s/%u", addr, prefix_len ? prefix_len : 64);
	printf("imsroha-bearer: configuring %s with %s, MTU %u\n", ifn, cidr, mtu);

	/*
	 * Start from a fresh link: one left behind by an earlier run still
	 * carries the previous PDN's address.
	 */
	const char *const del[] = { "ip", "link", "del", ifn, NULL };
	if (if_nametoindex(ifn))
		run(del);
	/* And whatever else still holds our mux id, under any name. */
	imsroha_rmnet_clear_mux(dev.data_netdev, dev.mux_id);

	/* Checksum offload as negotiated: QMAPv5 has its own header format. */
	const char *ingress_ck = NULL, *egress_ck = NULL;
	if (qmap == QMI_WDA_DATA_AGGREGATION_PROTOCOL_QMAPV5) {
		ingress_ck = "ingress-mapv5-checksum";
		egress_ck = "egress-mapv5-checksum";
	} else if (qmap == QMI_WDA_DATA_AGGREGATION_PROTOCOL_QMAPV4) {
		ingress_ck = "ingress-mapv4-checksum";
		egress_ck = "egress-mapv4-checksum";
	}
	const char *add[20];
	int n = 0;
	add[n++] = "ip"; add[n++] = "link"; add[n++] = "add"; add[n++] = "link";
	add[n++] = dev.data_netdev; add[n++] = "name"; add[n++] = ifn;
	add[n++] = "type"; add[n++] = "rmnet"; add[n++] = "mux_id"; add[n++] = mux_str;
	add[n++] = "ingress-deaggregation"; add[n++] = "on";
	if (ingress_ck) {
		add[n++] = ingress_ck; add[n++] = "on";
		add[n++] = egress_ck; add[n++] = "on";
	}
	add[n] = NULL;

	const char *const up[] = { "ip", "link", "set", ifn, "mtu", mtu_str, "up", NULL };
	/* nodad: the network assigned this address; nothing else can hold it. */
	const char *const ad[] = { "ip", "-6", "addr", "replace", cidr, "dev", ifn, "nodad", NULL };
	if (run(add) || run(up) || run(ad))
		return -1;

	/*
	 * Everything sent from the IMS address (SIP, RTP, DNS to the PDN's
	 * servers) leaves over this link, and nothing else does: the rule
	 * matches the source address, the table only has the link's default.
	 */
	const char *const rt[] = { "ip", "-6", "route", "replace", "default", "dev", ifn,
		"table", table, NULL };
	const char *const rule_del[] = { "ip", "-6", "rule", "del", "priority", prio, NULL };
	const char *const rule[] = { "ip", "-6", "rule", "add", "from", addr, "table", table,
		"priority", prio, NULL };
	if (run(rt))
		return -1;
	/* A rule left from the previous PDN's address goes first (bounded: one per run). */
	for (int i = 0; i < 16 && run_quiet(rule_del) == 0; i++)
		;
	if (run(rule))
		return -1;

	ims_ifindex = if_nametoindex(ifn);
	return ims_ifindex ? 0 : -1;
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
				die("%s was deleted", dev.ims_netdev);
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
					die("the IMS address was removed from %s", dev.ims_netdev);
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
		fprintf(stderr, "imsroha-bearer: netlink: %s\n", strerror(errno));
		if (fd >= 0)
			close(fd);
		return -1;
	}
	g_unix_fd_add(fd, G_IO_IN | G_IO_ERR | G_IO_HUP, on_netlink, NULL);
	return 0;
}

/* ---- QMI: the PDN's settings, raw ---- */

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

static void on_device_removed(QmiDevice *d, gpointer user_data)
{
	(void)d;
	(void)user_data;
	die("QMI device removed");
}

static int tlv_bytes(QmiMessage *m, guint8 type, guint8 *out, gsize size, gsize *len)
{
	guint16 tlen = 0;
	gsize init = qmi_message_tlv_read_init(m, type, &tlen, NULL);
	if (!init || tlen > size)
		return -1;
	gsize off = 0;
	for (guint16 i = 0; i < tlen; i++)
		if (!qmi_message_tlv_read_guint8(m, init, &off, &out[i], NULL))
			return -1;
	*len = tlen;
	return 0;
}

static void append_word(char *list, size_t size, const char *word)
{
	size_t l = strlen(list);
	snprintf(list + l, size - l, "%s%s", l ? " " : "", word);
}

static void append_v6(char *list, size_t size, const guint8 *a16)
{
	char s[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET6, a16, s, sizeof(s)))
		append_word(list, size, s);
}

static void on_settings_done(QmiDevice *d, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	QmiMessage *m;
	guint8 buf[1024];
	gsize len;
	char addr[INET6_ADDRSTRLEN];

	(void)user_data;

	m = qmi_device_command_full_finish(d, res, &error);
	if (!m) {
		die("get_current_settings: %s", error->message);
		g_error_free(error);
		return;
	}

	if (tlv_bytes(m, TLV_RESULT, buf, sizeof(buf), &len) || len < 4) {
		die("get_current_settings: no result TLV");
		goto out;
	}
	guint16 status = buf[0] | buf[1] << 8, qerr = buf[2] | buf[3] << 8;
	if (status) {
		die("get_current_settings failed: %s", qmi_protocol_error_get_string(qerr));
		goto out;
	}

	if (tlv_bytes(m, TLV_IPV6_ADDRESS, buf, sizeof(buf), &len) || len != 17) {
		die("no IPv6 address in the current settings (IPv4-only IMS PDNs are not supported)");
		goto out;
	}
	memcpy(&ims_addr, buf, 16);
	guint8 prefix_len = buf[16];
	inet_ntop(AF_INET6, &ims_addr, addr, sizeof(addr));

	guint32 mtu = 0;
	if (!tlv_bytes(m, TLV_MTU, buf, sizeof(buf), &len) && len == 4)
		mtu = buf[0] | buf[1] << 8 | buf[2] << 16 | (guint32)buf[3] << 24;
	if (mtu < 1280 || mtu > 1500) {
		printf("imsroha-bearer: no usable MTU from the modem (%u), using %u\n", mtu, IMS_MTU_FALLBACK);
		mtu = IMS_MTU_FALLBACK;
	}

	memset(&pdn, 0, sizeof(pdn));
	snprintf(pdn.iface, sizeof(pdn.iface), "%s", dev.ims_netdev);
	snprintf(pdn.addr, sizeof(pdn.addr), "%s", addr);
	pdn.mtu = mtu;

	if (!tlv_bytes(m, TLV_PCSCF_IPV6_LIST, buf, sizeof(buf), &len) && len >= 1 &&
	    len == 1 + 16 * (gsize)buf[0])
		for (guint i = 0; i < buf[0]; i++)
			append_v6(pdn.pcscf, sizeof(pdn.pcscf), buf + 1 + 16 * i);
	if (!tlv_bytes(m, TLV_PCSCF_FQDN_LIST, buf, sizeof(buf), &len) && len >= 1) {
		/* count, then per entry: u16 length + name */
		gsize o = 1;
		for (guint i = 0; i < buf[0] && o + 2 <= len; i++) {
			guint16 l = buf[o] | buf[o + 1] << 8;
			o += 2;
			if (o + l > len)
				break;
			char name[256];
			snprintf(name, sizeof(name), "%.*s", (int)l, (const char *)buf + o);
			append_word(pdn.pcscf_fqdn, sizeof(pdn.pcscf_fqdn), name);
			o += l;
		}
	}
	if (!tlv_bytes(m, TLV_IPV6_DNS1, buf, sizeof(buf), &len) && len == 16)
		append_v6(pdn.dns, sizeof(pdn.dns), buf);
	if (!tlv_bytes(m, TLV_IPV6_DNS2, buf, sizeof(buf), &len) && len == 16)
		append_v6(pdn.dns, sizeof(pdn.dns), buf);
	guint8 via_pco = 0;
	if (!tlv_bytes(m, TLV_PCSCF_VIA_PCO, buf, sizeof(buf), &len) && len == 1)
		via_pco = buf[0];
	printf("imsroha-bearer: PCO P-CSCF (flag %u): [%s] fqdn [%s], DNS [%s]\n",
	       via_pco, pdn.pcscf, pdn.pcscf_fqdn, pdn.dns);

	if (configure_network(addr, prefix_len, mtu)) {
		die("failed to configure %s", dev.ims_netdev);
		goto out;
	}
	if (watch_netlink()) {
		die("cannot watch %s", dev.ims_netdev);
		goto out;
	}
	int r = imsroha_pdn_write(imsroha_runtime_dir(), &pdn);
	if (r < 0) {
		die("cannot write %s/pdn: %s", imsroha_runtime_dir(), strerror(-r));
		goto out;
	}

	printf("imsroha-bearer: IMS PDN up on %s (%s)\n", dev.ims_netdev, addr);
	sd_notifyf(0, "READY=1\nSTATUS=IMS PDN up on %s (%s)", dev.ims_netdev, addr);
out:
	qmi_message_unref(m);
}

static void get_settings(void)
{
	QmiMessage *m = qmi_message_new(QMI_SERVICE_WDS, qmi_client_get_cid(QMI_CLIENT(g_wds)),
					qmi_client_get_next_transaction_id(QMI_CLIENT(g_wds)),
					WDS_GET_CURRENT_SETTINGS);
	guint32 mask = QMI_WDS_REQUESTED_SETTINGS_PCSCF_ADDRESS |
		       QMI_WDS_REQUESTED_SETTINGS_PCSCF_SERVER_ADDRESS_LIST |
		       QMI_WDS_REQUESTED_SETTINGS_PCSCF_DOMAIN_NAME_LIST |
		       QMI_WDS_REQUESTED_SETTINGS_DNS_ADDRESS |
		       QMI_WDS_REQUESTED_SETTINGS_IP_ADDRESS |
		       QMI_WDS_REQUESTED_SETTINGS_IP_FAMILY |
		       QMI_WDS_REQUESTED_SETTINGS_MTU;
	gsize init = qmi_message_tlv_write_init(m, 0x10, NULL);
	qmi_message_tlv_write_guint32(m, QMI_ENDIAN_LITTLE, mask, NULL);
	qmi_message_tlv_write_complete(m, init, NULL);
	qmi_device_command_full(g_dev, m, NULL, 10, NULL,
				(GAsyncReadyCallback)on_settings_done, NULL);
	qmi_message_unref(m);
}

/* ---- QMI: start the PDN ---- */

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
	printf("imsroha-bearer: start_network ok, profile %u, handle %u\n", profile_index, handle);

	g_signal_connect(g_wds, "packet-service-status",
			 G_CALLBACK(on_packet_service_status), NULL);
	get_settings();
}

static void start_network(void)
{
	QmiMessageWdsStartNetworkInput *inp = qmi_message_wds_start_network_input_new();

	qmi_message_wds_start_network_input_set_profile_index_3gpp(inp, profile_index, NULL);
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
		fprintf(stderr, "imsroha-bearer: set_ip_family: %s (continuing)\n", error->message);
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

static void bind_mux(void)
{
	QmiMessageWdsBindMuxDataPortInput *b = qmi_message_wds_bind_mux_data_port_input_new();
	qmi_message_wds_bind_mux_data_port_input_set_mux_id(b, (guint8)dev.mux_id, NULL);
	qmi_message_wds_bind_mux_data_port_input_set_endpoint_info(b, ep_type, (guint32)ep_iface, NULL);
	qmi_client_wds_bind_mux_data_port(g_wds, b, 10, NULL,
					  (GAsyncReadyCallback)on_bind_mux_done, NULL);
	qmi_message_wds_bind_mux_data_port_input_unref(b);
}

/* ---- QMI: the profile whose APN is the IMS one ---- */

static void next_profile(void);

static void on_profile_settings(QmiClientWds *wds, GAsyncResult *res, gpointer user_data)
{
	guint8 index = (guint8)GPOINTER_TO_UINT(user_data);
	QmiMessageWdsGetProfileSettingsOutput *out = qmi_client_wds_get_profile_settings_finish(wds, res, NULL);
	const char *apn = NULL;

	if (out && qmi_message_wds_get_profile_settings_output_get_result(out, NULL) &&
	    qmi_message_wds_get_profile_settings_output_get_apn_name(out, &apn, NULL) && apn &&
	    !g_ascii_strcasecmp(apn, dev.apn)) {
		profile_index = index;
		printf("imsroha-bearer: profile %u has APN \"%s\"\n", index, apn);
		qmi_message_wds_get_profile_settings_output_unref(out);
		bind_mux();
		return;
	}
	if (out)
		qmi_message_wds_get_profile_settings_output_unref(out);
	next_profile();
}

static void next_profile(void)
{
	if (!profiles || profiles_next >= profiles->len) {
		die("no 3GPP profile with APN \"%s\" on the modem; set profile=", dev.apn);
		return;
	}
	QmiMessageWdsGetProfileListOutputProfileListProfile *p =
		&g_array_index(profiles, QmiMessageWdsGetProfileListOutputProfileListProfile, profiles_next++);
	QmiMessageWdsGetProfileSettingsInput *in = qmi_message_wds_get_profile_settings_input_new();
	qmi_message_wds_get_profile_settings_input_set_profile_id(in, QMI_WDS_PROFILE_TYPE_3GPP,
								   p->profile_index, NULL);
	qmi_client_wds_get_profile_settings(g_wds, in, 10, NULL,
					    (GAsyncReadyCallback)on_profile_settings,
					    GUINT_TO_POINTER(p->profile_index));
	qmi_message_wds_get_profile_settings_input_unref(in);
}

static void on_profile_list(QmiClientWds *wds, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	QmiMessageWdsGetProfileListOutput *out = qmi_client_wds_get_profile_list_finish(wds, res, &error);
	GArray *list = NULL;

	(void)user_data;
	if (!out || !qmi_message_wds_get_profile_list_output_get_result(out, &error) ||
	    !qmi_message_wds_get_profile_list_output_get_profile_list(out, &list, &error)) {
		die("get_profile_list: %s", error->message);
		g_error_free(error);
		if (out)
			qmi_message_wds_get_profile_list_output_unref(out);
		return;
	}
	/* The profile names in the elements belong to the output: keep it. */
	profiles = g_array_ref(list);
	profiles_next = 0;
	next_profile();
}

static void find_profile(void)
{
	if (dev.profile > 0) {
		profile_index = (guint8)dev.profile;
		bind_mux();
		return;
	}
	QmiMessageWdsGetProfileListInput *in = qmi_message_wds_get_profile_list_input_new();
	qmi_message_wds_get_profile_list_input_set_profile_type(in, QMI_WDS_PROFILE_TYPE_3GPP, NULL);
	qmi_client_wds_get_profile_list(g_wds, in, 10, NULL, (GAsyncReadyCallback)on_profile_list, NULL);
	qmi_message_wds_get_profile_list_input_unref(in);
}

static void on_wds_ready(QmiDevice *d, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	QmiClient *client;

	(void)user_data;

	client = qmi_device_allocate_client_finish(d, res, &error);
	if (!client) {
		die("allocating a WDS client: %s", error->message);
		g_error_free(error);
		return;
	}
	g_wds = QMI_CLIENT_WDS(client);
	find_profile();
}

/* ---- QMI: the negotiated data format, for the rmnet checksum flags ---- */

static void allocate_wds(void)
{
	qmi_device_allocate_client(g_dev, QMI_SERVICE_WDS, QMI_CID_NONE, 10, NULL,
				   (GAsyncReadyCallback)on_wds_ready, NULL);
}

static void on_data_format(QmiClientWda *wda, GAsyncResult *res, gpointer user_data)
{
	QmiMessageWdaGetDataFormatOutput *out = qmi_client_wda_get_data_format_finish(wda, res, NULL);

	(void)user_data;
	if (out && qmi_message_wda_get_data_format_output_get_result(out, NULL))
		qmi_message_wda_get_data_format_output_get_downlink_data_aggregation_protocol(out, &qmap, NULL);
	if (out)
		qmi_message_wda_get_data_format_output_unref(out);
	printf("imsroha-bearer: data aggregation %s\n", qmi_wda_data_aggregation_protocol_get_string(qmap));
	qmi_device_release_client(g_dev, QMI_CLIENT(g_wda), QMI_DEVICE_RELEASE_CLIENT_FLAGS_RELEASE_CID,
				  10, NULL, NULL, NULL);
	allocate_wds();
}

static void on_wda_ready(QmiDevice *d, GAsyncResult *res, gpointer user_data)
{
	QmiClient *client = qmi_device_allocate_client_finish(d, res, NULL);

	(void)user_data;
	if (!client) {
		/* No WDA service: plain QMAP, no checksum offload. */
		allocate_wds();
		return;
	}
	g_wda = QMI_CLIENT_WDA(client);
	QmiMessageWdaGetDataFormatInput *in = qmi_message_wda_get_data_format_input_new();
	qmi_message_wda_get_data_format_input_set_endpoint_info(in, ep_type, (guint32)ep_iface, NULL);
	qmi_client_wda_get_data_format(g_wda, in, 10, NULL, (GAsyncReadyCallback)on_data_format, NULL);
	qmi_message_wda_get_data_format_input_unref(in);
}

static void on_open(GObject *src, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;

	(void)src;
	(void)user_data;
	g_dev = imsroha_qmi_open_finish(res, &error);
	if (!g_dev) {
		die("opening the modem's QMI device: %s", error->message);
		g_error_free(error);
		return;
	}
	g_signal_connect(g_dev, QMI_DEVICE_SIGNAL_REMOVED, G_CALLBACK(on_device_removed), NULL);
	qmi_device_allocate_client(g_dev, QMI_SERVICE_WDA, QMI_CID_NONE, 10, NULL,
				   (GAsyncReadyCallback)on_wda_ready, NULL);
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

	if (imsroha_config_load_device(&dev) < 0)
		return 1;
	if (find_data_path() < 0)
		return 1;

	loop = g_main_loop_new(NULL, FALSE);
	g_unix_signal_add(SIGTERM, on_sigterm, NULL);
	g_unix_signal_add(SIGINT, on_sigterm, NULL);

	imsroha_qmi_open(&dev, QMI_DEVICE_OPEN_FLAGS_EXPECT_INDICATIONS, NULL, on_open, NULL);
	g_main_loop_run(loop);

	/*
	 * No explicit Stop Network: closing the QMI client on exit releases it,
	 * and the modem tears down the call that client owns.
	 */
	return exit_code;
}
