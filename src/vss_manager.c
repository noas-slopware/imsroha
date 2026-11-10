#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libqmi-glib.h>
#include <libqrtr-glib.h>

static GMainLoop *loop;
static QmiDevice *g_dev;
static QmiClient *g_client;
static guint8 g_cid;
static int exit_code;

static void quit_fail(const char *why) {
    g_printerr("b2q-vss-manager: %s\n", why);
    exit_code = 1;
    if (loop)
        g_main_loop_quit(loop);
}

static void on_device_removed(QmiDevice *dev, gpointer user_data) {
    (void)dev;
    (void)user_data;
    quit_fail("QMI device removed (modem reset)");
}

static void dump_hex(const char *prefix, const guint8 *data, gsize len) {
    g_print("%s (%lu bytes): ", prefix, (unsigned long)len);
    for (gsize i = 0; i < len; i++) g_print("%02x ", data[i]);
    g_print("\n  ASCII: \"");
    for (gsize i = 0; i < len; i++) {
        char c = (char)data[i];
        g_print("%c", (c >= 32 && c <= 126) ? c : '.');
    }
    g_print("\"\n");
}

static void on_indication(QmiDevice *dev, QmiMessage *msg, gpointer user_data) {
    gsize len = 0;
    const guint8 *raw = qmi_message_get_raw(msg, &len, NULL);
    guint16 srv = qmi_message_get_service(msg);
    guint16 mid = qmi_message_get_message_id(msg);
    g_print("\n>>> INDICATION: srv=%u (0x%02x) msg_id=0x%04x <<<\n", srv, srv, mid);
    dump_hex("IND", raw, len);
    
    /* Parse TLVs */
    if (len >= 7) {
        gsize off = 7;
        while (off + 3 <= len) {
            guint8 type = raw[off];
            guint16 tlen = raw[off+1] | (raw[off+2] << 8);
            off += 3;
            if (off + tlen > len) break;
            g_print("  TLV 0x%02x (len %u):\n", type, tlen);
            dump_hex("    val", raw + off, tlen);
            
            /* If this is TLV 0x01 (IPC frame payload), check for P-CSCF string */
            if (type == 0x01 && tlen >= 7) {
                const guint8 *ipc = raw + off;
                guint16 ipc_pkt_len = ipc[2] | (ipc[3] << 8);
                g_print("    IPC packet: pkt_len=%u main_cmd=0x%02x sub_cmd=0x%02x type=0x%02x\n",
                        ipc_pkt_len, ipc[6], ipc[7], ipc[8]);
                if (tlen > 9) {
                    g_print("    Payload (from offset 9): \"");
                    for (guint16 k = 9; k < tlen; k++) {
                        char c = (char)ipc[k];
                        g_print("%c", (c >= 32 && c <= 126) ? c : '.');
                    }
                    g_print("\"\n");
                }
            }
            off += tlen;
        }
    }
}

static void on_cmd_done(QmiDevice *dev, GAsyncResult *res, gpointer user_data) {
    const char *label = (const char *)user_data;
    GError *error = NULL;
    QmiMessage *resp = qmi_device_command_full_finish(dev, res, &error);
    if (!resp) {
        g_print("[%s] CMD FAILED: %s\n", label, error ? error->message : "?");
        if (error) g_error_free(error);
        return;
    }
    gsize len = 0;
    const guint8 *raw = qmi_message_get_raw(resp, &len, NULL);
    guint16 res_code = 999, err_code = 999;
    for (gsize i = 0; i + 6 < len; i++) {
        if (raw[i] == 0x02 && raw[i+1] == 0x04 && raw[i+2] == 0x00) {
            res_code = raw[i+3] | (raw[i+4] << 8);
            err_code = raw[i+5] | (raw[i+6] << 8);
            break;
        }
    }
    g_print("[%s] Result=%u Error=0x%04x (%u)\n", label, res_code, err_code, err_code);
    qmi_message_unref(resp);
}

static void send_ipc_async(const guint8 *ipc_data, gsize ipc_len, gboolean include_rild0, const char *label) {
    g_print("\n--- Sending IPC [%s] (%lu bytes, include_rild0=%d) ---\n", label, (unsigned long)ipc_len, include_rild0);
    dump_hex("TX IPC", ipc_data, ipc_len);

    QmiMessage *req = qmi_message_new((QmiService)227, g_cid, qmi_client_get_next_transaction_id(g_client), 0x0006);

    if (include_rild0) {
        /* TLV 0x10: 1-byte length prefix 5, then "rild0" */
        gsize off10 = qmi_message_tlv_write_init(req, 0x10, NULL);
        qmi_message_tlv_write_guint8(req, 5, NULL);
        const char *name = "rild0";
        for (int i = 0; i < 5; i++)
            qmi_message_tlv_write_guint8(req, (guint8)name[i], NULL);
        qmi_message_tlv_write_complete(req, off10, NULL);
    }

    /* TLV 0x11: 2-byte length prefix, then raw IPC data */
    gsize off11 = qmi_message_tlv_write_init(req, 0x11, NULL);
    qmi_message_tlv_write_guint8(req, (guint8)(ipc_len & 0xff), NULL);
    qmi_message_tlv_write_guint8(req, (guint8)((ipc_len >> 8) & 0xff), NULL);
    for (gsize i = 0; i < ipc_len; i++)
        qmi_message_tlv_write_guint8(req, ipc_data[i], NULL);
    qmi_message_tlv_write_complete(req, off11, NULL);

    qmi_device_command_full(g_dev, req, NULL, 5, NULL, (GAsyncReadyCallback)on_cmd_done, (gpointer)label);
    qmi_message_unref(req);
}

static gboolean send_step2(gpointer user_data) {
    /* Send BuildIpcModemSdmPcscfGet: 07 00 00 00 0a 22 02 */
    static const guint8 pcscf_get1[7] = { 0x07, 0x00, 0x00, 0x00, 0x0a, 0x22, 0x02 };
    send_ipc_async(pcscf_get1, sizeof(pcscf_get1), FALSE, "BuildIpcModemSdmPcscfGet (0a 22 02)");
    return G_SOURCE_REMOVE;
}

static gboolean send_step3(gpointer user_data) {
    /* Send variant: 07 00 00 00 22 0a 02 */
    static const guint8 pcscf_get2[7] = { 0x07, 0x00, 0x00, 0x00, 0x22, 0x0a, 0x02 };
    send_ipc_async(pcscf_get2, sizeof(pcscf_get2), FALSE, "BuildIpcModemSdmPcscfGet (22 0a 02)");
    return G_SOURCE_REMOVE;
}

static void client_ready(QmiDevice *device, GAsyncResult *res, gpointer user_data) {
    GError *error = NULL;
    g_client = qmi_device_allocate_client_finish(device, res, &error);
    if (!g_client) {
        g_print("Alloc failed: %s\n", error ? error->message : "?");
        if (error) g_error_free(error);
        quit_fail("failed to allocate VSS client");
        return;
    }
    g_cid = qmi_client_get_cid(g_client);
    g_print("VSS Client CID: %u\n", g_cid);

    /* Step 1: Send IMS_REG_SET to ungate (binds rild0) */
    static const guint8 ungate_frame[13] = {
        0x0d, 0x00,             /* pkt_len = 13 */
        0x00, 0x00,             /* seq = 0, channel = 0 */
        0x16, 0x08,             /* main_cmd = 0x16 (IMS), sub_cmd = 0x08 (IMS_REG_SET) */
        0x03,                   /* cmd_type = 0x03 (SET) */
        0x01,                   /* status = 0x01 (registered) */
        0x01,                   /* featuretype = 0x01 (VoLTE / bit 0 = 1) */
        0x01,                   /* network = 0x01 (LTE) */
        0x00,                   /* cause = 0x00 */
        0x06,                   /* ecmp = 0x06 (LTE case 6) */
        0x30                    /* radio = 0x30 (E-UTRAN) */
    };
    send_ipc_async(ungate_frame, sizeof(ungate_frame), TRUE, "IMS_REG_SET ungate");

    /* Schedule step 2 after 1 second */
    g_timeout_add_seconds(1, send_step2, NULL);

    /* Schedule step 3 after 3 seconds */
    g_timeout_add_seconds(3, send_step3, NULL);
}

static void open_ready(QmiDevice *device, GAsyncResult *res, gpointer user_data) {
    GError *error = NULL;
    if (!qmi_device_open_finish(device, res, &error)) {
        g_print("Open failed: %s\n", error ? error->message : "?");
        if (error) g_error_free(error);
        quit_fail("failed to open QMI device");
        return;
    }
    g_dev = device;
    g_signal_connect(g_dev, "indication", G_CALLBACK(on_indication), NULL);
    g_signal_connect(g_dev, QMI_DEVICE_SIGNAL_REMOVED, G_CALLBACK(on_device_removed), NULL);
    g_print("QmiDevice open ok, indication signal connected\n");
    qmi_device_allocate_client(device, (QmiService)227, QMI_CID_NONE, 10, NULL, (GAsyncReadyCallback)client_ready, NULL);
}

static void device_ready(GObject *unused, GAsyncResult *res, gpointer user_data) {
    QmiDevice *dev = qmi_device_new_from_node_finish(res, NULL);
    if (!dev) {
        quit_fail("qmi_device_new_from_node failed");
        return;
    }
    qmi_device_open(dev, QMI_DEVICE_OPEN_FLAGS_EXPECT_INDICATIONS, 10, NULL, (GAsyncReadyCallback)open_ready, NULL);
}

static void bus_ready(GObject *unused, GAsyncResult *res, gpointer user_data) {
    QrtrBus *bus = qrtr_bus_new_finish(res, NULL);
    if (!bus) {
        quit_fail("qrtr_bus_new failed");
        return;
    }
    QrtrNode *node = qrtr_bus_peek_node(bus, 0);
    if (!node) {
        quit_fail("modem QRTR node 0 not found");
        return;
    }
    qmi_device_new_from_node(node, NULL, (GAsyncReadyCallback)device_ready, NULL);
}

int main() {
    loop = g_main_loop_new(NULL, FALSE);
    qrtr_bus_new(3000, NULL, (GAsyncReadyCallback)bus_ready, NULL);
    g_main_loop_run(loop);
    return exit_code;
}
