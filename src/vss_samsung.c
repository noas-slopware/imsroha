// SPDX-License-Identifier: GPL-3.0-only
/*
 * imsroha-vss-samsung: Samsung's modem firmware keeps IMS registration gated
 * until its own IMS stack (rild, over the vendor QMI service 227 "VSS",
 * which tunnels Samsung IPC) says it registered. With no Android, nothing
 * says so and the modem holds the IMS PDN back. This sends that IPC once
 * (IMS_REG_SET, VoLTE over LTE), then the two SDM P-CSCF queries, logs the
 * answers, releases its service 227 client and exits 0.
 *
 * It must not stay a client: the modem sends every 227 client an indication
 * every couple of minutes, nobody reads them while the AP is in s2idle, QRTR
 * flow control stalls, and Samsung's server ERR_FATALs the modem
 * ("Never recovery from QMI_CSI_CONN_BUSY"). Releasing the client closes its
 * QRTR socket, so the kernel tells the modem the client is gone.
 *
 * After a modem reset, imsroha-bearer exits and its restart starts this
 * again (Wants=), so the ungate is sent to every new modem boot.
 *
 * On a modem without service 227 (anything not Samsung) it exits 0 at once.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libqmi-glib.h>
#include "config.h"
#include "qmidev.h"
#if QMI_QRTR_SUPPORTED
#include <libqrtr-glib.h>
#endif

static GMainLoop *loop;
static QmiDevice *g_dev;
static QmiClient *g_client;
static guint8 g_cid;
static int exit_code;

/* The ungate and the two P-CSCF queries: release the client once all three
 * are answered (or failed). */
#define VSS_COMMANDS 3
static guint n_answered;

static void quit_fail(const char *why) {
    g_printerr("imsroha-vss-samsung: %s\n", why);
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

static void on_closed(GObject *src, GAsyncResult *res, gpointer user_data) {
    (void)user_data;
    qmi_device_close_finish(QMI_DEVICE(src), res, NULL);
    if (loop)
        g_main_loop_quit(loop);
}

static void on_released(GObject *src, GAsyncResult *res, gpointer user_data) {
    GError *error = NULL;
    (void)user_data;
    if (!qmi_device_release_client_finish(QMI_DEVICE(src), res, &error)) {
        /* The client is unregistered and its QRTR socket closed either way:
         * the release only fails on a client that was already released. */
        g_printerr("imsroha-vss-samsung: releasing the VSS client: %s\n", error->message);
        g_error_free(error);
    } else {
        g_print("VSS client released, done\n");
    }
    g_clear_object(&g_client);
    qmi_device_close_async(g_dev, 5, NULL, on_closed, NULL);
}

/* Every command is answered or has failed: stop being a 227 client. */
static void command_answered(void) {
    if (++n_answered < VSS_COMMANDS)
        return;
    qmi_device_release_client(g_dev, g_client, QMI_DEVICE_RELEASE_CLIENT_FLAGS_RELEASE_CID,
                              5, NULL, on_released, NULL);
}

static void on_cmd_done(QmiDevice *dev, GAsyncResult *res, gpointer user_data) {
    const char *label = (const char *)user_data;
    GError *error = NULL;
    QmiMessage *resp = qmi_device_command_full_finish(dev, res, &error);
    if (!resp) {
        g_print("[%s] CMD FAILED: %s\n", label, error ? error->message : "?");
        if (error) g_error_free(error);
        command_answered();
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
    command_answered();
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

G_GNUC_UNUSED static void open_ready(QmiDevice *device, GAsyncResult *res, gpointer user_data) {
    (void)res; (void)user_data;
    g_dev = device;
    g_signal_connect(g_dev, "indication", G_CALLBACK(on_indication), NULL);
    g_signal_connect(g_dev, QMI_DEVICE_SIGNAL_REMOVED, G_CALLBACK(on_device_removed), NULL);
    g_print("QmiDevice open ok, indication signal connected\n");
    qmi_device_allocate_client(device, (QmiService)227, QMI_CID_NONE, 10, NULL, (GAsyncReadyCallback)client_ready, NULL);
}

#if QMI_QRTR_SUPPORTED
static void on_vss_service(GObject *src, GAsyncResult *res, gpointer user_data) {
    QmiDevice *dev = user_data;
    if (!qrtr_node_wait_for_services_finish(QRTR_NODE(src), res, NULL)) {
        g_print("imsroha-vss-samsung: the modem has no Samsung VSS service (227), nothing to do\n");
        g_object_unref(dev);
        g_main_loop_quit(loop);
        return;
    }
    open_ready(dev, NULL, NULL);
}
#endif

static void on_open(GObject *src, GAsyncResult *res, gpointer user_data) {
    GError *error = NULL;
    (void)src; (void)user_data;
    QmiDevice *dev = imsroha_qmi_open_finish(res, &error);
    if (!dev) {
        g_printerr("imsroha-vss-samsung: opening the modem's QMI device: %s\n", error->message);
        g_error_free(error);
        quit_fail("no QMI device");
        return;
    }
#if QMI_QRTR_SUPPORTED
    QrtrNode *node = qmi_device_peek_node(dev);
#else
    void *node = NULL;
#endif
    if (!node) {
        /* Samsung's VSS service is on its SoC modems, reached over QRTR. */
        g_print("imsroha-vss-samsung: not a QRTR modem, nothing to do\n");
        g_object_unref(dev);
        g_main_loop_quit(loop);
        return;
    }
#if QMI_QRTR_SUPPORTED
    /*
     * The modem registers its services one by one while it boots (and it
     * may boot twice), so 227 may come after the node: wait for
     * it rather than look once. A modem that has not shown it after 30 s
     * is not a Samsung one.
     */
    GArray *svc = g_array_new(FALSE, FALSE, sizeof(guint32));
    guint32 vss = 227;
    g_array_append_val(svc, vss);
    qrtr_node_wait_for_services(node, svc, 30000, NULL, on_vss_service, dev);
    g_array_unref(svc);
#endif
}

int main(void) {
    struct imsroha_device dev;
    if (imsroha_config_load_device(&dev) < 0)
        return 1;
    loop = g_main_loop_new(NULL, FALSE);
    imsroha_qmi_open(&dev, QMI_DEVICE_OPEN_FLAGS_EXPECT_INDICATIONS, NULL, on_open, NULL);
    g_main_loop_run(loop);
    return exit_code;
}
