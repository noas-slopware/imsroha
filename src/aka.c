/* b2q-imsd — QMI UIM ISIM AKA Authenticator */
#include "aka.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <libqmi-glib.h>
#include <libqrtr-glib.h>

struct aka_ctx {
	GMainLoop *loop;
	QmiDevice *dev;
	QmiClientUim *uim;
	guint8 channel_id;
	const struct imsd_aka_challenge *ch;
	struct imsd_aka_result *out;
	struct imsd_isim_identity *id; /* set: read the identity instead of AKA */
	int id_step;
	int id_record;                 /* EF_IMPU record being read */
	guint8 id_cmd[5 + 2];          /* the APDU in flight, for a 6Cxx retry */
	gsize id_cmd_len;
	int err_code;
};

static void close_channel_and_quit(struct aka_ctx *ctx)
{
	QmiMessageUimLogicalChannelInput *close_in = qmi_message_uim_logical_channel_input_new();
	qmi_message_uim_logical_channel_input_set_slot(close_in, 1, NULL);
	qmi_message_uim_logical_channel_input_set_channel_id(close_in, ctx->channel_id, NULL);
	qmi_client_uim_logical_channel(ctx->uim, close_in, 5, NULL, NULL, NULL);
	qmi_message_uim_logical_channel_input_unref(close_in);
	g_main_loop_quit(ctx->loop);
}

static void id_apdu_ready(QmiClientUim *client, GAsyncResult *res, gpointer user_data);

static void send_id_apdu(struct aka_ctx *ctx, const guint8 *apdu, gsize len)
{
	memcpy(ctx->id_cmd, apdu, len);
	ctx->id_cmd_len = len;

	QmiMessageUimSendApduInput *in = qmi_message_uim_send_apdu_input_new();
	qmi_message_uim_send_apdu_input_set_slot(in, 1, NULL);
	qmi_message_uim_send_apdu_input_set_channel_id(in, ctx->channel_id, NULL);
	GArray *arr = g_array_sized_new(FALSE, FALSE, sizeof(guint8), len);
	g_array_append_vals(arr, apdu, len);
	qmi_message_uim_send_apdu_input_set_apdu(in, arr, NULL);
	g_array_unref(arr);
	qmi_client_uim_send_apdu(ctx->uim, in, 5, NULL, (GAsyncReadyCallback)id_apdu_ready, ctx);
	qmi_message_uim_send_apdu_input_unref(in);
}

/*
 * The identity read, one APDU per step on the ISIM's logical channel:
 *   0 SELECT EF_DOMAIN 1 READ BINARY
 *   2 SELECT EF_IMPI   3 READ BINARY
 *   4 SELECT EF_IMPU   5 READ RECORD n, n = 1, 2, ... until one is on the
 *                        home domain or the card has no more records
 * EF_IMPU lists several public identities; on LG U+ record 1 is the
 * emergency one (sip:...@sos.<domain>), which a normal REGISTER must not use.
 */
#define ID_MAX_IMPU_RECORDS 8

static void id_next(struct aka_ctx *ctx)
{
	static const guint16 fid[] = { 0x6f03, 0x6f02, 0x6f04 };
	guint8 cla = ctx->channel_id; /* channels 1-3: CLA carries the channel number */

	if (ctx->id_step >= 6) {
		close_channel_and_quit(ctx);
		return;
	}
	if (ctx->id_step % 2 == 0) {
		guint16 f = fid[ctx->id_step / 2];
		const guint8 sel[] = { cla, 0xa4, 0x00, 0x0c, 0x02, f >> 8, f & 0xff };
		send_id_apdu(ctx, sel, sizeof(sel));
	} else if (ctx->id_step == 5) {
		const guint8 rec[] = { cla, 0xb2, (guint8)ctx->id_record, 0x04, 0x00 };
		send_id_apdu(ctx, rec, sizeof(rec));
	} else {
		const guint8 bin[] = { cla, 0xb0, 0x00, 0x00, 0x00 };
		send_id_apdu(ctx, bin, sizeof(bin));
	}
}

/* sip:<user>@<host>[;params]: is <host> exactly the home domain? */
static int impu_on_domain(const char *impu, const char *domain)
{
	const char *at = strchr(impu, '@');
	if (strncmp(impu, "sip:", 4) != 0 || !at)
		return 0;
	size_t n = strcspn(at + 1, ";>");
	return n == strlen(domain) && strncmp(at + 1, domain, n) == 0;
}

/* TS 31.103: each of these files holds one TLV, tag 0x80, with a UTF-8 string. */
static void copy_tlv80(const guint8 *data, gsize len, char *out, gsize out_size)
{
	if (len < 2 || data[0] != 0x80)
		return;
	gsize n = data[1];
	if (n > len - 2)
		n = len - 2;
	if (n >= out_size)
		n = out_size - 1;
	memcpy(out, data + 2, n);
	out[n] = '\0';
}

static void id_apdu_ready(QmiClientUim *client, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;
	GArray *resp = NULL;
	QmiMessageUimSendApduOutput *output = qmi_client_uim_send_apdu_finish(client, res, &err);

	if (!output || !qmi_message_uim_send_apdu_output_get_apdu_response(output, &resp, &err) ||
	    !resp || resp->len < 2) {
		fprintf(stderr, "b2q-imsd: ISIM read failed: %s\n", err ? err->message : "short response");
		ctx->err_code = -EIO;
		g_clear_error(&err);
		if (output)
			qmi_message_uim_send_apdu_output_unref(output);
		close_channel_and_quit(ctx);
		return;
	}

	const guint8 *b = (const guint8 *)resp->data;
	guint8 sw1 = b[resp->len - 2], sw2 = b[resp->len - 1];
	gsize data_len = resp->len - 2;

	if (sw1 == 0x6c && ctx->id_cmd_len == 5) {
		/* Wrong Le: the card says how long the answer is. */
		guint8 again[5];
		memcpy(again, ctx->id_cmd, 5);
		again[4] = sw2;
		qmi_message_uim_send_apdu_output_unref(output);
		send_id_apdu(ctx, again, 5);
		return;
	}
	if (sw1 == 0x61) {
		const guint8 get[] = { ctx->channel_id, 0xc0, 0x00, 0x00, sw2 };
		qmi_message_uim_send_apdu_output_unref(output);
		send_id_apdu(ctx, get, sizeof(get));
		return;
	}
	if (ctx->id_step == 5 && sw1 == 0x6a && sw2 == 0x83) {
		/* Record not found: no IMPU on the home domain. */
		fprintf(stderr, "b2q-imsd: no EF_IMPU record on the home domain\n");
		ctx->id->impu[0] = '\0';
		qmi_message_uim_send_apdu_output_unref(output);
		close_channel_and_quit(ctx);
		return;
	}
	if (sw1 != 0x90 || sw2 != 0x00) {
		fprintf(stderr, "b2q-imsd: ISIM read step %d: status %02x%02x\n", ctx->id_step, sw1, sw2);
		ctx->err_code = -EIO;
		qmi_message_uim_send_apdu_output_unref(output);
		close_channel_and_quit(ctx);
		return;
	}

	if (ctx->id_step == 1)
		copy_tlv80(b, data_len, ctx->id->domain, sizeof(ctx->id->domain));
	else if (ctx->id_step == 3)
		copy_tlv80(b, data_len, ctx->id->impi, sizeof(ctx->id->impi));
	else if (ctx->id_step == 5)
		copy_tlv80(b, data_len, ctx->id->impu, sizeof(ctx->id->impu));
	/* b points into output's response: nothing reads it after this. */
	qmi_message_uim_send_apdu_output_unref(output);

	if (ctx->id_step == 5) {
		{
			/* Shape only: digits masked, so no identity reaches the log. */
			char shape[128];
			size_t k;
			for (k = 0; ctx->id->impu[k] && k + 1 < sizeof(shape); k++)
				shape[k] = (ctx->id->impu[k] >= '0' && ctx->id->impu[k] <= '9') ? 'N' : ctx->id->impu[k];
			shape[k] = '\0';
			fprintf(stderr, "b2q-imsd: EF_IMPU record %d: %s (home domain %s)\n",
				ctx->id_record, shape, ctx->id->domain);
		}
		if (impu_on_domain(ctx->id->impu, ctx->id->domain)) {
			close_channel_and_quit(ctx);
			return;
		}
		ctx->id->impu[0] = '\0';
		if (++ctx->id_record > ID_MAX_IMPU_RECORDS) {
			fprintf(stderr, "b2q-imsd: no EF_IMPU record on the home domain\n");
			close_channel_and_quit(ctx);
			return;
		}
		id_next(ctx);
		return;
	}
	if (ctx->id_step == 4)
		ctx->id_record = 1;
	ctx->id_step++;
	id_next(ctx);
}

static void apdu_ready(QmiClientUim *client, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;
	QmiMessageUimSendApduOutput *output = qmi_client_uim_send_apdu_finish(client, res, &err);
	GArray *resp = NULL;

	if (!output) {
		fprintf(stderr, "b2q-imsd: send_apdu failed: %s\n", err ? err->message : "unknown");
		ctx->err_code = -EIO;
		if (err) g_error_free(err);
		g_main_loop_quit(ctx->loop);
		return;
	}

	if (qmi_message_uim_send_apdu_output_get_apdu_response(output, &resp, &err) && resp && resp->len >= 2) {
		const guint8 *bytes = (const guint8 *)resp->data;
		if (bytes[0] == 0xDB) {
			/* Tag 0xDB: [0xDB] [Len_RES] [RES...] [Len_CK] [CK...] [Len_IK] [IK...] [90 00] */
			guint idx = 1;
			guint res_len = bytes[idx++];
			if (idx + res_len <= resp->len && res_len <= sizeof(ctx->out->res)) {
				memcpy(ctx->out->res, &bytes[idx], res_len);
				ctx->out->res_len = res_len;
				idx += res_len;
			}
			if (idx < resp->len) {
				guint ck_len = bytes[idx++];
				if (idx + ck_len <= resp->len && ck_len <= sizeof(ctx->out->ck)) {
					memcpy(ctx->out->ck, &bytes[idx], ck_len);
					idx += ck_len;
				}
			}
			if (idx < resp->len) {
				guint ik_len = bytes[idx++];
				if (idx + ik_len <= resp->len && ik_len <= sizeof(ctx->out->ik)) {
					memcpy(ctx->out->ik, &bytes[idx], ik_len);
					idx += ik_len;
				}
			}
			ctx->out->is_sync_failure = 0;
			ctx->out->success = 1;
		} else if (bytes[0] == 0xDC) {
			/* Tag 0xDC: [0xDC] [Len_AUTS=14] [AUTS (14 bytes)] [90 00] */
			guint auts_len = bytes[1];
			if (auts_len > 14) auts_len = 14;
			if (2 + auts_len <= resp->len) {
				memcpy(ctx->out->auts, &bytes[2], auts_len);
				ctx->out->auts_len = auts_len;
				ctx->out->is_sync_failure = 1;
				ctx->out->success = 1;
			}
		} else {
			fprintf(stderr, "b2q-imsd: unexpected APDU response tag 0x%02x\n", bytes[0]);
			ctx->err_code = -EPROTO;
		}
	} else {
		fprintf(stderr, "b2q-imsd: APDU response error: %s\n", err ? err->message : "none");
		ctx->err_code = -EIO;
		if (err) g_error_free(err);
	}
	qmi_message_uim_send_apdu_output_unref(output);

	/* Close logical channel */
	QmiMessageUimLogicalChannelInput *close_in = qmi_message_uim_logical_channel_input_new();
	qmi_message_uim_logical_channel_input_set_slot(close_in, 1, NULL);
	qmi_message_uim_logical_channel_input_set_channel_id(close_in, ctx->channel_id, NULL);
	qmi_client_uim_logical_channel(ctx->uim, close_in, 5, NULL, NULL, NULL);
	qmi_message_uim_logical_channel_input_unref(close_in);

	g_main_loop_quit(ctx->loop);
}

static void open_channel_ready(QmiClientUim *client, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;
	QmiMessageUimOpenLogicalChannelOutput *out = qmi_client_uim_open_logical_channel_finish(client, res, &err);

	if (!out) {
		fprintf(stderr, "b2q-imsd: open_logical_channel failed: %s\n", err ? err->message : "unknown");
		ctx->err_code = -EIO;
		if (err) g_error_free(err);
		g_main_loop_quit(ctx->loop);
		return;
	}
	qmi_message_uim_open_logical_channel_output_get_channel_id(out, &ctx->channel_id, NULL);
	qmi_message_uim_open_logical_channel_output_unref(out);

	if (ctx->id) {
		ctx->id_step = 0;
		id_next(ctx);
		return;
	}

	guint8 apdu[5 + 34 + 1];
	apdu[0] = ctx->channel_id;
	apdu[1] = 0x88;
	apdu[2] = 0x00;
	apdu[3] = 0x81;
	apdu[4] = 0x22;
	apdu[5] = 0x10; /* RAND len */
	memcpy(&apdu[6], ctx->ch->rand, 16);
	apdu[22] = 0x10; /* AUTN len */
	memcpy(&apdu[23], ctx->ch->autn, 16);
	apdu[39] = 0x00; /* Le */

	QmiMessageUimSendApduInput *in = qmi_message_uim_send_apdu_input_new();
	qmi_message_uim_send_apdu_input_set_slot(in, 1, NULL);
	qmi_message_uim_send_apdu_input_set_channel_id(in, ctx->channel_id, NULL);
	GArray *arr = g_array_sized_new(FALSE, FALSE, sizeof(guint8), sizeof(apdu));
	g_array_append_vals(arr, apdu, sizeof(apdu));
	qmi_message_uim_send_apdu_input_set_apdu(in, arr, NULL);
	g_array_unref(arr);

	qmi_client_uim_send_apdu(ctx->uim, in, 5, NULL, (GAsyncReadyCallback)apdu_ready, ctx);
	qmi_message_uim_send_apdu_input_unref(in);
}

static void uim_client_ready(QmiDevice *device, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;
	QmiClient *cl = qmi_device_allocate_client_finish(device, res, &err);

	if (!cl) {
		fprintf(stderr, "b2q-imsd: allocate UIM client failed: %s\n", err ? err->message : "unknown");
		ctx->err_code = -EIO;
		if (err) g_error_free(err);
		g_main_loop_quit(ctx->loop);
		return;
	}
	ctx->uim = QMI_CLIENT_UIM(cl);

	static const guint8 isim_aid[] = {
		0xa0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04, 0xff,
		0x82, 0xff, 0xff, 0x89, 0x01, 0x00, 0x00, 0xff
	};
	QmiMessageUimOpenLogicalChannelInput *in = qmi_message_uim_open_logical_channel_input_new();
	qmi_message_uim_open_logical_channel_input_set_slot(in, 1, NULL);
	GArray *arr = g_array_sized_new(FALSE, FALSE, sizeof(guint8), sizeof(isim_aid));
	g_array_append_vals(arr, isim_aid, sizeof(isim_aid));
	qmi_message_uim_open_logical_channel_input_set_aid(in, arr, NULL);
	g_array_unref(arr);

	qmi_client_uim_open_logical_channel(ctx->uim, in, 5, NULL, (GAsyncReadyCallback)open_channel_ready, ctx);
	qmi_message_uim_open_logical_channel_input_unref(in);
}

static void open_ready(QmiDevice *device, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;

	if (!qmi_device_open_finish(device, res, &err)) {
		fprintf(stderr, "b2q-imsd: open device failed: %s\n", err ? err->message : "unknown");
		ctx->err_code = -EIO;
		if (err) g_error_free(err);
		g_main_loop_quit(ctx->loop);
		return;
	}
	qmi_device_allocate_client(device, QMI_SERVICE_UIM, QMI_CID_NONE, 5, NULL, (GAsyncReadyCallback)uim_client_ready, ctx);
}

static void device_ready(GObject *unused, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;

	(void)unused;
	ctx->dev = qmi_device_new_from_node_finish(res, &err);
	if (!ctx->dev) {
		fprintf(stderr, "b2q-imsd: new_from_node failed: %s\n", err ? err->message : "unknown");
		ctx->err_code = -EIO;
		if (err) g_error_free(err);
		g_main_loop_quit(ctx->loop);
		return;
	}
	qmi_device_open(ctx->dev, QMI_DEVICE_OPEN_FLAGS_PROXY, 5, NULL, (GAsyncReadyCallback)open_ready, ctx);
}

static void bus_ready(GObject *unused, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;

	(void)unused;
	QrtrBus *bus = qrtr_bus_new_finish(res, &err);
	if (!bus) {
		fprintf(stderr, "b2q-imsd: qrtr_bus_new failed: %s\n", err ? err->message : "unknown");
		ctx->err_code = -EIO;
		if (err) g_error_free(err);
		g_main_loop_quit(ctx->loop);
		return;
	}
	QrtrNode *node = qrtr_bus_peek_node(bus, 0);
	if (!node) {
		fprintf(stderr, "b2q-imsd: QRTR node 0 not found\n");
		ctx->err_code = -ENODEV;
		g_object_unref(bus);
		g_main_loop_quit(ctx->loop);
		return;
	}
	qmi_device_new_from_node(node, NULL, (GAsyncReadyCallback)device_ready, ctx);
	g_object_unref(bus);
}

static gboolean timeout_cb(gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	fprintf(stderr, "b2q-imsd: AKA SIM request timed out\n");
	ctx->err_code = -ETIMEDOUT;
	g_main_loop_quit(ctx->loop);
	return G_SOURCE_REMOVE;
}

int imsd_isim_read_identity(struct imsd_isim_identity *id)
{
	if (!id)
		return -EINVAL;
	memset(id, 0, sizeof(*id));

	struct aka_ctx ctx = {
		.loop = g_main_loop_new(NULL, FALSE),
		.id = id,
	};
	guint t_id = g_timeout_add_seconds(5, timeout_cb, &ctx);
	qrtr_bus_new(3000, NULL, (GAsyncReadyCallback)bus_ready, &ctx);
	g_main_loop_run(ctx.loop);
	g_source_remove(t_id);
	g_main_loop_unref(ctx.loop);
	if (ctx.uim)
		g_object_unref(ctx.uim);
	if (ctx.dev)
		g_object_unref(ctx.dev);

	if (!ctx.err_code && (!id->impi[0] || !id->impu[0] || !id->domain[0]))
		ctx.err_code = -ENODATA;
	return ctx.err_code;
}

int imsd_aka_run_isim(const struct imsd_aka_challenge *ch,
		      struct imsd_aka_result *out)
{
	if (!ch || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	struct aka_ctx ctx = {
		.loop = g_main_loop_new(NULL, FALSE),
		.dev = NULL,
		.uim = NULL,
		.channel_id = 0,
		.ch = ch,
		.out = out,
		.err_code = 0
	};

	guint t_id = g_timeout_add_seconds(5, timeout_cb, &ctx);
	qrtr_bus_new(3000, NULL, (GAsyncReadyCallback)bus_ready, &ctx);
	g_main_loop_run(ctx.loop);
	g_source_remove(t_id);
	g_main_loop_unref(ctx.loop);

	if (ctx.uim)
		g_object_unref(ctx.uim);
	if (ctx.dev)
		g_object_unref(ctx.dev);

	return ctx.err_code;
}
