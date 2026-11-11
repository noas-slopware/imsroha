// SPDX-License-Identifier: GPL-3.0-only
/*
 * SIM access over QMI UIM: the subscriber identity and IMS AKA.
 *
 * The identity comes from the ISIM (TS 31.103 EF_DOMAIN, EF_IMPI, EF_IMPU)
 * when the card has one. Every card also gets EF_IMSI and EF_AD read from the
 * USIM, for the PLMN that picks the carrier profile, and for TS 23.003 13.3
 * derived identities when there is no ISIM. AKA runs on the ISIM, or on the
 * USIM (same AUTHENTICATE, 3G context) when there is none.
 */
#include "aka.h"
#include "qmidev.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <libqmi-glib.h>

static struct imsroha_device sim_dev = { .qrtr_node = 0 };
static int aka_on_usim; /* set by the identity read: the card has no ISIM */

void imsroha_sim_set_device(const struct imsroha_device *dev)
{
	sim_dev = *dev;
}

/* 3GPP partial AIDs (RID A000000087 + application code): selected by prefix. */
static const guint8 isim_aid[] = {
	0xa0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04, 0xff,
	0x82, 0xff, 0xff, 0x89, 0x01, 0x00, 0x00, 0xff
};
static const guint8 usim_aid[] = { 0xa0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02 };

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
	int usim;                      /* AKA: run it on the USIM */
	int id_phase;                  /* identity: 0 EF_IMSI, 1 EF_AD, 2 EF_SMSP, then the ISIM */
	guint8 imsi_raw[9];
	gsize imsi_len;
	const guint8 *aid;             /* the application being opened, for a retry */
	gsize aid_len;
	int open_tries;
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
		fprintf(stderr, "imsroha: ISIM read failed: %s\n", err ? err->message : "short response");
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
		fprintf(stderr, "imsroha: no EF_IMPU record on the home domain\n");
		ctx->id->impu[0] = '\0';
		qmi_message_uim_send_apdu_output_unref(output);
		close_channel_and_quit(ctx);
		return;
	}
	if (sw1 != 0x90 || sw2 != 0x00) {
		fprintf(stderr, "imsroha: ISIM read step %d: status %02x%02x\n", ctx->id_step, sw1, sw2);
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
			fprintf(stderr, "imsroha: EF_IMPU record %d: %s (home domain %s)\n",
				ctx->id_record, shape, ctx->id->domain);
		}
		if (impu_on_domain(ctx->id->impu, ctx->id->domain)) {
			close_channel_and_quit(ctx);
			return;
		}
		ctx->id->impu[0] = '\0';
		if (++ctx->id_record > ID_MAX_IMPU_RECORDS) {
			fprintf(stderr, "imsroha: no EF_IMPU record on the home domain\n");
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
		fprintf(stderr, "imsroha: send_apdu failed: %s\n", err ? err->message : "unknown");
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
			fprintf(stderr, "imsroha: unexpected APDU response tag 0x%02x\n", bytes[0]);
			ctx->err_code = -EPROTO;
		}
	} else {
		fprintf(stderr, "imsroha: APDU response error: %s\n", err ? err->message : "none");
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

static void open_channel(struct aka_ctx *ctx, const guint8 *aid, gsize aid_len);

static gboolean open_channel_again(gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	open_channel(ctx, ctx->aid, ctx->aid_len);
	return G_SOURCE_REMOVE;
}

/*
 * All of the card's logical channels are in use for the moment: another QMI
 * client (imsroha-rcs reading EF_IMPU, ModemManager) holds one, or a process
 * that just stopped has not given its own back yet. That says nothing about
 * whether the card has the application.
 */
static int channels_busy(const GError *err)
{
	return err && err->domain == QMI_PROTOCOL_ERROR &&
	       (err->code == QMI_PROTOCOL_ERROR_INSUFFICIENT_RESOURCES ||
		err->code == QMI_PROTOCOL_ERROR_DEVICE_IN_USE);
}

static void open_channel_ready(QmiClientUim *client, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;
	QmiMessageUimOpenLogicalChannelOutput *out = qmi_client_uim_open_logical_channel_finish(client, res, &err);

	if (!out || !qmi_message_uim_open_logical_channel_output_get_result(out, &err)) {
		if (channels_busy(err)) {
			if (out)
				qmi_message_uim_open_logical_channel_output_unref(out);
			/* Within run_ctx()'s 10 s: 12 tries, 500 ms apart. */
			if (++ctx->open_tries < 12) {
				g_clear_error(&err);
				g_timeout_add(500, open_channel_again, ctx);
				return;
			}
			fprintf(stderr, "imsroha: no free logical channel on the card (%s)\n", err->message);
			g_clear_error(&err);
			ctx->err_code = -EBUSY;
			g_main_loop_quit(ctx->loop);
			return;
		}
		if (ctx->id && out) {
			/* No ISIM on this card: the identity is derived from the IMSI. */
			fprintf(stderr, "imsroha: no ISIM application (%s), using the USIM\n",
				err ? err->message : "unknown");
			ctx->id->has_isim = 0;
		} else {
			fprintf(stderr, "imsroha: open_logical_channel failed: %s\n", err ? err->message : "unknown");
			ctx->err_code = -EIO;
		}
		g_clear_error(&err);
		if (out)
			qmi_message_uim_open_logical_channel_output_unref(out);
		g_main_loop_quit(ctx->loop);
		return;
	}
	qmi_message_uim_open_logical_channel_output_get_channel_id(out, &ctx->channel_id, NULL);
	qmi_message_uim_open_logical_channel_output_unref(out);

	if (ctx->id) {
		ctx->id->has_isim = 1;
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

static void open_channel(struct aka_ctx *ctx, const guint8 *aid, gsize aid_len)
{
	ctx->aid = aid;
	ctx->aid_len = aid_len;
	QmiMessageUimOpenLogicalChannelInput *in = qmi_message_uim_open_logical_channel_input_new();
	qmi_message_uim_open_logical_channel_input_set_slot(in, 1, NULL);
	GArray *arr = g_array_sized_new(FALSE, FALSE, sizeof(guint8), aid_len);
	g_array_append_vals(arr, aid, aid_len);
	qmi_message_uim_open_logical_channel_input_set_aid(in, arr, NULL);
	g_array_unref(arr);

	qmi_client_uim_open_logical_channel(ctx->uim, in, 5, NULL, (GAsyncReadyCallback)open_channel_ready, ctx);
	qmi_message_uim_open_logical_channel_input_unref(in);
}

/* TS 31.102 EF_IMSI: length, then BCD with the parity/type nibble first. */
static void decode_imsi(const guint8 *b, gsize len, char *out, gsize size)
{
	gsize n = 0;
	if (len < 2 || b[0] < 1 || b[0] > len - 1) {
		out[0] = '\0';
		return;
	}
	for (gsize i = 1; i <= b[0] && n + 1 < size; i++) {
		guint8 lo = b[i] & 0x0f, hi = b[i] >> 4;
		if (i > 1 && lo <= 9)
			out[n++] = (char)('0' + lo);
		if (hi <= 9 && n + 1 < size)
			out[n++] = (char)('0' + hi);
	}
	out[n] = '\0';
}

static void read_usim_file(struct aka_ctx *ctx, guint16 fid);
static void read_smsp(struct aka_ctx *ctx);
static void sim_files_done(struct aka_ctx *ctx);

static void usim_file_ready(QmiClientUim *client, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;
	GArray *data = NULL;
	QmiMessageUimReadTransparentOutput *out = qmi_client_uim_read_transparent_finish(client, res, &err);

	if (!out || !qmi_message_uim_read_transparent_output_get_result(out, &err) ||
	    !qmi_message_uim_read_transparent_output_get_read_result(out, &data, &err) || !data) {
		fprintf(stderr, "imsroha: reading EF_%s failed: %s\n", ctx->id_phase ? "AD" : "IMSI",
			err ? err->message : "no data");
		g_clear_error(&err);
		if (out)
			qmi_message_uim_read_transparent_output_unref(out);
		if (ctx->id_phase == 0) {
			ctx->err_code = -EIO;
			g_main_loop_quit(ctx->loop);
			return;
		}
		/* No EF_AD: assume two MNC digits, unless the MCC says otherwise below. */
		ctx->id->mnc_len = 0;
	} else if (ctx->id_phase == 0) {
		ctx->imsi_len = MIN(data->len, sizeof(ctx->imsi_raw));
		memcpy(ctx->imsi_raw, data->data, ctx->imsi_len);
		decode_imsi(ctx->imsi_raw, ctx->imsi_len, ctx->id->imsi, sizeof(ctx->id->imsi));
	} else {
		const guint8 *b = (const guint8 *)data->data;
		ctx->id->mnc_len = data->len >= 4 && ((b[3] & 0x0f) == 2 || (b[3] & 0x0f) == 3) ? (b[3] & 0x0f) : 0;
	}
	if (out)
		qmi_message_uim_read_transparent_output_unref(out);

	if (ctx->id_phase++ == 0) {
		read_usim_file(ctx, 0x6fad);
		return;
	}
	read_smsp(ctx);
}

/* TS 31.102 4.2.27 EF_SMSP: alpha id, indicators, TP-DA (12), TS-SCA (12), PID, DCS, VP. */
static void smsp_ready(QmiClientUim *client, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GArray *data = NULL;
	QmiMessageUimReadRecordOutput *out = qmi_client_uim_read_record_finish(client, res, NULL);

	if (out && qmi_message_uim_read_record_output_get_result(out, NULL) &&
	    qmi_message_uim_read_record_output_get_read_result(out, &data, NULL) && data && data->len >= 28) {
		const guint8 *r = (const guint8 *)data->data + data->len - 28;
		const guint8 *sca = r + 13;
		/* Indicator bit 1 is 0 when the SC address is present; sca[0] counts TON + BCD bytes. */
		if (!(r[0] & 0x02) && sca[0] >= 2 && sca[0] <= 11) {
			gsize n = 0;
			char *o = ctx->id->smsc;
			if (sca[1] == 0x91)
				o[n++] = '+';
			for (guint i = 2; i <= sca[0] && n + 2 < sizeof(ctx->id->smsc); i++) {
				if ((sca[i] & 0x0f) <= 9)
					o[n++] = (char)('0' + (sca[i] & 0x0f));
				if ((sca[i] >> 4) <= 9)
					o[n++] = (char)('0' + (sca[i] >> 4));
			}
			o[n] = '\0';
		}
	}
	if (out)
		qmi_message_uim_read_record_output_unref(out);
	sim_files_done(ctx);
}

static void read_smsp(struct aka_ctx *ctx)
{
	static const guint8 path[] = { 0x00, 0x3f, 0xff, 0x7f };
	QmiMessageUimReadRecordInput *in = qmi_message_uim_read_record_input_new();
	GArray *aid = g_array_new(FALSE, FALSE, sizeof(guint8));
	GArray *p = g_array_sized_new(FALSE, FALSE, sizeof(guint8), sizeof(path));

	g_array_append_vals(p, path, sizeof(path));
	qmi_message_uim_read_record_input_set_session(in, QMI_UIM_SESSION_TYPE_PRIMARY_GW_PROVISIONING, aid, NULL);
	qmi_message_uim_read_record_input_set_file(in, 0x6f42, p, NULL);
	qmi_message_uim_read_record_input_set_record(in, 1, 0, NULL);
	g_array_unref(aid);
	g_array_unref(p);
	qmi_client_uim_read_record(ctx->uim, in, 5, NULL, (GAsyncReadyCallback)smsp_ready, ctx);
	qmi_message_uim_read_record_input_unref(in);
}

static void sim_files_done(struct aka_ctx *ctx)
{
	/* EF_IMSI, EF_AD and EF_SMSP done: the PLMN, then the ISIM if there is one. */
	size_t ilen = strlen(ctx->id->imsi);
	int mnc_len = ctx->id->mnc_len ? ctx->id->mnc_len : 2;
	if (ilen < 6) {
		fprintf(stderr, "imsroha: EF_IMSI holds no IMSI\n");
		ctx->err_code = -ENODATA;
		g_main_loop_quit(ctx->loop);
		return;
	}
	snprintf(ctx->id->mcc, sizeof(ctx->id->mcc), "%.3s", ctx->id->imsi);
	snprintf(ctx->id->mnc, sizeof(ctx->id->mnc), "%.*s", mnc_len, ctx->id->imsi + 3);
	fprintf(stderr, "imsroha: USIM PLMN %s%s\n", ctx->id->mcc, ctx->id->mnc);
	open_channel(ctx, isim_aid, sizeof(isim_aid));
}

static void read_usim_file(struct aka_ctx *ctx, guint16 fid)
{
	/* MF 3F00, ADF.USIM 7FFF, as little-endian bytes (as ModemManager does it). */
	static const guint8 path[] = { 0x00, 0x3f, 0xff, 0x7f };
	QmiMessageUimReadTransparentInput *in = qmi_message_uim_read_transparent_input_new();
	GArray *aid = g_array_new(FALSE, FALSE, sizeof(guint8));
	GArray *p = g_array_sized_new(FALSE, FALSE, sizeof(guint8), sizeof(path));

	g_array_append_vals(p, path, sizeof(path));
	qmi_message_uim_read_transparent_input_set_session(in, QMI_UIM_SESSION_TYPE_PRIMARY_GW_PROVISIONING, aid, NULL);
	qmi_message_uim_read_transparent_input_set_file(in, fid, p, NULL);
	qmi_message_uim_read_transparent_input_set_read_information(in, 0, 0, NULL);
	g_array_unref(aid);
	g_array_unref(p);
	qmi_client_uim_read_transparent(ctx->uim, in, 5, NULL, (GAsyncReadyCallback)usim_file_ready, ctx);
	qmi_message_uim_read_transparent_input_unref(in);
}

static void uim_client_ready(QmiDevice *device, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;
	QmiClient *cl = qmi_device_allocate_client_finish(device, res, &err);

	if (!cl) {
		fprintf(stderr, "imsroha: allocate UIM client failed: %s\n", err ? err->message : "unknown");
		ctx->err_code = -EIO;
		if (err) g_error_free(err);
		g_main_loop_quit(ctx->loop);
		return;
	}
	ctx->uim = QMI_CLIENT_UIM(cl);

	if (ctx->id) {
		ctx->id_phase = 0;
		read_usim_file(ctx, 0x6f07);
	} else if (ctx->usim) {
		open_channel(ctx, usim_aid, sizeof(usim_aid));
	} else {
		open_channel(ctx, isim_aid, sizeof(isim_aid));
	}
}

static void on_open(GObject *src, GAsyncResult *res, gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	GError *err = NULL;

	(void)src;
	ctx->dev = imsroha_qmi_open_finish(res, &err);
	if (!ctx->dev) {
		fprintf(stderr, "imsroha: opening the modem's QMI device: %s\n", err ? err->message : "unknown");
		ctx->err_code = -EIO;
		g_clear_error(&err);
		g_main_loop_quit(ctx->loop);
		return;
	}
	qmi_device_allocate_client(ctx->dev, QMI_SERVICE_UIM, QMI_CID_NONE, 5, NULL, (GAsyncReadyCallback)uim_client_ready, ctx);
}

static gboolean timeout_cb(gpointer user_data)
{
	struct aka_ctx *ctx = user_data;
	fprintf(stderr, "imsroha: SIM request timed out\n");
	ctx->err_code = -ETIMEDOUT;
	g_main_loop_quit(ctx->loop);
	return G_SOURCE_REMOVE;
}

static void run_ctx(struct aka_ctx *ctx)
{
	guint t_id = g_timeout_add_seconds(10, timeout_cb, ctx);
	imsroha_qmi_open(&sim_dev, QMI_DEVICE_OPEN_FLAGS_PROXY, NULL, on_open, ctx);
	g_main_loop_run(ctx->loop);
	g_source_remove(t_id);
	g_main_loop_unref(ctx->loop);
	if (ctx->uim) {
		if (ctx->dev)
			qmi_device_release_client(ctx->dev, QMI_CLIENT(ctx->uim),
						  QMI_DEVICE_RELEASE_CLIENT_FLAGS_RELEASE_CID, 5, NULL, NULL, NULL);
		g_object_unref(ctx->uim);
	}
	if (ctx->dev)
		g_object_unref(ctx->dev);
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
	run_ctx(&ctx);
	if (ctx.err_code == -EBUSY)
		return -EBUSY; /* the card is busy, not without an ISIM: ask again later */
	if (ctx.err_code && id->has_isim && id->imsi[0] && id->mcc[0]) {
		fprintf(stderr, "imsroha: reading the ISIM failed (%s), using the USIM\n", strerror(-ctx.err_code));
		ctx.err_code = 0;
		id->has_isim = 0;
	}
	if (ctx.err_code)
		return ctx.err_code;

	if (id->has_isim && (!id->impi[0] || !id->impu[0] || !id->domain[0])) {
		fprintf(stderr, "imsroha: the ISIM has no usable identity, using the USIM\n");
		id->has_isim = 0;
	}
	if (!id->has_isim) {
		/* TS 23.003 13.3/13.4B: identities derived from the IMSI. */
		char derived[128];
		imsroha_derived_domain(id->mcc, id->mnc, derived, sizeof(derived));
		snprintf(id->impi, sizeof(id->impi), "%s@%s", id->imsi, derived);
		snprintf(id->impu, sizeof(id->impu), "sip:%s@%s", id->imsi, derived);
		id->domain[0] = '\0'; /* the carrier profile's, or the derived one */
	}
	aka_on_usim = !id->has_isim;
	return 0;
}

int imsd_aka_run_isim(const struct imsd_aka_challenge *ch,
		      struct imsd_aka_result *out)
{
	if (!ch || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	struct aka_ctx ctx = {
		.loop = g_main_loop_new(NULL, FALSE),
		.ch = ch,
		.out = out,
		.usim = aka_on_usim,
	};
	run_ctx(&ctx);
	return ctx.err_code;
}
