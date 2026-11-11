// SPDX-License-Identifier: GPL-3.0-only
/* The IMEI, for the +sip.instance IMEI URN (TS 23.003 13.8, RFC 7254). */
#include "imei.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <libqmi-glib.h>
#include "qmidev.h"

struct imei_ctx {
	GMainLoop *loop;
	QmiDevice *dev;
	QmiClient *dms;
	char *out;
	size_t size;
	int err;
};

static void ids_ready(QmiClientDms *dms, GAsyncResult *res, gpointer user_data)
{
	struct imei_ctx *c = user_data;
	const char *imei = NULL;
	QmiMessageDmsGetIdsOutput *o = qmi_client_dms_get_ids_finish(dms, res, NULL);

	if (o && qmi_message_dms_get_ids_output_get_result(o, NULL) &&
	    qmi_message_dms_get_ids_output_get_imei(o, &imei, NULL) && imei && strlen(imei) >= 14)
		snprintf(c->out, c->size, "%s", imei);
	else
		c->err = -ENODATA;
	if (o)
		qmi_message_dms_get_ids_output_unref(o);
	g_main_loop_quit(c->loop);
}

static void dms_ready(QmiDevice *dev, GAsyncResult *res, gpointer user_data)
{
	struct imei_ctx *c = user_data;
	c->dms = qmi_device_allocate_client_finish(dev, res, NULL);
	if (!c->dms) {
		c->err = -EIO;
		g_main_loop_quit(c->loop);
		return;
	}
	qmi_client_dms_get_ids(QMI_CLIENT_DMS(c->dms), NULL, 5, NULL, (GAsyncReadyCallback)ids_ready, c);
}

static void opened(GObject *src, GAsyncResult *res, gpointer user_data)
{
	struct imei_ctx *c = user_data;
	(void)src;
	c->dev = imsroha_qmi_open_finish(res, NULL);
	if (!c->dev) {
		c->err = -EIO;
		g_main_loop_quit(c->loop);
		return;
	}
	qmi_device_allocate_client(c->dev, QMI_SERVICE_DMS, QMI_CID_NONE, 5, NULL,
				   (GAsyncReadyCallback)dms_ready, c);
}

static gboolean timed_out(gpointer user_data)
{
	struct imei_ctx *c = user_data;
	c->err = -ETIMEDOUT;
	g_main_loop_quit(c->loop);
	return G_SOURCE_REMOVE;
}

int imsroha_read_imei(const struct imsroha_device *dev, char *out, size_t size)
{
	struct imei_ctx c = { .loop = g_main_loop_new(NULL, FALSE), .out = out, .size = size };

	out[0] = '\0';
	guint t = g_timeout_add_seconds(10, timed_out, &c);
	imsroha_qmi_open(dev, QMI_DEVICE_OPEN_FLAGS_PROXY, NULL, opened, &c);
	g_main_loop_run(c.loop);
	g_source_remove(t);
	g_main_loop_unref(c.loop);
	if (c.dms) {
		qmi_device_release_client(c.dev, c.dms, QMI_DEVICE_RELEASE_CLIENT_FLAGS_RELEASE_CID, 5, NULL, NULL, NULL);
		g_object_unref(c.dms);
	}
	if (c.dev)
		g_object_unref(c.dev);
	return c.err;
}

int imsroha_imei_urn(const char *imei, char *out, size_t size)
{
	/* urn:gsma:imei:<TAC, 8>-<SNR, 6>-0: the check digit is not sent, the spare is 0. */
	size_t n = strlen(imei);
	if (n < 14)
		return -EINVAL;
	for (size_t i = 0; i < 14; i++)
		if (imei[i] < '0' || imei[i] > '9')
			return -EINVAL;
	snprintf(out, size, "urn:gsma:imei:%.8s-%.6s-0", imei, imei + 8);
	return 0;
}
