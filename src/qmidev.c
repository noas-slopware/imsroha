// SPDX-License-Identifier: GPL-3.0-only
#include "qmidev.h"

/* SoC modems are reached over QRTR when libqmi was built with it; USB and
 * PCIe modems (qmi-device=) never need it. */
#if QMI_QRTR_SUPPORTED
#include <libqrtr-glib.h>
#endif

struct open_ctx {
	QmiDeviceOpenFlags flags;
#if QMI_QRTR_SUPPORTED
	QrtrBus *bus;
#else
	GObject *bus; /* always NULL */
#endif
	guint node;
};

static void open_ctx_free(struct open_ctx *c)
{
	if (c->bus)
		g_object_unref(c->bus);
	g_free(c);
}

static void on_opened(GObject *src, GAsyncResult *res, gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;

	if (!qmi_device_open_finish(QMI_DEVICE(src), res, &error)) {
		g_object_unref(src);
		g_task_return_error(task, error);
	} else {
		g_task_return_pointer(task, src, g_object_unref);
	}
	g_object_unref(task);
}

static void on_device(GObject *src, GAsyncResult *res, gpointer user_data)
{
	GTask *task = user_data;
	struct open_ctx *c = g_task_get_task_data(task);
	GError *error = NULL;
	QmiDevice *qmi;

	(void)src;
#if QMI_QRTR_SUPPORTED
	if (c->bus)
		qmi = qmi_device_new_from_node_finish(res, &error);
	else
#endif
		qmi = qmi_device_new_finish(res, &error);
	if (!qmi) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}
	/* The QRTR bus lives as long as the device: it reports the node going away. */
	if (c->bus)
		g_object_set_data_full(G_OBJECT(qmi), "imsroha-qrtr-bus", g_steal_pointer(&c->bus), g_object_unref);
	qmi_device_open(qmi, c->flags, 10, g_task_get_cancellable(task), on_opened, task);
}

#if QMI_QRTR_SUPPORTED
static void on_node(GObject *src, GAsyncResult *res, gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	QrtrNode *node = qrtr_bus_wait_for_node_finish(QRTR_BUS(src), res, &error);

	if (!node) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}
	qmi_device_new_from_node(node, g_task_get_cancellable(task), on_device, task);
	g_object_unref(node);
}

static void on_bus(GObject *src, GAsyncResult *res, gpointer user_data)
{
	GTask *task = user_data;
	struct open_ctx *c = g_task_get_task_data(task);
	GError *error = NULL;

	(void)src;
	c->bus = qrtr_bus_new_finish(res, &error);
	if (!c->bus) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}
	qrtr_bus_wait_for_node(c->bus, c->node, 10000, g_task_get_cancellable(task), on_node, task);
}
#endif

void imsroha_qmi_open(const struct imsroha_device *dev, QmiDeviceOpenFlags flags,
		      GCancellable *cancellable, GAsyncReadyCallback cb, gpointer user_data)
{
	GTask *task = g_task_new(NULL, cancellable, cb, user_data);
	struct open_ctx *c = g_new0(struct open_ctx, 1);

	c->flags = flags;
	c->node = dev->qrtr_node < 0 ? 0 : (guint)dev->qrtr_node;
	g_task_set_task_data(task, c, (GDestroyNotify)open_ctx_free);

	if (dev->qmi_path[0]) {
		/* A character device is shared with ModemManager through qmi-proxy. */
		c->flags |= QMI_DEVICE_OPEN_FLAGS_PROXY;
		GFile *file = g_file_new_for_path(dev->qmi_path);
		qmi_device_new(file, cancellable, on_device, task);
		g_object_unref(file);
		return;
	}
#if QMI_QRTR_SUPPORTED
	qrtr_bus_new(3000, cancellable, on_bus, task);
#else
	g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
				"this libqmi has no QRTR support: set qmi-device= in [device]");
	g_object_unref(task);
#endif
}

QmiDevice *imsroha_qmi_open_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_pointer(G_TASK(res), error);
}

int imsroha_qmi_has_service(QmiDevice *qmi, QmiService service)
{
#if QMI_QRTR_SUPPORTED
	QrtrNode *node = qmi_device_peek_node(qmi);
	if (!node)
		return -1;
	return qrtr_node_lookup_port(node, service) >= 0 ? 1 : 0;
#else
	(void)qmi; (void)service;
	return -1;
#endif
}
