// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <libqmi-glib.h>
#include "config.h"

/*
 * Opens the modem's QMI device as the [device] section describes it: the
 * character device in qmi-device= (USB/PCIe modems), else QRTR node
 * qrtr-node= (SoC modems). The callback gets an open QmiDevice or an error.
 */
void imsroha_qmi_open(const struct imsroha_device *dev, QmiDeviceOpenFlags flags,
		      GCancellable *cancellable, GAsyncReadyCallback cb, gpointer user_data);
QmiDevice *imsroha_qmi_open_finish(GAsyncResult *res, GError **error);

/* Does the QRTR node (or the QMI device) offer this service? -1 when unknown. */
int imsroha_qmi_has_service(QmiDevice *qmi, QmiService service);
