#include "dbus.h"

#include <stdio.h>

void imsd_emit_state_changed(sd_bus *bus, int state)
{
	if (!bus)
		return;
	sd_bus_emit_signal(bus, IMSD_BUS_PATH, IMSD_BUS_NAME,
			   "RegistrationStateChanged", "i", state);
}

void imsd_emit_pdu_received(sd_bus *bus, const char *inbox_id, const char *pdu_hex)
{
	if (!bus || !inbox_id || !pdu_hex)
		return;
	sd_bus_emit_signal(bus, IMSD_BUS_PATH, IMSD_BUS_NAME,
			   "PduReceived", "ss", inbox_id, pdu_hex);
}

void imsd_emit_call_added(sd_bus *bus, uint32_t call_id, const char *number, int direction)
{
	if (!bus)
		return;
	sd_bus_emit_signal(bus, IMSD_BUS_PATH, IMSD_BUS_NAME,
			   "CallAdded", "usi", call_id, number ? number : "", direction);
}

void imsd_emit_call_state_changed(sd_bus *bus, uint32_t call_id, int state, int reason)
{
	if (!bus)
		return;
	sd_bus_emit_signal(bus, IMSD_BUS_PATH, IMSD_BUS_NAME,
			   "CallStateChanged", "uii", call_id, state, reason);
}
