#pragma once

#include <stdint.h>
#include <systemd/sd-bus.h>

#define IMSD_BUS_NAME "org.b2q.Imsd"
#define IMSD_BUS_PATH "/org/b2q/Imsd"
#define IMSD_ERR_NOT_READY "org.b2q.Imsd.Error.NotReady"

enum imsd_state {
	IMSD_DOWN = 0,
	IMSD_REGISTERING = 1,
	IMSD_UP = 2,
};

void imsd_emit_state_changed(sd_bus *bus, int state);
void imsd_emit_pdu_received(sd_bus *bus, const char *inbox_id, const char *pdu_hex);
void imsd_emit_call_added(sd_bus *bus, uint32_t call_id, const char *number, int direction);
void imsd_emit_call_state_changed(sd_bus *bus, uint32_t call_id, int state, int reason);
