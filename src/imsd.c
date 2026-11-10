/* b2q-imsd — IMS daemon for Samsung Galaxy Z Flip3 (SM-F711N)
 *
 * Implements 3GPP SIP registration (ISIM AKA), SMS over IMS (3GPP TS 24.011),
 * and VoLTE voice signaling. Standard dialer/SMS apps talk to ModemManager;
 * MM delegates voice/messaging to this daemon over D-Bus (org.b2q.Imsd).
 *
 * Event-driven only: sd-event + sd-bus. No polls, no sleeps.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#include "aka.h"
#include "audio.h"
#include "dbus.h"
#include "inbox.h"
#include "sip.h"

static struct imsd_sip_ctx sip_ctx;

static int method_get_state(sd_bus_message *m, void *userdata,
			    sd_bus_error *ret_error)
{
	(void)userdata;
	(void)ret_error;
	return sd_bus_reply_method_return(m, "i", sip_ctx.reg_state);
}

static int method_send_sms(sd_bus_message *m, void *userdata,
			   sd_bus_error *ret_error)
{
	const char *dest = NULL;
	const char *text = NULL;
	(void)userdata;

	int r = sd_bus_message_read(m, "ss", &dest, &text);
	if (r < 0)
		return r;

	if (sip_ctx.reg_state != IMSD_UP)
		return sd_bus_error_set(ret_error, IMSD_ERR_NOT_READY, "account not registered with carrier");

	r = imsd_sip_send_sms(&sip_ctx, dest, text, m);
	if (r < 0)
		return sd_bus_error_setf(ret_error, SD_BUS_ERROR_FAILED, "failed to send SMS: %d", r);

	/* Defer reply until carrier returns RP-ACK or error asynchronously */
	return 1;
}

static int method_place_call(sd_bus_message *m, void *userdata,
			     sd_bus_error *ret_error)
{
	const char *dest = NULL;
	(void)userdata;

	int r = sd_bus_message_read(m, "s", &dest);
	if (r < 0)
		return r;

	if (sip_ctx.reg_state != IMSD_UP)
		return sd_bus_error_set(ret_error, IMSD_ERR_NOT_READY, "account not registered with carrier");

	uint32_t call_id = 0;
	r = imsd_sip_place_call(&sip_ctx, dest, &call_id);
	if (r < 0)
		return sd_bus_error_setf(ret_error, SD_BUS_ERROR_FAILED, "failed to place call: %d", r);

	return sd_bus_reply_method_return(m, "u", call_id);
}

static int method_hangup_call(sd_bus_message *m, void *userdata,
			      sd_bus_error *ret_error)
{
	uint32_t call_id = 0;
	(void)userdata;
	(void)ret_error;
	sd_bus_message_read(m, "u", &call_id);
	imsd_sip_hangup(&sip_ctx);
	return sd_bus_reply_method_return(m, "");
}

static int method_answer_call(sd_bus_message *m, void *userdata,
			      sd_bus_error *ret_error)
{
	uint32_t call_id = 0;
	(void)userdata;

	int r = sd_bus_message_read(m, "u", &call_id);
	if (r < 0)
		return r;

	if (sip_ctx.call_state != IMSD_CALL_RINGING)
		return sd_bus_error_setf(ret_error, SD_BUS_ERROR_FAILED,
					 "call %u is not ringing", call_id);

	fprintf(stderr, "b2q-imsd: answering call %u\n", call_id);
	r = imsd_sip_answer_call(&sip_ctx);
	if (r < 0)
		return sd_bus_error_setf(ret_error, SD_BUS_ERROR_FAILED, "failed to answer call: %d", r);
	return sd_bus_reply_method_return(m, "");
}

static int method_send_dtmf(sd_bus_message *m, void *userdata,
			    sd_bus_error *ret_error)
{
	uint32_t call_id = 0;
	const char *dtmf = NULL;
	int r;
	(void)userdata;

	r = sd_bus_message_read(m, "us", &call_id, &dtmf);
	if (r < 0)
		return r;

	if (call_id != sip_ctx.active_call_id ||
	    (sip_ctx.call_state != IMSD_CALL_ACTIVE && sip_ctx.call_state != IMSD_CALL_EARLY_MEDIA))
		return sd_bus_error_setf(ret_error, SD_BUS_ERROR_FAILED,
					 "call %u is not active", call_id);

	r = imsd_sip_send_dtmf(&sip_ctx, dtmf);
	if (r < 0)
		return sd_bus_error_set_errnof(ret_error, -r, "failed to send DTMF: %m");
	return sd_bus_reply_method_return(m, "");
}

static int append_pending(const char *id, const char *pdu_hex, void *userdata)
{
	return sd_bus_message_append(userdata, "(ss)", id, pdu_hex);
}

/* Inbox entries not yet acknowledged by ModemManager, oldest first. */
static int method_get_pending_pdus(sd_bus_message *m, void *userdata,
				   sd_bus_error *ret_error)
{
	sd_bus_message *reply = NULL;
	int r;
	(void)userdata;

	r = sd_bus_message_new_method_return(m, &reply);
	if (r >= 0)
		r = sd_bus_message_open_container(reply, 'a', "(ss)");
	if (r >= 0) {
		r = imsd_inbox_for_each(append_pending, reply);
		if (r < 0) {
			sd_bus_message_unref(reply);
			return sd_bus_error_set_errnof(ret_error, -r, "cannot read the inbox: %m");
		}
		r = sd_bus_message_close_container(reply);
	}
	if (r >= 0)
		r = sd_bus_send(NULL, reply, NULL);
	sd_bus_message_unref(reply);
	return r;
}

static int method_ack_pdu(sd_bus_message *m, void *userdata,
			  sd_bus_error *ret_error)
{
	const char *id = NULL;
	(void)userdata;

	int r = sd_bus_message_read(m, "s", &id);
	if (r < 0)
		return r;
	r = imsd_inbox_remove(id);
	if (r < 0 && r != -ENOENT)
		return sd_bus_error_set_errnof(ret_error, -r, "cannot remove inbox entry %s: %m", id);
	return sd_bus_reply_method_return(m, "");
}

static const sd_bus_vtable imsd_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD("GetState", "", "i", method_get_state, 0),
	SD_BUS_METHOD("SendSms", "ss", "s", method_send_sms, 0),
	SD_BUS_METHOD("CreateCall", "s", "u", method_place_call, 0),
	SD_BUS_METHOD("AnswerCall", "u", "", method_answer_call, 0),
	SD_BUS_METHOD("HangupCall", "u", "", method_hangup_call, 0),
	SD_BUS_METHOD("SendDtmf", "us", "", method_send_dtmf, 0),
	/* Privileged: they hand out and delete the user's messages. Only root
	 * (ModemManager) may call them. */
	SD_BUS_METHOD("GetPendingPdus", "", "a(ss)", method_get_pending_pdus, 0),
	SD_BUS_METHOD("AckPdu", "s", "", method_ack_pdu, 0),
	SD_BUS_SIGNAL("RegistrationStateChanged", "i", 0),
	SD_BUS_SIGNAL("PduReceived", "ss", 0),
	SD_BUS_SIGNAL("CallAdded", "usi", 0),
	SD_BUS_SIGNAL("CallStateChanged", "uii", 0),
	SD_BUS_VTABLE_END
};

static int on_signal(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata)
{
	(void)s; (void)si;
	sd_event *event = userdata;
	fprintf(stderr, "b2q-imsd: caught exit signal, stopping...\n");
	sd_event_exit(event, 0);
	return 0;
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv;
	sd_event *event = NULL;
	sd_bus *bus = NULL;
	int ret = 1;

	sip_ctx.fd = -1;
	sip_ctx.rtp_fd = -1;

	int r = sd_event_default(&event);
	if (r < 0) {
		fprintf(stderr, "b2q-imsd: sd_event_default failed: %d\n", r);
		return 1;
	}

	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGTERM);
	sigprocmask(SIG_BLOCK, &ss, NULL);
	sd_event_add_signal(event, NULL, SIGINT, on_signal, event);
	sd_event_add_signal(event, NULL, SIGTERM, on_signal, event);

	r = sd_bus_open_system(&bus);
	if (r < 0) {
		fprintf(stderr, "b2q-imsd: sd_bus_open_system failed: %d\n", r);
		goto done;
	}

	r = sd_bus_add_object_vtable(bus, NULL, IMSD_BUS_PATH,
				     IMSD_BUS_NAME, imsd_vtable, NULL);
	if (r < 0) {
		fprintf(stderr, "b2q-imsd: sd_bus_add_object_vtable failed: %d\n", r);
		goto done;
	}

	r = sd_bus_request_name(bus, IMSD_BUS_NAME, 0);
	if (r < 0) {
		fprintf(stderr, "b2q-imsd: sd_bus_request_name failed: %d\n", r);
		goto done;
	}

	r = sd_bus_attach_event(bus, event, 0);
	if (r < 0) {
		fprintf(stderr, "b2q-imsd: sd_bus_attach_event failed: %d\n", r);
		goto done;
	}

	/* Call audio goes to the user session; SMS works without it. */
	r = imsd_audio_init(event);
	if (r < 0)
		fprintf(stderr, "b2q-imsd: no call audio socket: %s\n", strerror(-r));

	/* Before REGISTER: nothing may be acknowledged until it can be stored. */
	r = imsd_inbox_init();
	if (r < 0) {
		fprintf(stderr, "b2q-imsd: cannot open the inbox: %d\n", r);
		goto done;
	}

	r = imsd_sip_init(&sip_ctx, event, bus);
	if (r < 0) {
		fprintf(stderr, "b2q-imsd: imsd_sip_init failed: %d\n", r);
		goto done;
	}

	fprintf(stderr, "b2q-imsd: daemon running on %s\n", IMSD_BUS_NAME);
	r = sd_event_loop(event);
	ret = (r < 0) ? 1 : 0;

done:
	imsd_sip_destroy(&sip_ctx);
	if (bus) {
		sd_bus_close(bus);
		sd_bus_unref(bus);
	}
	if (event) {
		sd_event_unref(event);
	}
	return ret;
}
