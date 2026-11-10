#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "codec.h"

#define IMSD_SIP_PORT 5060
#define IMSD_PCSCF_IP "2001:4430:4:401::43"
#define IMSD_PCSCF_PORT 5060
#define IMSD_DOMAIN "lte-lguplus.co.kr"
#define IMSD_IMS_IFACE "qmapmux0.3"
/*
 * TTAK.KO-06.0357 (Korean VoLTE terminal standard), mandatory User-Agent:
 * "TTA-VoLTE/<ver> <model>/<SW version> Device_Type/<type> <operator>", the
 * format of the stock LG U+ profile ("TTA-VoLTE/[UICC_VERSION]
 * [PRODUCT_MODEL]/[BUILD_VERSION] Device_Type/Android_Phone [OMCCODE]").
 * Operators classify the terminal from it.
 */
/* Payload types imsd offers (same numbers as the stock profile where it has them). */
#define IMSD_PT_AMRWB 106
#define IMSD_PT_AMR 104
#define IMSD_PT_DTMF_WB 107
#define IMSD_PT_DTMF 101
#define IMSD_USER_AGENT "TTA-VoLTE/1.0 SM-F711N/b2q-imsd-0.1 Device_Type/Android_Phone LUC"
/* Methods we answer; every Allow header we send lists the same set. */
#define IMSD_ALLOW "INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, OPTIONS, INFO"

enum imsd_call_state {
	IMSD_CALL_IDLE = 0,
	IMSD_CALL_DIALING = 1,
	IMSD_CALL_RINGING = 2,
	IMSD_CALL_EARLY_MEDIA = 3,
	IMSD_CALL_ACTIVE = 4,
	IMSD_CALL_TERMINATED = 5,
};

/* 16 slots of 20 ms: 320 ms of reordering room */
#define IMSD_PLAYOUT_SLOTS 16
/* Frames played behind the newest arrival: 60 ms of jitter absorbed */
#define IMSD_PLAYOUT_DELAY 3

struct imsd_sip_ctx {
	int fd;
	sd_event *event;
	sd_bus *bus;
	char local_ip[INET6_ADDRSTRLEN];
	struct sockaddr_in6 pcscf_addr;

	/* Subscriber identity, read from the ISIM at start (never compiled in). */
	char impi[128];      /* private identity, the Digest username */
	char impu[128];      /* public identity, sip:<user>@<domain> */
	char impu_user[64];  /* its user part, for Contact */

	/* Registration state */
	int reg_state; /* 0=down, 1=registering, 2=up */
	uint32_t reg_cseq;
	char reg_call_id[64];
	char reg_from_tag[16];
	uint32_t reg_expires;
	/* Min-Expires from a 423 to REGISTER, 0 until one arrives. */
	uint32_t reg_min_expires;
	char reg_service_route[256];
	char reg_associated_uri[256];
	sd_event_source *reg_timer;
	sd_event_source *reg_retry_timer;
	int reg_retry_count;

	/* Call state */
	int call_state;
	uint32_t active_call_id;
	char call_id[64];
	char call_branch[64];
	char call_from_tag[16];
	char call_to_tag[64];
	char call_remote[160]; /* the INVITE's To value, <tel:...> */
	char call_remote_uri[128];
	char call_remote_contact[128];
	uint32_t call_cseq;
	uint32_t call_invite_cseq;

	/* Incoming call state */
	int call_is_incoming;
	char inc_via[1024];
	char inc_from[256];
	char inc_to[256];
	char inc_call_id[128];
	char inc_cseq[64];
	char inc_contact[256];
	/* The INVITE had no SDP: our 200 OK is the offer, the ACK the answer. */
	int inc_offerless;

	/* RTP socket */
	int rtp_fd;
	sd_event_source *rtp_source;
	uint64_t rtp_rx_pkts;
	uint64_t rtp_rx_bytes;

	/* Codec negotiation */
	int call_pt_amrwb;
	int call_pt_amr;
	/* What the far end's latest SDP actually lists (call_pt_* fall back to defaults). */
	int call_has_wb;
	int call_has_nb;
	int call_pt_dtmf;
	int call_pt_dtmf_wb;
	int call_pt_dtmf_nb;
	/* Whether the last SDP actually offered each telephone-event clock. */
	int call_has_dtmf_wb;
	int call_has_dtmf_nb;
	int call_octet_aligned;

	/* Our SDP origin: one session id per call, version bumped per body (RFC 3264 8). */
	uint64_t sdp_sess_id;
	uint64_t sdp_sess_ver;

	/* DTMF (RFC 4733 telephone-event) queue */
	char dtmf_queue[64];
	size_t dtmf_q_len;
	int dtmf_active_event;
	uint16_t dtmf_duration;
	int dtmf_end_sent;
	int dtmf_gap_frames;
	uint32_t dtmf_start_ts;

	/* Remote RTP endpoint */
	char remote_rtp_ip[INET6_ADDRSTRLEN];
	uint16_t remote_rtp_port;
	struct sockaddr_in6 remote_rtp_addr;

	/* RTP uplink stream */
	sd_event_source *rtp_tx_timer;
	uint16_t rtp_tx_seq;
	uint32_t rtp_tx_ts;
	uint64_t rtp_tx_pkts;


	/* Async SMS handling */
	sd_bus_message *pending_sms_msg;
	sd_event_source *sms_timeout_timer;
	uint8_t sms_mr;

	/* AMR-WB / AMR-NB codec state while a call has audio */
	struct imsd_codec_state codec;
	int codec_open;

	/*
	 * Downlink playout. Received frames wait in slots keyed by their RTP
	 * timestamp, and the 20 ms RTP timer decodes exactly one frame per tick,
	 * a few frames behind the newest arrival. A slot that is empty when its
	 * turn comes (DTX between SID frames, a lost or late packet) is decoded
	 * as NO_DATA, so the decoder produces comfort noise or conceals the gap
	 * and the PCM stream never runs dry.
	 */
	struct {
		uint8_t frame[64];
		uint8_t len;
		uint8_t wb;
		uint8_t valid;
		uint32_t ts;
	} playout[IMSD_PLAYOUT_SLOTS];
	int playout_started;
	uint32_t playout_ts;	/* RTP timestamp of the next frame to play */
	uint32_t playout_step;	/* RTP ticks per frame of the codec in use */
	int playout_wb;
	uint64_t playout_late, playout_filled, playout_resyncs;
};

int imsd_sip_init(struct imsd_sip_ctx *ctx, sd_event *event, sd_bus *bus);
void imsd_sip_destroy(struct imsd_sip_ctx *ctx);

int imsd_sip_register(struct imsd_sip_ctx *ctx);
int imsd_sip_send_sms(struct imsd_sip_ctx *ctx, const char *dest_number, const char *text, sd_bus_message *msg);
int imsd_sip_place_call(struct imsd_sip_ctx *ctx, const char *dest_number, uint32_t *out_call_id);
int imsd_sip_answer_call(struct imsd_sip_ctx *ctx);
int imsd_sip_hangup(struct imsd_sip_ctx *ctx);
int imsd_sip_send_dtmf(struct imsd_sip_ctx *ctx, const char *dtmf);
