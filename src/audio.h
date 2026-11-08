#pragma once

#include <stdint.h>
#include <systemd/sd-event.h>

/*
 * Call audio hand-off to the user session.
 *
 * b2q-imsd runs as a system service and keeps RTP and the AMR-WB codec. The
 * PCM goes over a SOCK_SEQPACKET socket, /run/b2q-imsd/audio.sock (root:audio,
 * 0660), to b2q-ims-audio in the user's session, which plays and records it
 * through PipeWire. One datagram per message:
 *
 *   'S'                call audio starts: open playback and capture
 *   'E'                call audio ends: close them
 *   'P' + 640 bytes    one 20 ms frame, S16LE, 16 kHz, mono
 *                      (imsd -> client: downlink; client -> imsd: uplink)
 */

#define IMSD_AUDIO_RATE 16000
#define IMSD_AUDIO_FRAME 320 /* samples per 20 ms */

int imsd_audio_init(sd_event *event);
void imsd_audio_call_start(void);
void imsd_audio_call_end(void);
void imsd_audio_downlink(const int16_t pcm[IMSD_AUDIO_FRAME]);
/* Returns 1 and fills pcm when an uplink frame is queued, 0 otherwise. */
int imsd_audio_uplink(int16_t pcm[IMSD_AUDIO_FRAME]);
