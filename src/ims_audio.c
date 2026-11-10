// SPDX-License-Identifier: MIT
/*
 * b2q-ims-audio: call audio for b2q-imsd, run in the user's session.
 *
 * b2q-imsd (a system service) keeps RTP and AMR-WB and exchanges 20 ms PCM
 * frames with this process over /run/b2q-imsd/audio.sock (see audio.h for
 * the protocol). Here the frames go to and from PipeWire through the ALSA
 * "pipewire" PCM, so WirePlumber and callaudiod route them like any other
 * call audio. Nothing is opened between calls.
 *
 * Event-driven: one poll() over the socket, the capture PCM, and an inotify
 * watch that waits for the socket to appear. The only timeout is the short
 * PCM open retry right after a call starts (see try_open()).
 */

#define _GNU_SOURCE
#include <alsa/asoundlib.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define RATE 16000
#define FRAME 320 /* samples per 20 ms */
#define FRAME_BYTES (FRAME * 2)
#define LATENCY_US 60000 /* three frames of ALSA buffer each way */

static const char *sock_dir = "/run/b2q-imsd";
static const char *sock_path = "/run/b2q-imsd/audio.sock";
/*
 * "pipewire", not "default": if the ALSA config ever stopped pointing default
 * at PipeWire, default would open the sound card directly and take it away
 * from PipeWire mid-call. A missing pipewire PCM is just a clean open error.
 */
static const char *pcm_name = "pipewire";

static int sock = -1;
static snd_pcm_t *play, *cap;
static volatile sig_atomic_t quit;

/*
 * A nonblocking read returns whatever is available, often part of a frame, so
 * gather samples until a whole 20 ms frame is there. Sending partial reads as
 * frames would run the uplink faster than real time.
 */
static unsigned char up_buf[1 + FRAME_BYTES] = { 'P' };
static snd_pcm_uframes_t up_fill;

static void on_term(int sig)
{
	(void)sig;
	quit = 1;
}

static snd_pcm_t *open_pcm_once(snd_pcm_stream_t dir, int *last_err)
{
	snd_pcm_t *pcm = NULL;
	int r = snd_pcm_open(&pcm, pcm_name, dir, SND_PCM_NONBLOCK);
	if (r >= 0)
		r = snd_pcm_set_params(pcm, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED,
				       1, RATE, 1, LATENCY_US);
	if (r < 0) {
		*last_err = r;
		if (pcm)
			snd_pcm_close(pcm);
		return NULL;
	}
	return pcm;
}

/*
 * The card profile switches to Voice Call at the same moment as the
 * call-start signal, and the old PipeWire node can disappear before the new
 * one exists. A single open at that instant fails with ENOENT and leaves the
 * direction dead for the whole call. So a failed open is retried from the
 * poll() loop, every OPEN_RETRY_MS for up to OPEN_RETRIES tries (2 s), while
 * downlink frames keep flowing; between calls nothing is retried.
 */
#define OPEN_RETRY_MS 50
#define OPEN_RETRIES 40

static int in_call;
static int open_tries;
static int open_err;
static int64_t open_next_ms;

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int open_pending(void)
{
	return in_call && (!play || !cap) && open_tries < OPEN_RETRIES;
}

static void try_open(void)
{
	if (!play)
		play = open_pcm_once(SND_PCM_STREAM_PLAYBACK, &open_err);
	if (!cap) {
		cap = open_pcm_once(SND_PCM_STREAM_CAPTURE, &open_err);
		if (cap)
			snd_pcm_start(cap);
	}
	open_tries++;
	open_next_ms = now_ms() + OPEN_RETRY_MS;
	if (play && cap)
		fprintf(stderr, "b2q-ims-audio: call audio on (playback ok, capture ok%s)\n",
			open_tries > 1 ? ", after retrying" : "");
	else if (!open_pending())
		fprintf(stderr, "b2q-ims-audio: call audio on (playback %s, capture %s): %s %s\n",
			play ? "ok" : "none", cap ? "ok" : "none", pcm_name, snd_strerror(open_err));
}

static void call_start(void)
{
	in_call = 1;
	open_tries = 0;
	try_open();
}

static void call_end(void)
{
	if (!in_call)
		return;
	in_call = 0;
	open_tries = 0;
	if (play) {
		snd_pcm_drop(play);
		snd_pcm_close(play);
		play = NULL;
	}
	if (cap) {
		snd_pcm_close(cap);
		cap = NULL;
	}
	up_fill = 0;
	fprintf(stderr, "b2q-ims-audio: call audio off\n");
}

static void downlink(const int16_t *pcm)
{
	snd_pcm_sframes_t n;

	if (!play)
		return;
	n = snd_pcm_writei(play, pcm, FRAME);
	if (n == -EAGAIN)
		return; /* buffer full: drop this frame rather than block */
	if (n < 0 && snd_pcm_recover(play, (int)n, 1) == 0)
		snd_pcm_writei(play, pcm, FRAME);
}

static void uplink(void)
{
	snd_pcm_sframes_t n;

	for (;;) {
		n = snd_pcm_readi(cap, up_buf + 1 + up_fill * 2, FRAME - up_fill);
		if (n == -EAGAIN)
			return;
		if (n < 0) {
			if (snd_pcm_recover(cap, (int)n, 1) < 0)
				return;
			snd_pcm_start(cap);
			continue;
		}
		up_fill += n;
		if (up_fill < FRAME)
			continue;
		send(sock, up_buf, sizeof(up_buf), MSG_DONTWAIT | MSG_NOSIGNAL);
		up_fill = 0;
	}
}

static int try_connect(void)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", sock_path);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	fprintf(stderr, "b2q-ims-audio: connected to %s\n", sock_path);
	return fd;
}

/*
 * Wait until the socket can be connected: inotify on its directory for a new
 * socket, and on the parent for the directory itself appearing. With
 * connect_now unset (after a disconnect) the first attempt waits for an event
 * too: b2q-imsd re-creates the socket when it restarts, and connecting again
 * right away to a daemon that just dropped us would only spin.
 */
static int wait_for_socket(int connect_now)
{
	int in = inotify_init1(IN_CLOEXEC);
	char parent[256];
	char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

	if (in < 0)
		return -1;
	snprintf(parent, sizeof(parent), "%s", sock_dir);
	char *slash = strrchr(parent, '/');
	if (slash && slash != parent)
		*slash = '\0';

	inotify_add_watch(in, parent, IN_CREATE | IN_MOVED_TO);
	while (!quit) {
		inotify_add_watch(in, sock_dir, IN_CREATE | IN_MOVED_TO | IN_ATTRIB);
		if (connect_now) {
			sock = try_connect();
			if (sock >= 0)
				break;
		}
		connect_now = 1;
		struct pollfd p = { .fd = in, .events = POLLIN };
		if (poll(&p, 1, -1) < 0 && errno != EINTR)
			break;
		if (p.revents & POLLIN)
			(void)!read(in, buf, sizeof(buf));
	}
	close(in);
	return sock >= 0 ? 0 : -1;
}

static void serve(void)
{
	unsigned char buf[1 + FRAME_BYTES];

	while (!quit) {
		struct pollfd fds[8];
		int nfds = 1;

		fds[0].fd = sock;
		fds[0].events = POLLIN;
		if (cap) {
			int n = snd_pcm_poll_descriptors(cap, fds + 1, 7);
			if (n > 0)
				nfds += n;
		}
		/* Downlink frames arrive every 20 ms, so retry on a deadline, not on idle. */
		int timeout = -1;
		if (open_pending()) {
			int64_t left = open_next_ms - now_ms();
			timeout = left > 0 ? (int)left : 0;
		}
		int r = poll(fds, nfds, timeout);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (open_pending() && now_ms() >= open_next_ms) {
			try_open();
			continue;
		}

		if (fds[0].revents & (POLLHUP | POLLERR))
			break;
		if (fds[0].revents & POLLIN) {
			ssize_t n = recv(sock, buf, sizeof(buf), 0);
			if (n <= 0)
				break;
			if (buf[0] == 'S')
				call_start();
			else if (buf[0] == 'E')
				call_end();
			else if (buf[0] == 'P' && n == (ssize_t)sizeof(buf))
				downlink((const int16_t *)(buf + 1));
		}

		if (cap && nfds > 1) {
			unsigned short revents = 0;
			snd_pcm_poll_descriptors_revents(cap, fds + 1, nfds - 1, &revents);
			if (revents & POLLIN)
				uplink();
		}
	}
}

int main(void)
{
	struct sigaction sa = { .sa_handler = on_term };
	const char *e;

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	setvbuf(stderr, NULL, _IOLBF, 0);

	/* Overrides for testing against a stand-in imsd and a non-PipeWire PCM. */
	if ((e = getenv("B2Q_IMS_AUDIO_DIR")) && *e) {
		static char path[256];
		sock_dir = e;
		snprintf(path, sizeof(path), "%s/audio.sock", e);
		sock_path = path;
	}
	if ((e = getenv("B2Q_IMS_AUDIO_PCM")) && *e)
		pcm_name = e;

	int first = 1;

	while (!quit) {
		if (wait_for_socket(first) < 0)
			break;
		first = 0;
		serve();
		/* imsd went away (restart, new PDN): drop the call and wait again. */
		call_end();
		close(sock);
		sock = -1;
		fprintf(stderr, "b2q-ims-audio: b2q-imsd disconnected\n");
	}
	return 0;
}
