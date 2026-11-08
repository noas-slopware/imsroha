// SPDX-License-Identifier: MIT
#define _GNU_SOURCE /* accept4 */
#include "audio.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCK_NAME "audio.sock"
#define FRAME_BYTES (IMSD_AUDIO_FRAME * 2)
/*
 * Uplink frames queued between the session's capture clock and the 20 ms RTP
 * clock. 6 frames is 120 ms: enough to ride out scheduling jitter, short
 * enough that a drifting clock costs at most that much delay before the oldest
 * frame is dropped.
 */
#define UPLINK_QUEUE 6

static sd_event *ev;
static char sock_path[108];
static int listen_fd = -1;
static int client_fd = -1;
static sd_event_source *client_src;
static int in_call;

static int16_t uplink[UPLINK_QUEUE][IMSD_AUDIO_FRAME];
static unsigned int up_head, up_count;

static void send_ctl(char c)
{
	if (client_fd >= 0)
		send(client_fd, &c, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static void drop_client(void)
{
	if (client_src)
		client_src = sd_event_source_unref(client_src);
	if (client_fd >= 0) {
		close(client_fd);
		client_fd = -1;
		/*
		 * The slot is free: touch the socket so a bridge that was refused
		 * (it waits on inotify for IN_ATTRIB/IN_CREATE) tries again now.
		 */
		utimensat(AT_FDCWD, sock_path, NULL, 0);
	}
	up_head = up_count = 0;
}

static int on_client(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	unsigned char buf[1 + FRAME_BYTES];
	(void)s;
	(void)userdata;

	if (revents & (EPOLLHUP | EPOLLERR)) {
		fprintf(stderr, "b2q-imsd: audio client disconnected\n");
		drop_client();
		return 0;
	}

	for (;;) {
		ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			drop_client();
			return 0;
		}
		if (n == 0) {
			fprintf(stderr, "b2q-imsd: audio client disconnected\n");
			drop_client();
			return 0;
		}
		if (n != (ssize_t)sizeof(buf) || buf[0] != 'P' || !in_call)
			continue;

		/* Full queue: drop the oldest frame, keep the newest. */
		if (up_count == UPLINK_QUEUE) {
			up_head = (up_head + 1) % UPLINK_QUEUE;
			up_count--;
		}
		memcpy(uplink[(up_head + up_count) % UPLINK_QUEUE], buf + 1, FRAME_BYTES);
		up_count++;
	}
}

static int on_accept(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	(void)s;
	(void)revents;
	(void)userdata;

	int c = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (c < 0)
		return 0;

	/*
	 * One session at a time, and the one already connected keeps it. A
	 * "newest wins" rule let two bridges (two user managers) kick each other
	 * off in a loop. The refused client waits for the socket to be re-created.
	 */
	if (client_fd >= 0) {
		fprintf(stderr, "b2q-imsd: audio client refused, one is already connected\n");
		close(c);
		return 0;
	}
	client_fd = c;
	if (sd_event_add_io(ev, &client_src, client_fd, EPOLLIN, on_client, NULL) < 0) {
		drop_client();
		return 0;
	}
	fprintf(stderr, "b2q-imsd: audio client connected\n");
	if (in_call)
		send_ctl('S');
	return 0;
}

int imsd_audio_init(sd_event *event)
{
	/* systemd sets RUNTIME_DIRECTORY from RuntimeDirectory=b2q-imsd. */
	const char *dir = getenv("RUNTIME_DIRECTORY");
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	char *path = sock_path;

	if (!dir || !*dir)
		dir = "/run/b2q-imsd";
	if ((size_t)snprintf(path, sizeof(sock_path), "%s/" SOCK_NAME, dir) >= sizeof(sock_path))
		return -ENAMETOOLONG;
	if (mkdir(dir, 0755) < 0 && errno != EEXIST)
		return -errno;

	ev = event;
	listen_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (listen_fd < 0)
		return -errno;

	unlink(path);
	memcpy(sa.sun_path, path, strlen(path) + 1);
	if (bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(listen_fd, 2) < 0) {
		int r = -errno;
		close(listen_fd);
		listen_fd = -1;
		return r;
	}

	/* The user session's audio bridge connects as a member of "audio". */
	struct group *g = getgrnam("audio");
	if (!g || chown(path, 0, g->gr_gid) < 0 || chmod(path, 0660) < 0)
		fprintf(stderr, "b2q-imsd: cannot hand %s to group audio: %m\n", path);

	return sd_event_add_io(ev, NULL, listen_fd, EPOLLIN, on_accept, NULL);
}

void imsd_audio_call_start(void)
{
	in_call = 1;
	up_head = up_count = 0;
	if (client_fd < 0)
		fprintf(stderr, "b2q-imsd: no audio client in the user session, call has no audio\n");
	send_ctl('S');
}

void imsd_audio_call_end(void)
{
	if (!in_call)
		return;
	in_call = 0;
	up_head = up_count = 0;
	send_ctl('E');
}

void imsd_audio_downlink(const int16_t pcm[IMSD_AUDIO_FRAME])
{
	unsigned char buf[1 + FRAME_BYTES];

	if (client_fd < 0 || !in_call)
		return;
	buf[0] = 'P';
	memcpy(buf + 1, pcm, FRAME_BYTES);
	/* A full socket means the session is behind; drop this frame. */
	send(client_fd, buf, sizeof(buf), MSG_DONTWAIT | MSG_NOSIGNAL);
}

int imsd_audio_uplink(int16_t pcm[IMSD_AUDIO_FRAME])
{
	if (!up_count)
		return 0;
	memcpy(pcm, uplink[up_head], FRAME_BYTES);
	up_head = (up_head + 1) % UPLINK_QUEUE;
	up_count--;
	return 1;
}
