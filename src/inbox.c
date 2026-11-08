// SPDX-License-Identifier: MIT
#include "inbox.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define INBOX_SUBDIR "inbox"
#define PDU_MAX 512 /* "00" + 2 * 176 TPDU bytes fits with room to spare */

static int inbox_fd = -1;
static unsigned int inbox_seq;

int imsd_inbox_init(void)
{
	/* systemd sets STATE_DIRECTORY from StateDirectory=b2q-imsd. */
	const char *state = getenv("STATE_DIRECTORY");
	char path[512];
	int base;

	if (!state || !*state)
		state = "/var/lib/b2q-imsd";
	/* STATE_DIRECTORY may list several paths separated by ':'; use the first. */
	snprintf(path, sizeof(path), "%s", state);
	char *colon = strchr(path, ':');
	if (colon)
		*colon = '\0';

	if (mkdir(path, 0700) < 0 && errno != EEXIST)
		return -errno;
	base = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (base < 0)
		return -errno;
	if (mkdirat(base, INBOX_SUBDIR, 0700) < 0 && errno != EEXIST) {
		int r = -errno;
		close(base);
		return r;
	}
	inbox_fd = openat(base, INBOX_SUBDIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	close(base);
	if (inbox_fd < 0)
		return -errno;

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	inbox_seq = (unsigned int)ts.tv_nsec & 0xffffff;
	return 0;
}

static int valid_id(const char *id)
{
	if (strlen(id) != IMSD_INBOX_ID_LEN - 1 || id[16] != '-')
		return 0;
	for (size_t i = 0; i < IMSD_INBOX_ID_LEN - 1; i++) {
		if (i == 16)
			continue;
		if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
			return 0;
	}
	return 1;
}

int imsd_inbox_store(const char *pdu_hex, char id[IMSD_INBOX_ID_LEN])
{
	struct timespec ts;
	char tmp[IMSD_INBOX_ID_LEN + 5];
	size_t len = strlen(pdu_hex);
	int fd, r = 0;

	if (inbox_fd < 0)
		return -EBADF;

	clock_gettime(CLOCK_REALTIME, &ts);
	snprintf(id, IMSD_INBOX_ID_LEN, "%016llx-%06x",
		 (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec,
		 inbox_seq++ & 0xffffff);
	snprintf(tmp, sizeof(tmp), "%s.tmp", id);

	fd = openat(inbox_fd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	if (write(fd, pdu_hex, len) != (ssize_t)len || fsync(fd) < 0)
		r = errno ? -errno : -EIO;
	if (close(fd) < 0 && !r)
		r = -errno;
	if (!r && renameat(inbox_fd, tmp, inbox_fd, id) < 0)
		r = -errno;
	if (!r && fsync(inbox_fd) < 0)
		r = -errno;
	if (r)
		unlinkat(inbox_fd, tmp, 0);
	return r;
}

int imsd_inbox_remove(const char *id)
{
	if (inbox_fd < 0)
		return -EBADF;
	if (!valid_id(id))
		return -EINVAL;
	if (unlinkat(inbox_fd, id, 0) < 0)
		return -errno;
	return fsync(inbox_fd) < 0 ? -errno : 0;
}

static int by_name(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

int imsd_inbox_for_each(int (*cb)(const char *id, const char *pdu_hex, void *userdata),
			void *userdata)
{
	char **names = NULL;
	size_t n = 0, cap = 0;
	int r = 0;

	if (inbox_fd < 0)
		return -EBADF;

	int dfd = dup(inbox_fd);
	if (dfd < 0)
		return -errno;
	DIR *dir = fdopendir(dfd);
	if (!dir) {
		r = -errno;
		close(dfd);
		return r;
	}
	rewinddir(dir);

	struct dirent *de;
	while ((de = readdir(dir))) {
		if (!valid_id(de->d_name))
			continue; /* ".", "..", leftover *.tmp from a crash mid-write */
		if (n == cap) {
			cap = cap ? 2 * cap : 16;
			char **grown = realloc(names, cap * sizeof(*names));
			if (!grown) {
				r = -ENOMEM;
				goto out;
			}
			names = grown;
		}
		names[n] = strdup(de->d_name);
		if (!names[n]) {
			r = -ENOMEM;
			goto out;
		}
		n++;
	}
	qsort(names, n, sizeof(*names), by_name);

	for (size_t i = 0; i < n && r >= 0; i++) {
		char pdu[PDU_MAX + 1];
		int fd = openat(inbox_fd, names[i], O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;
		ssize_t got = read(fd, pdu, PDU_MAX);
		close(fd);
		if (got <= 0)
			continue;
		pdu[got] = '\0';
		r = cb(names[i], pdu, userdata);
	}
out:
	for (size_t i = 0; i < n; i++)
		free(names[i]);
	free(names);
	closedir(dir);
	return r < 0 ? r : 0;
}
