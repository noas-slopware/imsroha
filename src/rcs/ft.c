// SPDX-License-Identifier: GPL-3.0-only
/*
 * File transfer over HTTP in the daemon (RCC.07 3.2.5, R9 7.4.1.1): SendFile
 * uploads to the content server and sends the file-info it answers with as a
 * chat message; a file-info that comes in a chat is fetched into the
 * download directory and announced with FileReceived. The HTTP work blocks,
 * so every transfer runs in a worker thread and ends on the main loop.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cpim.h"
#include "fthttp.h"
#include "rcsd.h"
#include "sipua.h"

/* Neither the configuration nor the file-info says how big: no more than this. */
#define FT_HARD_MAX (1024ull << 20)
#define FT_THUMB_MAX (4u << 20)

struct ft_job {
	struct rcsd *r;
	GCancellable *cancel;
	char number[32];
	char id[64];
	char ua[256];
	/* A copy: a new registration reloads r->ft while workers run. The
	 * credentials in it go only to the servers it names (ft_url_trusted). */
	struct ft_config ft;

	/* upload */
	int fd;
	guint64 size;
	char *url, *name, *ctype;
	char tid[40];
	char *xml;
	size_t xml_len;

	/* download */
	struct ft_info info;
	gint64 ts_ms;
	guint64 max;
	char *dir;                  /* where the files land, for the signal */
	char *base, *sub;           /* dir = base/sub; sub is created as the owner */
	struct ft_ident owner;
	int has_owner;
	char *path, *thumb;
	guint64 got;

	int result;
	const char *reason;         /* FileReceiveFailed's */
	char err[320];
};

static GList *jobs;

static void job_free(struct ft_job *j)
{
	jobs = g_list_remove(jobs, j);
	if (j->fd >= 0)
		close(j->fd);
	g_clear_object(&j->cancel);
	memset(&j->ft, 0, sizeof(j->ft));
	g_free(j->url);
	g_free(j->name);
	g_free(j->ctype);
	g_free(j->xml);
	ft_info_clear(&j->info);
	g_free(j->dir);
	g_free(j->base);
	g_free(j->sub);
	g_free(j->path);
	g_free(j->thumb);
	g_free(j);
}

static struct ft_job *job_new(struct rcsd *r)
{
	struct ft_job *j = g_new0(struct ft_job, 1);
	j->r = r;
	j->fd = -1;
	j->cancel = g_cancellable_new();
	rcs_config_expand_ua(&r->cfg, r->cfg.http_user_agent, j->ua, sizeof(j->ua));
	j->ft = r->ft;
	jobs = g_list_prepend(jobs, j);
	return j;
}

/* ftHTTPCSUser for this URL, or NULL: only our content servers get it. */
static const char *user_for(const struct ft_job *j, const char *url)
{
	return j->ft.user[0] && ft_url_trusted(&j->ft, url) ? j->ft.user : NULL;
}

void rcsd_ft_load(struct rcsd *r)
{
	ft_config_from_xml(r->xml, &r->ft);
	if (!r->ft.enabled) {
		fprintf(stderr, "imsroha-rcs: file transfer: not provisioned (ftAuth, ftHTTPCSURI)\n");
		return;
	}
	/* The URIs are no secret; ftHTTPCSUser/Pwd are and never get here. */
	fprintf(stderr, "imsroha-rcs: file transfer over HTTP to %s up to %" G_GUINT64_FORMAT " KB",
		r->ft.cs_uri, r->ft.max_size / 1024);
	if (r->ft.extra_uri[0])
		fprintf(stderr, ", %s above that", r->ft.extra_uri);
	fprintf(stderr, "%s\n", r->ft.user[0] ? ", with credentials" : "");
}

void rcsd_ft_shutdown(struct rcsd *r)
{
	(void)r;
	for (GList *l = jobs; l; l = l->next)
		g_cancellable_cancel(((struct ft_job *)l->data)->cancel);
}

/* ---- sending ---------------------------------------------------------------- */

static void upload_thread(GTask *t, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)src;
	struct ft_job *j = data;
	struct ft_upload u = {
		.url = j->url, .user = user_for(j, j->url), .pwd = j->ft.pwd,
		.user_agent = j->ua, .fd = j->fd, .size = j->size, .name = j->name, .ctype = j->ctype,
		.tid = j->tid,
	};
	j->result = ft_upload_run(&j->r->cfg, &u, cancel, &j->xml, &j->xml_len, j->err, sizeof(j->err));
	g_task_return_boolean(t, TRUE);
}

static void upload_done(GObject *src, GAsyncResult *res, gpointer p)
{
	(void)src; (void)res;
	struct ft_job *j = p;
	struct rcsd *r = j->r;
	if (j->result < 0) {
		fprintf(stderr, "imsroha-rcs: file %s to %s: upload failed: %s\n", j->id, j->number, j->err);
		rcsd_dbus_status(r, j->id, "failed");
		job_free(j);
		return;
	}
	fprintf(stderr, "imsroha-rcs: file %s to %s: uploaded, sending the file-info\n", j->id, j->number);
	/* The server's file-info goes out as it came (R9 7.4.1.1.1's example). */
	size_t len;
	char *body = cpim_message(j->id, FT_HTTP_CTYPE ";charset=UTF-8", j->xml, &len);
	GError *e = NULL;
	if (!rcsd_chat_enqueue(r, j->number, j->id, body, len, &e)) {
		fprintf(stderr, "imsroha-rcs: file %s: %s\n", j->id, e->message);
		g_error_free(e);
		rcsd_dbus_status(r, j->id, "failed");
	}
	job_free(j);
}

struct open_req {
	const char *path;
	int fd;
};

static int open_fn(void *p)
{
	struct open_req *o = p;
	/* O_NONBLOCK: a FIFO must not hold us in open(); only regular files go on. */
	o->fd = open(o->path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
	return o->fd < 0 ? -errno : 0;
}

/* The caller's identity from the bus, for opening the file as them. */
static int caller_ident(GVariant *creds, struct ft_ident *id)
{
	GVariant *d = g_variant_get_child_value(creds, 0);
	guint32 uid;
	int ok = g_variant_lookup(d, "UnixUserID", "u", &uid);
	memset(id, 0, sizeof(*id));
	id->uid = uid;
	GVariant *gs = ok ? g_variant_lookup_value(d, "UnixGroupIDs", G_VARIANT_TYPE("au")) : NULL;
	g_variant_unref(d);
	if (!ok)
		return -EPERM;
	if (uid == geteuid()) {
		if (gs)
			g_variant_unref(gs);
		return 0;
	}
	struct passwd pw, *pp = NULL;
	char buf[2048];
	getpwuid_r(uid, &pw, buf, sizeof(buf), &pp);
	if (gs) {
		gsize n;
		const guint32 *v = g_variant_get_fixed_array(gs, &n, sizeof(guint32));
		id->ngroups = (int)MIN(n, G_N_ELEMENTS(id->groups));
		for (int i = 0; i < id->ngroups; i++)
			id->groups[i] = v[i];
		g_variant_unref(gs);
		if (pp)
			id->gid = pp->pw_gid;
		else if (id->ngroups)
			id->gid = id->groups[0];
		else
			return -EPERM;
		return 0;
	}
	/* An older bus: the groups the user database gives. */
	if (!pp)
		return -EPERM;
	id->gid = pp->pw_gid;
	int n = G_N_ELEMENTS(id->groups);
	if (getgrouplist(pp->pw_name, pp->pw_gid, id->groups, &n) < 0)
		return -EPERM;
	id->ngroups = n;
	return 0;
}

struct send_req {
	struct rcsd *r;
	GDBusMethodInvocation *inv;
	char number[32];
	char *path;
};

static void send_fail(struct send_req *s, const char *err, const char *fmt, ...) G_GNUC_PRINTF(3, 4);
static void send_fail(struct send_req *s, const char *err, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char *m = g_strdup_vprintf(fmt, ap);
	va_end(ap);
	g_dbus_method_invocation_return_dbus_error(s->inv, err, m);
	g_free(m);
}

static const char *guess_type(const char *name, int fd)
{
	guchar head[512];
	ssize_t n = pread(fd, head, sizeof(head), 0);
	gboolean uncertain;
	char *ct = g_content_type_guess(name, n > 0 ? head : NULL, n > 0 ? (gsize)n : 0, &uncertain);
	char *mime = ct ? g_content_type_get_mime_type(ct) : NULL;
	g_free(ct);
	static char out[128];
	g_strlcpy(out, mime && *mime ? mime : "application/octet-stream", sizeof(out));
	g_free(mime);
	return out;
}

static void on_creds(GObject *src, GAsyncResult *res, gpointer p)
{
	struct send_req *s = p;
	struct rcsd *r = s->r;
	GError *e = NULL;
	GVariant *v = g_dbus_connection_call_finish(G_DBUS_CONNECTION(src), res, &e);
	struct ft_ident who;
	if (!v || caller_ident(v, &who) < 0) {
		send_fail(s, RCSD_ERROR_FAILED, "cannot tell who is asking%s%s", e ? ": " : "", e ? e->message : "");
		g_clear_error(&e);
		goto out;
	}
	if (!r->ua || !sipua_registered(r->ua) || !r->ft.enabled) {
		send_fail(s, RCSD_ERROR_NOT_READY, "RCS is not registered (%s)", rcsd_state_name(r->state));
		goto out;
	}
	/* imsroha-rcs is root: the file is opened with the caller's rights, not ours. */
	struct open_req o = { .path = s->path, .fd = -1 };
	int err = ft_as_user(&who, open_fn, &o);
	struct stat st;
	if (err < 0 || fstat(o.fd, &st) < 0) {
		send_fail(s, RCSD_ERROR_FAILED, "%s: %s", s->path, g_strerror(err < 0 ? -err : errno));
		if (o.fd >= 0)
			close(o.fd);
		goto out;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0) {
		send_fail(s, RCSD_ERROR_FAILED, "%s: not a regular file with something in it", s->path);
		close(o.fd);
		goto out;
	}
	fcntl(o.fd, F_SETFL, fcntl(o.fd, F_GETFL) & ~O_NONBLOCK);
	guint64 size = (guint64)st.st_size;
	const char *url = ft_upload_uri(&r->ft, size);
	if (!url) {
		send_fail(s, RCSD_ERROR_FAILED, "%s: %" G_GUINT64_FORMAT " bytes is more than the carrier takes", s->path,
			  size);
		close(o.fd);
		goto out;
	}
	struct ft_job *j = job_new(r);
	j->fd = o.fd;
	j->size = size;
	j->url = g_strdup(url);
	char *base = g_path_get_basename(s->path);
	j->name = base;
	j->ctype = g_strdup(guess_type(base, j->fd));
	char *tid = g_uuid_string_random();
	g_strlcpy(j->tid, tid, sizeof(j->tid));
	g_free(tid);
	cpim_msg_id(j->id, sizeof(j->id));
	g_strlcpy(j->number, s->number, sizeof(j->number));
	fprintf(stderr, "imsroha-rcs: file %s to %s: %" G_GUINT64_FORMAT " bytes of %s, uploading\n", j->id, j->number,
		size, j->ctype);
	g_dbus_method_invocation_return_value(s->inv, g_variant_new("(s)", j->id));
	GTask *t = g_task_new(NULL, j->cancel, upload_done, j);
	g_task_set_task_data(t, j, NULL);
	g_task_run_in_thread(t, upload_thread);
	g_object_unref(t);
out:
	if (v)
		g_variant_unref(v);
	g_free(s->path);
	g_free(s);
}

void rcsd_ft_send(struct rcsd *r, const char *sender, const char *number, const char *path,
		  GDBusMethodInvocation *inv)
{
	if (!r->ua || !sipua_registered(r->ua)) {
		g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_NOT_READY, "RCS is not registered");
		return;
	}
	if (!r->ft.enabled) {
		g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_FAILED,
							   "file transfer is not provisioned for this SIM");
		return;
	}
	struct send_req *s = g_new0(struct send_req, 1);
	s->r = r;
	s->inv = inv;
	if (sipua_e164(r->ua, number, s->number, sizeof(s->number)) < 0 || !g_path_is_absolute(path) || !sender) {
		g_dbus_method_invocation_return_dbus_error(inv, RCSD_ERROR_FAILED,
							   !sender ? "no sender" : !g_path_is_absolute(path)
							   ? "the path must be absolute" : "not a phone number");
		g_free(s);
		return;
	}
	s->path = g_strdup(path);
	g_dbus_connection_call(g_dbus_method_invocation_get_connection(inv), "org.freedesktop.DBus",
			       "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionCredentials",
			       g_variant_new("(s)", sender), G_VARIANT_TYPE("(a{sv})"), G_DBUS_CALL_FLAGS_NONE, 5000,
			       NULL, on_creds, s);
}

/* ---- receiving ---------------------------------------------------------------- */

/* Message-IDs come from the peer: only these characters go into a file name. */
static void safe_id(const char *id, char *out, size_t size)
{
	size_t n = 0;
	for (const char *p = id; *p && n + 1 < size; p++)
		if (g_ascii_isalnum(*p) || *p == '-' || *p == '_')
			out[n++] = *p;
	out[n] = '\0';
	if (!n)
		snprintf(out, size, "x%08x", g_random_int());
}

struct mkdir_req {
	struct ft_job *j;
	int dirfd;
};

static int dir_fn(void *p)
{
	struct mkdir_req *m = p;
	int base = open(m->j->base, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (base < 0)
		return -errno;
	if (mkdirat(base, m->j->sub, 0700) < 0 && errno != EEXIST) {
		int e = -errno;
		close(base);
		return e;
	}
	m->dirfd = openat(base, m->j->sub, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	int e = m->dirfd < 0 ? -errno : 0;
	close(base);
	return e;
}

struct create_req {
	int dirfd;
	const char *name;
	int fd;
};

static int create_fn(void *p)
{
	struct create_req *c = p;
	c->fd = openat(c->dirfd, c->name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (c->fd < 0 && errno == EEXIST) {
		/* A part file left by an earlier run. */
		unlinkat(c->dirfd, c->name, 0);
		c->fd = openat(c->dirfd, c->name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	}
	return c->fd < 0 ? -errno : 0;
}

/* name, then "stem (2).ext", "stem (3).ext"...: never over an existing file. */
static char *settle(int dirfd, const char *part, const char *name)
{
	const char *dot = strrchr(name, '.');
	if (dot == name)
		dot = NULL;
	for (int i = 1; i < 1000; i++) {
		char *cand = i == 1 ? g_strdup(name)
				    : g_strdup_printf("%.*s (%d)%s", dot ? (int)(dot - name) : (int)strlen(name), name, i,
						      dot ? dot : "");
		int rc = renameat2(dirfd, part, dirfd, cand, RENAME_NOREPLACE);
		if (rc < 0 && (errno == EINVAL || errno == ENOSYS)) {
			/* A filesystem without RENAME_NOREPLACE: link() refuses an existing name too. */
			rc = linkat(dirfd, part, dirfd, cand, 0);
			if (rc == 0)
				unlinkat(dirfd, part, 0);
		}
		if (rc == 0)
			return cand;
		g_free(cand);
		if (errno != EEXIST)
			return NULL;
	}
	return NULL;
}

/* One URL into dirfd/name; the final name (g_free) or NULL with j->err. */
static char *fetch(struct ft_job *j, int dirfd, const char *url, const char *part, const char *name,
		   guint64 max, GCancellable *cancel, int *result)
{
	struct create_req c = { .dirfd = dirfd, .name = part, .fd = -1 };
	int e = ft_as_user(j->has_owner ? &j->owner : NULL, create_fn, &c);
	if (e < 0) {
		snprintf(j->err, sizeof(j->err), "%s/%s: %s", j->dir, part, g_strerror(-e));
		*result = e;
		return NULL;
	}
	e = ft_download_run(&j->r->cfg, url, user_for(j, url), j->ft.pwd, j->ua, c.fd, max, cancel, j->err,
			    sizeof(j->err));
	struct stat st;
	if (e == 0 && (fsync(c.fd) < 0 || fstat(c.fd, &st) < 0))
		e = -errno;
	close(c.fd);
	char *final = NULL;
	if (e == 0 && !(final = settle(dirfd, part, name))) {
		e = -errno;
		snprintf(j->err, sizeof(j->err), "%s/%s: %s", j->dir, name, g_strerror(errno));
	}
	if (e < 0) {
		unlinkat(dirfd, part, 0);
		*result = e;
		return NULL;
	}
	j->got = (guint64)st.st_size;
	*result = 0;
	return final;
}

static const char *thumb_ext(const char *ctype)
{
	static const char *const map[][2] = {
		{ "image/jpeg", "jpg" }, { "image/png", "png" }, { "image/gif", "gif" },
		{ "image/bmp", "bmp" }, { "image/webp", "webp" },
	};
	for (size_t i = 0; ctype && i < G_N_ELEMENTS(map); i++)
		if (!g_ascii_strcasecmp(ctype, map[i][0]))
			return map[i][1];
	return "img";
}

static void download_thread(GTask *t, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)src;
	struct ft_job *j = data;
	struct mkdir_req m = { .j = j, .dirfd = -1 };
	int e = ft_as_user(j->has_owner ? &j->owner : NULL, dir_fn, &m);
	if (e < 0) {
		snprintf(j->err, sizeof(j->err), "%s: %s", j->dir, g_strerror(-e));
		j->result = e;
		j->reason = "failed";
		g_task_return_boolean(t, TRUE);
		return;
	}
	char sid[48], part[64];
	safe_id(j->id, sid, sizeof(sid));

	/* The thumbnail first: small, and the app can show it while the file comes. */
	const struct ft_part *th = &j->info.thumb;
	if (th->present && th->url && (!th->size || th->size <= FT_THUMB_MAX)) {
		snprintf(part, sizeof(part), ".%s.thumb.part", sid);
		char *tname = g_strdup_printf("thumb-%s.%s", sid, thumb_ext(th->ctype));
		int tr;
		char *got = fetch(j, m.dirfd, th->url, part, tname, th->size ? th->size : FT_THUMB_MAX, cancel, &tr);
		g_free(tname);
		if (got) {
			j->thumb = g_build_filename(j->dir, got, NULL);
			g_free(got);
		} else {
			fprintf(stderr, "imsroha-rcs: file %s: no thumbnail: %s\n", j->id, j->err);
			j->err[0] = '\0';
		}
	}

	const struct ft_part *fp = &j->info.file;
	char *name = ft_safe_name(fp->name);
	if (!name)
		name = g_strdup_printf("file-%s", sid);
	snprintf(part, sizeof(part), ".%s.part", sid);
	char *got = fetch(j, m.dirfd, fp->url, part, name, j->max, cancel, &j->result);
	g_free(name);
	close(m.dirfd);
	if (got) {
		j->path = g_build_filename(j->dir, got, NULL);
		g_free(got);
	} else {
		j->reason = j->result == -EACCES ? "unauthorized" : j->result == -EFBIG ? "too-large"
			    : j->result == -ENOENT ? "gone" : "failed";
	}
	g_task_return_boolean(t, TRUE);
}

static void download_done(GObject *src, GAsyncResult *res, gpointer p)
{
	(void)src; (void)res;
	struct ft_job *j = p;
	if (j->result < 0) {
		fprintf(stderr, "imsroha-rcs: file %s from %s: %s (%s)\n", j->id, j->number, j->reason, j->err);
		rcsd_dbus_file_failed(j->r, j->number, j->id, j->reason);
	} else {
		fprintf(stderr, "imsroha-rcs: file %s from %s: %" G_GUINT64_FORMAT " bytes in %s\n", j->id, j->number,
			j->got, j->path);
		rcsd_dbus_file_received(j->r, j->number, j->id, j->path,
					j->info.file.ctype ? j->info.file.ctype : "application/octet-stream", j->got,
					j->thumb, j->ts_ms);
	}
	job_free(j);
}

/* Where received files go: [rcs] download-dir/<IMSI>, created as that
 * directory's owner, or the state directory (root's alone). */
static int place(struct ft_job *j)
{
	struct rcsd *r = j->r;
	if (r->cfg.download_dir[0]) {
		struct stat st;
		if (stat(r->cfg.download_dir, &st) < 0)
			return -errno;
		if (!S_ISDIR(st.st_mode))
			return -ENOTDIR;
		j->base = g_strdup(r->cfg.download_dir);
		j->sub = g_strdup(r->id.imsi);
		if (st.st_uid != geteuid()) {
			j->has_owner = 1;
			j->owner.uid = st.st_uid;
			j->owner.gid = st.st_gid;
			j->owner.ngroups = 1;
			j->owner.groups[0] = st.st_gid;
		}
	} else {
		j->base = g_build_filename(r->cfg.state_dir, r->id.imsi, NULL);
		j->sub = g_strdup("files");
		if (g_mkdir_with_parents(j->base, 0700) < 0)
			return -errno;
	}
	j->dir = g_build_filename(j->base, j->sub, NULL);
	return 0;
}

void rcsd_ft_received(struct rcsd *r, const char *number, const char *id, const char *xml, size_t len,
		      gint64 ts_ms)
{
	struct ft_info fi;
	GError *e = NULL;
	if (ft_info_parse(xml, len, &fi, &e) < 0) {
		fprintf(stderr, "imsroha-rcs: file %s from %s: unusable file-info: %s\n", id, number, e->message);
		g_error_free(e);
		rcsd_dbus_file_failed(r, number, id, "invalid");
		return;
	}
	const char *reason = NULL;
	gint64 now = (gint64)time(NULL);
	if (fi.file.until && fi.file.until <= now)
		reason = "expired";
	else if (r->ft.incoming_max && fi.file.size > r->ft.incoming_max)
		reason = "too-large";
	if (reason) {
		/* Not even a connection: the server would only say 404, or send too much. */
		fprintf(stderr, "imsroha-rcs: file %s from %s: %s, not fetched\n", id, number, reason);
		rcsd_dbus_file_failed(r, number, id, reason);
		ft_info_clear(&fi);
		return;
	}
	struct ft_job *j = job_new(r);
	j->info = fi;
	j->ts_ms = ts_ms;
	g_strlcpy(j->number, number, sizeof(j->number));
	g_strlcpy(j->id, id, sizeof(j->id));
	/* The limit counts what arrives, not what the file-info claims. */
	j->max = r->ft.incoming_max ? r->ft.incoming_max : fi.file.size ? fi.file.size : FT_HARD_MAX;
	int pe = place(j);
	if (pe < 0) {
		fprintf(stderr, "imsroha-rcs: file %s: download directory %s: %s\n", id,
			r->cfg.download_dir[0] ? r->cfg.download_dir : r->cfg.state_dir, g_strerror(-pe));
		rcsd_dbus_file_failed(r, number, id, "failed");
		job_free(j);
		return;
	}
	fprintf(stderr, "imsroha-rcs: file %s from %s: %" G_GUINT64_FORMAT " bytes of %s, fetching\n", id, number,
		fi.file.size, fi.file.ctype ? fi.file.ctype : "?");
	GTask *t = g_task_new(NULL, j->cancel, download_done, j);
	g_task_set_task_data(t, j, NULL);
	g_task_run_in_thread(t, download_thread);
	g_object_unref(t);
}
