// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <glib.h>
#include <gio/gio.h>
#include "acs.h"
#include "rcs_config.h"

/*
 * File transfer over HTTP (GSMA RCC.07 3.2.5, TTAK.KO-06.0410/R9 7.4): the
 * file goes to the carrier's content server, the chat carries only the
 * file-info XML the server answers with, and the receiver fetches the file
 * from the URL in it. This part is blocking and has no daemon state, so the
 * tests can drive it directly; ft.c runs it in worker threads.
 */

#define FT_HTTP_CTYPE "application/vnd.gsma.rcs-ft-http+xml"

/* The FileTransfer values of the stored configuration (and Ext's extras). */
struct ft_config {
	int enabled;                 /* ftAuth=1 and an ftHTTPCSURI */
	char cs_uri[256];            /* ftHTTPCSURI */
	char extra_uri[256];         /* ftHTTPExtraCSURI (R9 B.1): above MaxSizeFileTr */
	char user[192], pwd[160];    /* ftHTTPCSUser/Pwd: Digest, both servers. Never logged */
	guint64 max_size;            /* MaxSizeFileTr in bytes, 0 = none given */
	guint64 extra_max;           /* MaxSizeExtraFileTr in bytes, 0 = no limit (R9 table B.1) */
	guint64 warn_size;           /* ftWarnSize */
	guint64 incoming_max;        /* what we accept, 0 = no limit */
	int aut_accept;              /* ftAutAccept */
};
void ft_config_from_xml(const struct acs_xml *x, struct ft_config *out);
/* The server for a file of this size: cs_uri, extra_uri, or NULL (too large). */
const char *ft_upload_uri(const struct ft_config *c, guint64 size);
/* Is url on one of the configured content servers, over https? Only those
 * get our credentials, whatever a peer's file-info says. */
int ft_url_trusted(const struct ft_config *c, const char *url);

/* One <file-info> of the file-info document. */
struct ft_part {
	int present;
	guint64 size;
	char *name;          /* file-name as sent (may be URL-encoded) */
	char *ctype;
	char *url;           /* data url */
	gint64 until;        /* data until, unix seconds; 0 = not given */
};
struct ft_info {
	struct ft_part file, thumb;
};
int ft_info_parse(const char *xml, size_t len, struct ft_info *out, GError **error);
void ft_info_clear(struct ft_info *f);

/* "%EC%9D%8C+1.amr" -> "음 1.amr" -> a name safe to create in a directory:
 * no '/', no leading '.', no control characters, valid UTF-8, at most 200
 * bytes with the extension kept. NULL when nothing is left. */
char *ft_safe_name(const char *sent);
/* As stock sends file names: application/x-www-form-urlencoded. */
char *ft_form_encode(const char *name);

/* An Authorization value for a Digest challenge (RFC 7616: MD5, SHA-256,
 * their -sess, qop auth or none). NULL when the challenge is not one.
 * cnonce NULL: a random one (the tests pass RFC 2617's). */
char *ft_digest(const char *challenge, const char *user, const char *pwd, const char *method,
		const char *uri, const char *cnonce);

/* The upload (stock UploadFileTask): an empty POST, a 401 answered with
 * Digest, then multipart/form-data with tid and File. 0 and the file-info
 * XML, or <0 and why in err. */
struct ft_upload {
	const char *url;
	const char *user, *pwd;   /* NULL: no credentials */
	const char *user_agent;
	int fd;
	guint64 size;
	const char *name;         /* the file name to send (not encoded) */
	const char *ctype;
	const char *tid;
};
int ft_upload_run(const struct rcs_config *cfg, const struct ft_upload *u, GCancellable *cancel,
		  char **xml, size_t *len, char *err, size_t esize);

/* GET url into fd, at most max bytes (0: no limit); a 401 is answered once
 * when user is set. 0, or <0 with err: -EACCES for a 401 we did not answer,
 * -EFBIG for too much. */
int ft_download_run(const struct rcs_config *cfg, const char *url, const char *user, const char *pwd,
		    const char *user_agent, int fd, guint64 max, GCancellable *cancel, char *err,
		    size_t esize);

/*
 * Runs fn with another user's filesystem identity, on this thread only
 * (setfsuid/setfsgid and the raw setgroups syscall are per thread on
 * Linux), then ours again. imsroha-rcs is root: a file a D-Bus caller asks
 * us to send is opened as that caller, a file we store for the user is
 * created as the owner of the download directory. uid == geteuid(): fn runs
 * as is. Returns fn's result, or a negative errno when the switch failed.
 */
struct ft_ident {
	uid_t uid;
	gid_t gid;
	int ngroups;
	gid_t groups[64];
};
int ft_as_user(const struct ft_ident *who, int (*fn)(void *), void *ud);
