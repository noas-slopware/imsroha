// SPDX-License-Identifier: GPL-3.0-only
#include "cert.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <glib/gstdio.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#define CERT_FILE "msrp-cert.pem"
#define CERT_BITS 2048
#define CERT_DAYS 365
/* made again this long before it expires */
#define CERT_RENEW_DAYS 30

G_LOCK_DEFINE_STATIC(cur);
static GTlsCertificate *cur;
static char cur_fp[3 * 20 + 8];
static char cur_aor[256];

static int fail(GError **error, int gerr, const char *what)
{
	g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "MSRP certificate: %s: %s",
		    what, gnutls_strerror(gerr));
	return -EIO;
}

/* "SHA-1 AA:BB:..." of the DER certificate */
static int fingerprint(gnutls_x509_crt_t crt, char *out, size_t size, GError **error)
{
	unsigned char d[20];
	size_t n = sizeof(d);
	int r = gnutls_x509_crt_get_fingerprint(crt, GNUTLS_DIG_SHA1, d, &n);
	if (r < 0)
		return fail(error, r, "fingerprint");
	GString *s = g_string_new("SHA-1 ");
	for (size_t i = 0; i < n; i++)
		g_string_append_printf(s, i ? ":%02X" : "%02X", d[i]);
	g_strlcpy(out, s->str, size);
	g_string_free(s, TRUE);
	return 0;
}

/* The stored certificate, if it is for aor and not close to expiring. */
static int load(const char *path, const char *aor, char **pem_out, char *fp, size_t fpsize)
{
	char *pem = NULL;
	gsize len = 0;
	if (!g_file_get_contents(path, &pem, &len, NULL))
		return -ENOENT;
	gnutls_datum_t d = { (unsigned char *)pem, (unsigned)len };
	gnutls_x509_crt_t crt;
	int ok = 0;
	if (gnutls_x509_crt_init(&crt) == 0) {
		if (gnutls_x509_crt_import(crt, &d, GNUTLS_X509_FMT_PEM) == 0) {
			/* the SAN, not the CN: a DN comes back escaped ("\+82...") */
			char san[256];
			size_t sanl = sizeof(san) - 1;
			time_t exp = gnutls_x509_crt_get_expiration_time(crt);
			if (gnutls_x509_crt_get_subject_alt_name(crt, 0, san, &sanl, NULL) == GNUTLS_SAN_URI &&
			    sanl == strlen(aor) && !memcmp(san, aor, sanl) && exp > time(NULL) + CERT_RENEW_DAYS * 86400 &&
			    fingerprint(crt, fp, fpsize, NULL) == 0)
				ok = 1;
		}
		gnutls_x509_crt_deinit(crt);
	}
	if (!ok) {
		g_free(pem);
		return -ESTALE;
	}
	*pem_out = pem;
	return 0;
}

/* A new self-signed certificate for aor, written to path with its key (0600). */
static int make(const char *path, const char *aor, char **pem_out, char *fp, size_t fpsize, GError **error)
{
	gnutls_x509_privkey_t key = NULL;
	gnutls_x509_crt_t crt = NULL;
	gnutls_datum_t kpem = { 0 }, cpem = { 0 };
	int r, ret = -EIO;

	if ((r = gnutls_x509_privkey_init(&key)) < 0 ||
	    (r = gnutls_x509_privkey_generate(key, GNUTLS_PK_RSA, CERT_BITS, 0)) < 0) {
		ret = fail(error, r, "key");
		goto out;
	}
	if ((r = gnutls_x509_crt_init(&crt)) < 0) {
		ret = fail(error, r, "certificate");
		goto out;
	}
	unsigned char serial[16];
	if ((r = gnutls_rnd(GNUTLS_RND_NONCE, serial, sizeof(serial))) < 0) {
		ret = fail(error, r, "serial");
		goto out;
	}
	serial[0] &= 0x7f; /* positive */
	time_t now = time(NULL);
	if ((r = gnutls_x509_crt_set_version(crt, 3)) < 0 ||
	    (r = gnutls_x509_crt_set_serial(crt, serial, sizeof(serial))) < 0 ||
	    (r = gnutls_x509_crt_set_activation_time(crt, now - 86400)) < 0 ||
	    (r = gnutls_x509_crt_set_expiration_time(crt, now + (time_t)CERT_DAYS * 86400)) < 0 ||
	    (r = gnutls_x509_crt_set_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, aor, strlen(aor))) < 0 ||
	    (r = gnutls_x509_crt_set_subject_alt_name(crt, GNUTLS_SAN_URI, aor, strlen(aor),
						      GNUTLS_FSAN_SET)) < 0 ||
	    (r = gnutls_x509_crt_set_key(crt, key)) < 0 ||
	    (r = gnutls_x509_crt_set_key_usage(crt, GNUTLS_KEY_DIGITAL_SIGNATURE |
						     GNUTLS_KEY_KEY_ENCIPHERMENT)) < 0 ||
	    (r = gnutls_x509_crt_set_key_purpose_oid(crt, GNUTLS_KP_TLS_WWW_CLIENT, 0)) < 0 ||
	    (r = gnutls_x509_crt_set_key_purpose_oid(crt, GNUTLS_KP_TLS_WWW_SERVER, 0)) < 0 ||
	    (r = gnutls_x509_crt_sign2(crt, crt, key, GNUTLS_DIG_SHA256, 0)) < 0) {
		ret = fail(error, r, "signing");
		goto out;
	}
	if ((r = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_PEM, &cpem)) < 0 ||
	    (r = gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_PEM, &kpem)) < 0) {
		ret = fail(error, r, "export");
		goto out;
	}
	if (fingerprint(crt, fp, fpsize, error) < 0)
		goto out;

	char *pem = g_strdup_printf("%.*s%.*s", (int)cpem.size, cpem.data, (int)kpem.size, kpem.data);
	char *tmp = g_strconcat(path, ".tmp", NULL);
	int fd = g_open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	size_t plen = strlen(pem);
	if (fd < 0 || write(fd, pem, plen) != (ssize_t)plen || fsync(fd) < 0 || close(fd) < 0 ||
	    g_rename(tmp, path) < 0) {
		int e = errno;
		if (fd >= 0)
			close(fd);
		g_unlink(tmp);
		g_set_error(error, G_IO_ERROR, g_io_error_from_errno(e), "MSRP certificate: %s: %s",
			    path, g_strerror(e));
		g_free(tmp);
		g_free(pem);
		ret = -e;
		goto out;
	}
	g_free(tmp);
	*pem_out = pem;
	ret = 0;
out:
	gnutls_free(cpem.data);
	gnutls_free(kpem.data);
	if (crt)
		gnutls_x509_crt_deinit(crt);
	if (key)
		gnutls_x509_privkey_deinit(key);
	return ret;
}

int rcs_cert_ensure(const char *dir, const char *aor, GError **error)
{
	if (cur && !strcmp(cur_aor, aor))
		return 0;

	char *path = g_build_filename(dir, CERT_FILE, NULL);
	char *pem = NULL;
	char fp[sizeof(cur_fp)];
	int r = load(path, aor, &pem, fp, sizeof(fp));
	if (r < 0) {
		if (g_mkdir_with_parents(dir, 0700) < 0) {
			int e = errno;
			g_set_error(error, G_IO_ERROR, g_io_error_from_errno(e), "MSRP certificate: %s: %s",
				    dir, g_strerror(e));
			g_free(path);
			return -e;
		}
		r = make(path, aor, &pem, fp, sizeof(fp), error);
		if (r < 0) {
			g_free(path);
			return r;
		}
		fprintf(stderr, "imsroha-rcs: new MSRP certificate, %s\n", fp);
	}
	g_free(path);

	GTlsCertificate *c = g_tls_certificate_new_from_pem(pem, -1, error);
	g_free(pem);
	if (!c)
		return -EINVAL;
	G_LOCK(cur);
	g_clear_object(&cur);
	cur = c;
	G_UNLOCK(cur);
	g_strlcpy(cur_fp, fp, sizeof(cur_fp));
	g_strlcpy(cur_aor, aor, sizeof(cur_aor));
	return 0;
}

GTlsCertificate *rcs_cert_get(void)
{
	G_LOCK(cur);
	GTlsCertificate *c = cur ? g_object_ref(cur) : NULL;
	G_UNLOCK(cur);
	return c;
}

const char *rcs_cert_fingerprint(void)
{
	return cur ? cur_fp : NULL;
}
