// SPDX-License-Identifier: GPL-3.0-only
/* The MSRP client certificate: made once, loaded again, made again for another address. */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <glib/gstdio.h>
#include "cert.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)

int main(void)
{
	char *dir = g_dir_make_tmp("rcs-cert-XXXXXX", NULL);
	char *sub = g_build_filename(dir, "450060000000000", NULL);
	char *path = g_build_filename(sub, "msrp-cert.pem", NULL);
	GError *e = NULL;

	CHECK(rcs_cert_get() == NULL && rcs_cert_fingerprint() == NULL);
	CHECK(rcs_cert_ensure(sub, "sip:+821000000000@example.org", &e) == 0);
	char fp1[96];
	g_strlcpy(fp1, rcs_cert_fingerprint(), sizeof(fp1));
	CHECK(g_str_has_prefix(fp1, "SHA-1 ") && strlen(fp1) == 6 + 59);
	GStatBuf st;
	CHECK(g_stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
	GTlsCertificate *c = rcs_cert_get();
	CHECK(c);
	g_object_unref(c);

	/* same address: kept in memory */
	CHECK(rcs_cert_ensure(sub, "sip:+821000000000@example.org", &e) == 0);
	CHECK(!strcmp(fp1, rcs_cert_fingerprint()));

	/* another address: a new one, written over the old file */
	CHECK(rcs_cert_ensure(sub, "sip:+821011111111@example.org", &e) == 0);
	char fp2[96];
	g_strlcpy(fp2, rcs_cert_fingerprint(), sizeof(fp2));
	CHECK(strcmp(fp1, fp2));

	/* back to the second after another one elsewhere: loaded from the file,
	 * not made again */
	char *other = g_build_filename(dir, "other", NULL);
	char *opath = g_build_filename(other, "msrp-cert.pem", NULL);
	CHECK(rcs_cert_ensure(other, "sip:+821022222222@example.org", &e) == 0);
	CHECK(strcmp(fp2, rcs_cert_fingerprint()));
	CHECK(rcs_cert_ensure(sub, "sip:+821011111111@example.org", &e) == 0);
	CHECK(!strcmp(fp2, rcs_cert_fingerprint()));
	g_unlink(opath);
	g_rmdir(other);

	g_unlink(path);
	g_rmdir(sub);
	g_rmdir(dir);
	printf("ok\n");
	return 0;
}
