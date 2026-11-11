// SPDX-License-Identifier: GPL-3.0-only
/*
 * The pure parts of file transfer over HTTP: the FileTransfer configuration,
 * which server a file goes to, whose URLs get our credentials, the file-info
 * document (R9 7.4.1.1.1's example), received file names, Digest.
 */
#include <stdio.h>
#include <string.h>
#include "acs.h"
#include "fthttp.h"

static int fail;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fail = 1; } } while (0)
#define STREQ(a, b) do { const char *_a = (a), *_b = (b); \
	if (!_a || strcmp(_a, _b)) { printf("FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, _a ? _a : "(null)", _b); fail = 1; } } while (0)

static const char cfg_xml[] =
	"<?xml version=\"1.0\"?><wap-provisioningdoc version=\"1.1\">"
	"<characteristic type=\"VERS\"><parm name=\"version\" value=\"1\"/><parm name=\"validity\" value=\"1\"/></characteristic>"
	"<characteristic type=\"APPLICATION\"><parm name=\"AppID\" value=\"ap2002\"/>"
	"<characteristic type=\"SERVICES\"><parm name=\"ftAuth\" value=\"1\"/></characteristic>"
	"<characteristic type=\"MESSAGING\">"
	"<characteristic type=\"FileTransfer\">"
	"<parm name=\"ftWarnSize\" value=\"5120\"/><parm name=\"MaxSizeFileTr\" value=\"5120\"/>"
	"<parm name=\"ftAutAccept\" value=\"1\"/>"
	"<parm name=\"ftHTTPCSURI\" value=\"https://content.example.com/content/\"/>"
	"<parm name=\"ftHTTPCSUser\" value=\"u@example.com\"/><parm name=\"ftHTTPCSPwd\" value=\"pw\"/>"
	"<parm name=\"ftHTTPFallback\" value=\"0\"/></characteristic>"
	"<characteristic type=\"Ext\"><parm name=\"MaxSizeExtraFileTr\" value=\"307200\"/>"
	"<parm name=\"ftHTTPExtraCSURI\" value=\"https://large-content.example.com/content/\"/></characteristic>"
	"</characteristic></characteristic></wap-provisioningdoc>";

/* R9 7.4.1.1.1, with the URLs on one line. */
static const char info_xml[] =
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
	"<file xmlns=\"urn:gsma:params:xml:ns:rcs:rcs:fthttp\"\r\n"
	"xmlns:e=\"urn:gsma:params:xml:ns:rcs:rcs:up:fthttpext\">\r\n"
	"  <file-info type=\"thumbnail\">\r\n"
	"    <file-size>1683</file-size>\r\n"
	"    <content-type>image/jpeg</content-type>\r\n"
	"    <data url=\"http://rcs-seoul1.mip.ABCcom.net:80/content/A7v?t=image%2Fjpeg&amp;s=1683\" until=\"2066-08-23T04:53:50.000Z\"/>\r\n"
	"  </file-info>\r\n"
	"  <file-info type=\"file\">\r\n"
	"    <file-size>169502</file-size>\r\n"
	"    <file-name>20180413_112647.jpg</file-name>\r\n"
	"    <content-type>image/jpeg</content-type>\r\n"
	"    <data url=\"http://rcs-seoul1.mip.ABCcom.net:80/content/HRX?t=image%2Fjpeg&amp;s=169502\" until=\"2066-08-23T04:53:50.000Z\"/>\r\n"
	"    <e:branded-url>http://rcs-seoul1.mip.ABCcom.net:80/content/HRX</e:branded-url>\r\n"
	"  </file-info>\r\n"
	"</file>\r\n";

int main(void)
{
	struct acs_xml *x = acs_xml_parse(cfg_xml, strlen(cfg_xml), NULL);
	CHECK(x);
	struct ft_config c;
	ft_config_from_xml(x, &c);
	acs_xml_free(x);
	CHECK(c.enabled);
	STREQ(c.cs_uri, "https://content.example.com/content/");
	STREQ(c.extra_uri, "https://large-content.example.com/content/");
	STREQ(c.user, "u@example.com");
	CHECK(c.max_size == 5120 * 1024ull && c.extra_max == 307200 * 1024ull);
	CHECK(c.incoming_max == 307200 * 1024ull);
	STREQ(ft_upload_uri(&c, 5120 * 1024ull), c.cs_uri);
	STREQ(ft_upload_uri(&c, 5120 * 1024ull + 1), c.extra_uri);
	CHECK(!ft_upload_uri(&c, 307200 * 1024ull + 1));
	c.extra_max = 0; /* R9 B.1: 0 is no limit */
	STREQ(ft_upload_uri(&c, 1ull << 40), c.extra_uri);

	/* Credentials only to our servers, only over https. */
	CHECK(ft_url_trusted(&c, "https://content.example.com/content/abc?x=1"));
	CHECK(ft_url_trusted(&c, "https://LARGE-content.example.com:443/x"));
	CHECK(!ft_url_trusted(&c, "http://content.example.com/content/abc"));
	CHECK(!ft_url_trusted(&c, "https://content.example.com:8443/content/abc"));
	CHECK(!ft_url_trusted(&c, "https://content.example.com.evil.test/x"));
	CHECK(!ft_url_trusted(&c, "https://u@content.example.com/x"));

	/* No ftAuth, no file transfer. */
	const char *off = "<wap-provisioningdoc><characteristic type=\"FileTransfer\">"
			  "<parm name=\"ftHTTPCSURI\" value=\"https://a/\"/></characteristic></wap-provisioningdoc>";
	x = acs_xml_parse(off, strlen(off), NULL);
	ft_config_from_xml(x, &c);
	acs_xml_free(x);
	CHECK(!c.enabled && !ft_upload_uri(&c, 1));

	struct ft_info fi;
	CHECK(ft_info_parse(info_xml, strlen(info_xml), &fi, NULL) == 0);
	CHECK(fi.file.present && fi.thumb.present);
	CHECK(fi.file.size == 169502 && fi.thumb.size == 1683);
	STREQ(fi.file.name, "20180413_112647.jpg");
	STREQ(fi.file.ctype, "image/jpeg");
	STREQ(fi.file.url, "http://rcs-seoul1.mip.ABCcom.net:80/content/HRX?t=image%2Fjpeg&s=169502");
	STREQ(fi.thumb.url, "http://rcs-seoul1.mip.ABCcom.net:80/content/A7v?t=image%2Fjpeg&s=1683");
	CHECK(fi.file.until == 3049764830);
	ft_info_clear(&fi);
	CHECK(ft_info_parse("<file/>", 7, &fi, NULL) < 0);
	CHECK(ft_info_parse("<file><file-info", 16, &fi, NULL) < 0);

	/* Names from the peer. */
	char *n;
	STREQ((n = ft_safe_name("%EC%9D%8C%EC%84%B1+%EB%A9%94%EC%8B%9C%EC%A7%80+001.amr")), "음성 메시지 001.amr");
	g_free(n);
	STREQ((n = ft_safe_name("../../etc/passwd")), "passwd");
	g_free(n);
	STREQ((n = ft_safe_name("..%2F..%2Fetc%2Fshadow")), "shadow");
	g_free(n);
	STREQ((n = ft_safe_name("C:\\Users\\x\\a.txt")), "a.txt");
	g_free(n);
	STREQ((n = ft_safe_name(".bashrc")), "bashrc");
	g_free(n);
	STREQ((n = ft_safe_name("a%0Ab%01c.txt")), "abc.txt");
	g_free(n);
	CHECK(!(n = ft_safe_name("..")));
	CHECK(!(n = ft_safe_name("dir/")));
	CHECK(!ft_safe_name(NULL));
	char longname[400];
	memset(longname, 'a', 300);
	strcpy(longname + 300, ".jpeg");
	n = ft_safe_name(longname);
	CHECK(n && strlen(n) == 200 && g_str_has_suffix(n, ".jpeg"));
	g_free(n);
	/* Hangul is 3 bytes: the cut lands between characters. */
	GString *h = g_string_new(NULL);
	for (int i = 0; i < 100; i++)
		g_string_append(h, "가");
	g_string_append(h, ".txt");
	n = ft_safe_name(h->str);
	CHECK(n && strlen(n) <= 200 && g_utf8_validate(n, -1, NULL) && g_str_has_suffix(n, ".txt"));
	g_free(n);
	g_string_free(h, TRUE);
	STREQ((n = ft_form_encode("음 a+b.txt")), "%EC%9D%8C+a%2Bb.txt");
	g_free(n);

	/* RFC 2617 3.5. */
	const char *ch = "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", "
			 "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
	char *a = ft_digest(ch, "Mufasa", "Circle Of Life", "GET", "/dir/index.html", "0a4f113b");
	CHECK(a && strstr(a, "response=\"6629fae49393a05397450978507c4ef1\""));
	CHECK(a && strstr(a, "qop=auth,nc=00000001,cnonce=\"0a4f113b\""));
	CHECK(a && strstr(a, "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
	g_free(a);
	/* RFC 7616 3.9.1, SHA-256. */
	ch = "Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=SHA-256, "
	     "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
	a = ft_digest(ch, "Mufasa", "Circle of Life", "GET", "/dir/index.html",
		      "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");
	CHECK(a && strstr(a, "response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\""));
	g_free(a);
	CHECK(!ft_digest("Basic realm=\"x\"", "u", "p", "GET", "/", NULL));
	CHECK(!ft_digest("Digest realm=\"x\",nonce=\"n\",qop=\"auth-int\"", "u", "p", "GET", "/", NULL));
	CHECK(!ft_digest("Digest realm=\"x\",nonce=\"n\",algorithm=AKAv1-MD5", "u", "p", "GET", "/", NULL));

	if (!fail)
		printf("rcs-ft: passed\n");
	return fail;
}
