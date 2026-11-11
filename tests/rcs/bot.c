// SPDX-License-Identifier: GPL-3.0-only
/* bot.c: the Chatbot characteristic, multipart/mixed, content types, URIs, the botinfo query. */
#include <stdio.h>
#include <string.h>
#include "acs.h"
#include "bot.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static struct acs_xml *xml(const char *s)
{
	GError *e = NULL;
	struct acs_xml *x = acs_xml_parse(s, strlen(s), &e);
	if (!x)
		printf("xml: %s\n", e->message);
	return x;
}

#define DOC(services, chatbot)                                                                   \
	"<?xml version=\"1.0\"?><wap-provisioningdoc version=\"1.1\">"                           \
	"<characteristic type=\"APPLICATION\"><characteristic type=\"SERVICES\">" services        \
	"</characteristic><characteristic type=\"MESSAGING\">" chatbot "</characteristic>"       \
	"</characteristic></wap-provisioningdoc>"

static void config(void)
{
	struct bot_config b;
	/* R9 B.1.2's sample: ChatbotMsgTech 2, standaloneMsgAuth 2. */
	struct acs_xml *x = xml(DOC("<parm name=\"standaloneMsgAuth\" value=\"2\"/>",
				    "<characteristic type=\"Chatbot\">"
				    "<parm name=\"ChatbotDirectory\" value=\"botplatform.maapservice.com\"/>"
				    "<parm name=\"BotinfoFQDNRoot\" value=\"botplatform.maapservice.com\"/>"
				    "<parm name=\"ChatbotMsgTech\" value=\"2\"/></characteristic>"));
	bot_config_from_xml(x, 1, 1, &b);
	CHECK(b.present && b.session && b.sa && b.xbot && bot_on(&b));
	CHECK(!strcmp(b.root, "botplatform.maapservice.com"));
	bot_config_from_xml(x, 1, 0, &b);
	CHECK(b.session && b.sa && !b.xbot);
	bot_config_from_xml(x, 0, 1, &b);
	CHECK(b.present && !b.session && !b.sa && !b.xbot && !bot_on(&b));
	acs_xml_free(x);
	/* No Chatbot characteristic: nothing. */
	x = xml(DOC("<parm name=\"standaloneMsgAuth\" value=\"1\"/>", ""));
	bot_config_from_xml(x, 1, 1, &b);
	CHECK(!b.present && !bot_on(&b) && !b.xbot);
	acs_xml_free(x);
	/* Session only (stock's default MsgTech 1), and SLM only without standaloneMsgAuth. */
	x = xml(DOC("", "<characteristic type=\"Chatbot\"><parm name=\"PrivacyDisable\" value=\"1\"/></characteristic>"));
	bot_config_from_xml(x, 1, 1, &b);
	CHECK(b.present && b.session && !b.sa && b.xbot);
	acs_xml_free(x);
	x = xml(DOC("", "<characteristic type=\"Chatbot\"><parm name=\"ChatbotMsgTech\" value=\"3\"/></characteristic>"));
	bot_config_from_xml(x, 1, 1, &b);
	CHECK(!bot_on(&b) && !b.xbot);
	acs_xml_free(x);
}

static void multipart(void)
{
	char *ct, *part, *sugg;
	size_t n;
	/* RCC.07's layout: a card and its suggestions. */
	const char *m1 = "--next\r\nContent-Type: application/vnd.gsma.botmessage.v1.0+json\r\n"
			 "Content-Length: 9\r\n\r\n{\"a\":\"b\"}\r\n"
			 "--next\r\nContent-Type: application/vnd.gsma.botsuggestion.v1.0+json\r\n\r\n"
			 "{\"suggestions\":[]}\r\n--next--\r\n";
	CHECK(bot_multipart_split("multipart/mixed; boundary=\"next\"", m1, strlen(m1), &ct, &part, &n, &sugg) == 0);
	CHECK(ct && !strcmp(ct, BOT_CT_MESSAGE));
	CHECK(part && !strcmp(part, "{\"a\":\"b\"}") && n == 9);
	CHECK(sugg && !strcmp(sugg, "{\"suggestions\":[]}"));
	g_free(ct), g_free(part), g_free(sugg);
	/* Suggestions first, text with a charset, a preamble, LF only, unquoted boundary. */
	const char *m2 = "preamble\n--b1\nContent-Type: application/vnd.gsma.botsuggestion.v1.0+json\n\n[1]\n"
			 "--b1\nContent-Type: text/plain; charset=utf-8\n\n\xec\x95\x88\xeb\x85\x95\n--b1--";
	CHECK(bot_multipart_split("multipart/mixed;boundary=b1", m2, strlen(m2), &ct, &part, &n, &sugg) == 0);
	CHECK(ct && !strcmp(ct, "text/plain") && part && !strcmp(part, "\xec\x95\x88\xeb\x85\x95"));
	CHECK(sugg && !strcmp(sugg, "[1]"));
	g_free(ct), g_free(part), g_free(sugg);
	/* A part without headers is text/plain (stock ImMultipart). */
	const char *m3 = "--x\r\n\r\nhello\r\n--x--\r\n";
	CHECK(bot_multipart_split("multipart/mixed; boundary=x", m3, strlen(m3), &ct, &part, &n, &sugg) == 0);
	CHECK(ct && !strcmp(ct, "text/plain") && part && !strcmp(part, "hello") && !sugg);
	g_free(ct), g_free(part), g_free(sugg);
	/* An empty part (the next delimiter right after this one), and one at the very end. */
	const char *m5 = "--x\r\n--x\r\nContent-Type: text/plain\r\n\r\nhi\r\n--x--";
	CHECK(bot_multipart_split("multipart/mixed; boundary=x", m5, strlen(m5), &ct, &part, &n, &sugg) == 0);
	CHECK(ct && !strcmp(ct, "text/plain") && part && !strcmp(part, "") && n == 0);
	g_free(ct), g_free(part), g_free(sugg);
	const char *m6 = "--x\r\n--x--";
	CHECK(bot_multipart_split("multipart/mixed; boundary=x", m6, strlen(m6), &ct, &part, &n, &sugg) == 0);
	CHECK(part && !strcmp(part, ""));
	g_free(ct), g_free(part), g_free(sugg);
	const char *m7 = "--x\r\nContent-Type: text/plain\r\n";
	CHECK(bot_multipart_split("multipart/mixed; boundary=x", m7, strlen(m7), &ct, &part, &n, &sugg) == 0);
	g_free(ct), g_free(part), g_free(sugg);
	/* No boundary, or only suggestions: not a message. */
	CHECK(bot_multipart_split("multipart/mixed", m3, strlen(m3), &ct, &part, &n, &sugg) < 0);
	const char *m4 = "--x\r\nContent-Type: application/vnd.gsma.botsuggestion.v1.0+json\r\n\r\n[]\r\n--x--";
	CHECK(bot_multipart_split("multipart/mixed; boundary=x", m4, strlen(m4), &ct, &part, &n, &sugg) < 0);
	CHECK(!ct && !part && !sugg);
}

static void types(void)
{
	CHECK(bot_kind_of(BOT_CT_MESSAGE) == BOT_KIND_MESSAGE);
	CHECK(bot_kind_of("Application/Vnd.Gsma.Botmessage.v1.0+json") == BOT_KIND_MESSAGE);
	CHECK(bot_kind_of(BOT_CT_XBOT) == BOT_KIND_XBOT);
	CHECK(bot_kind_of("application/vnd.gsma.xbotmessage.v1.3+json") == BOT_KIND_XBOT);
	CHECK(bot_kind_of(BOT_CT_OPENRICH) == BOT_KIND_OPENRICH);
	CHECK(bot_kind_of(BOT_CT_SUGGESTION) == BOT_KIND_NONE);
	CHECK(bot_kind_of("text/plain") == BOT_KIND_NONE);
	CHECK(bot_xbot_version_ok(BOT_CT_XBOT) && bot_xbot_version_ok(BOT_CT_OPENRICH));
	CHECK(!bot_xbot_version_ok("application/vnd.gsma.xbotmessage.v1.3+json"));
	CHECK(!bot_xbot_version_ok("application/vnd.gsma.openrichcard.v2.0+json"));
	CHECK(bot_xbot_version_ok(BOT_CT_MESSAGE));
}

static void uris(void)
{
	char k[256];
	CHECK(bot_uri_key("sip:bot@botplatform.loopback.example;tk=on", k, sizeof(k)) == 0 && !strcmp(k, "sip:bot@botplatform.loopback.example"));
	CHECK(bot_uri_key("sip:bot@botplatform.loopback.example?X=y", k, sizeof(k)) == 0 && !strcmp(k, "sip:bot@botplatform.loopback.example"));
	CHECK(bot_uri_key("tel:+821012345678", k, sizeof(k)) < 0);
	CHECK(bot_uri_key("sip:nohost", k, sizeof(k)) < 0);
	CHECK(bot_uri_key("sip:bot@", k, sizeof(k)) < 0);
	CHECK(bot_uri_key("sip:b ot@x", k, sizeof(k)) < 0);
	CHECK(bot_uri_key("sip:bot@x\r\nEvil: 1", k, sizeof(k)) < 0);
	CHECK(bot_uri_key("sip:b\xc3\xb6t@x", k, sizeof(k)) < 0);
}

static void botinfo(void)
{
	char host[256];
	uint16_t port;
	/* Stock's query (Samsung Messages ki.k): id, hl, ho = MCC + MNC padded to three, v. */
	char *q = bot_info_request("botplatform.maapservice.com", "sip:bot@botplatform.maapservice.com;tk=on",
				   "ko-KR", "450", "06", 3, "UA/1", NULL, host, sizeof(host), &port);
	CHECK(q && !strcmp(q, "GET /bot?id=sip%3Abot%40botplatform.maapservice.com&hl=ko&ho=450006&v=3 HTTP/1.1\r\n"
			      "Host: botplatform.maapservice.com\r\nUser-Agent: UA/1\r\nAccept: application/json\r\n"
			      "Connection: close\r\n\r\n"));
	CHECK(!strcmp(host, "botplatform.maapservice.com") && port == 443);
	g_free(q);
	/* No root: the bot's domain (R9 7.7.3.2). A port, an ETag, no language, no PLMN. */
	q = bot_info_request("", "sip:a@bots.example", NULL, "", "", 0, NULL, "\"v1\"", host, sizeof(host), &port);
	CHECK(q && !strcmp(q, "GET /bot?id=sip%3Aa%40bots.example&hl=en&ho=000000 HTTP/1.1\r\nHost: bots.example\r\n"
			      "Accept: application/json\r\nIf-None-Match: \"v1\"\r\nConnection: close\r\n\r\n"));
	g_free(q);
	q = bot_info_request("localhost:18447", "sip:a@b", "en", "450", "6", 3, NULL, NULL, host, sizeof(host), &port);
	CHECK(q && strstr(q, "Host: localhost:18447\r\n") && strstr(q, "&ho=450006&") && port == 18447 &&
	      !strcmp(host, "localhost"));
	g_free(q);
	/* Nothing that could put bytes of its own on the wire. */
	CHECK(!bot_info_request("evil.example/x", "sip:a@b", "en", "450", "06", 3, NULL, NULL, host, sizeof(host), &port));
	CHECK(!bot_info_request("", "sip:a@evil host", "en", "450", "06", 3, NULL, NULL, host, sizeof(host), &port));
	CHECK(!bot_info_request("", "sip:a@b\r\nX: 1", "en", "450", "06", 3, NULL, NULL, host, sizeof(host), &port));
	CHECK(!bot_info_request("", "tel:+8215880000", "en", "450", "06", 3, NULL, NULL, host, sizeof(host), &port));
	q = bot_info_request("b", "sip:a@b", "en", "450", "06", 3, "x\r\nEvil: 1", "\"e\"\r\nEvil: 2", host,
			     sizeof(host), &port);
	CHECK(q && !strstr(q, "Evil"));
	g_free(q);

	CHECK(bot_max_age("max-age=3600") == 3600);
	CHECK(bot_max_age("public, max-age=60") == 60);
	CHECK(bot_max_age("no-cache") == 0);
	CHECK(bot_max_age("max-age=60, no-store") == 0);
	CHECK(bot_max_age("public") == -1);
	CHECK(bot_max_age(NULL) == -1);
}

int main(void)
{
	config();
	multipart();
	types();
	uris();
	botinfo();
	if (fails)
		return 1;
	printf("rcs-bot: passed\n");
	return 0;
}
