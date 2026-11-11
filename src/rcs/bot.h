// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <glib.h>
#include "acs.h"

/*
 * Chatbots and RCS A2P (GSMA RCC.07 3.6, TTAK.KO-06.0410/R9 7.7): the
 * feature tags, service ids and content types, the provisioned Chatbot
 * characteristic, the multipart/mixed a bot message comes in, and the
 * botinfo query. No I/O here: botinfo.c and chat.c do that.
 */

/* Feature tags (R9 tables 6-4 and 7-7; stock Capabilities.java has the same strings).
 * The extended bot message's tag and its service id differ: rcs.xbotmessage
 * in Contact, rcs.chatbot.xbotmessage in the presence tuple (R9 table 7-7,
 * stock ServiceTuple.java). */
#define BOT_IARI_SESSION "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot"
#define BOT_IARI_SA "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot.sa"
#define BOT_IARI_XBOT "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.xbotmessage"
#define BOT_VERSION_TAG "+g.gsma.rcs.botversion=\"#=1\""
#define BOT_ROLE_TAG "+g.gsma.rcs.isbot"
#define BOT_SID_SESSION "org.3gpp.urn:urn-7:3gpp-application.ims.iari.rcs.chatbot"
#define BOT_SID_SA "org.3gpp.urn:urn-7:3gpp-application.ims.iari.rcs.chatbot.sa"
#define BOT_SID_XBOT "org.3gpp.urn:urn-7:3gpp-application.ims.iari.rcs.chatbot.xbotmessage"
#define BOT_SID_ROLE "org.gsma.rcs.isbot"

/* Content types (stock MIMEContentType.java, libsec-ims.so). */
#define BOT_CT_MESSAGE "application/vnd.gsma.botmessage.v1.0+json"
#define BOT_CT_SUGGESTION "application/vnd.gsma.botsuggestion.v1.0+json"
#define BOT_CT_RESPONSE "application/vnd.gsma.botsuggestion.response.v1.0+json"
#define BOT_CT_XBOT "application/vnd.gsma.xbotmessage.v1.0+json"
#define BOT_CT_OPENRICH "application/vnd.gsma.openrichcard.v1.0+json"
#define BOT_CT_XBOT_PREFIX "application/vnd.gsma.xbotmessage.v"
#define BOT_CT_OPENRICH_PREFIX "application/vnd.gsma.openrichcard.v"

/* The ICSI of large message mode (OMA CPM; stock libsec-ims.so). */
#define RCS_ICSI_LARGEMSG "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg"
#define RCS_ICSI_LARGEMSG_RAW "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.largemsg"

/* The provisioned Chatbot characteristic, and what we advertise from it. */
struct bot_config {
	int present;            /* the configuration has a Chatbot characteristic */
	int msg_tech;           /* ChatbotMsgTech: 0 off, 1 session, 2 session and SLM, 3 SLM */
	int slm_auth;           /* SERVICES/standaloneMsgAuth: 0 off, 1 on, 2 receiving only */
	char root[256];         /* BotinfoFQDNRoot ("" = the bot's domain, R9 7.7.3.2) */
	char directory[256];    /* ChatbotDirectory */
	/* Advertised (and accepted): */
	int session;            /* rcs.chatbot + botversion */
	int sa;                 /* rcs.chatbot.sa + botversion */
	int xbot;               /* rcs.xbotmessage (R9 7.7.4.1) */
};

/* enable: [rcs] chatbot=; xbot: the carrier's rcs-xbotmessage. */
void bot_config_from_xml(const struct acs_xml *x, int enable, int xbot, struct bot_config *out);
static inline int bot_on(const struct bot_config *b)
{
	return b && (b->session || b->sa);
}

enum bot_kind {
	BOT_KIND_NONE,       /* not a bot payload */
	BOT_KIND_MESSAGE,    /* botmessage: RCC.07 rich card or carousel */
	BOT_KIND_XBOT,       /* R9 7.7.4 extended bot message */
	BOT_KIND_OPENRICH,   /* R9 open rich card */
};
/* ctype without parameters. */
enum bot_kind bot_kind_of(const char *ctype);
/* An xbotmessage/openrichcard version we take: stock's IsSupportedXbotMessageContentType
 * compares the content type's version with its own; ours is 1.0. */
int bot_xbot_version_ok(const char *ctype);

/*
 * multipart/mixed (RFC 2046) as a bot sends it (RCC.07 3.6.10): one message
 * part and an optional botsuggestion part. ctype_full is the Content-Type
 * with its boundary. As stock ImMultipart: a part without headers is
 * text/plain; the botsuggestion part goes to *suggestion. 0 or -EBADMSG.
 * *ctype (parameters stripped), *body and *suggestion are g_malloc'd (or NULL).
 */
int bot_multipart_split(const char *ctype_full, const char *body, size_t len, char **ctype, char **part,
			size_t *plen, char **suggestion);

/* sip:bot@host;tk=on?x=y -> sip:bot@host: the conversation key of a bot. 0 or -EINVAL
 * (not a sip:/sips: URI, or characters that have no place in one). */
int bot_uri_key(const char *uri, char *out, size_t size);

/*
 * The botinfo query (RCC.07 3.6.4.1.1, R9 7.7.3.2): GET
 * https://<root>/bot?id=<bot_id>&hl=<lang>&ho=<mcc><mnc>&v=<v>, as stock
 * Samsung Messages builds it (BotProfileLoaderV2, ki.k: mcc and mnc padded
 * to three digits, v the profile version of its bot API). root may carry
 * :port; "" takes the bot id's domain. Returns the request (NULL: bot_id or
 * root unusable) and the host and port to connect to.
 */
char *bot_info_request(const char *root, const char *bot_id, const char *lang, const char *mcc,
		       const char *mnc, int v, const char *user_agent, const char *etag, char *host,
		       size_t hsize, uint16_t *port);
/* max-age of a Cache-Control value, 0 for no-cache/no-store, -1 when none. */
long bot_max_age(const char *cache_control);
