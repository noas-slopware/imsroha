# RCS (Chatting+ and other Universal Profile carriers): feasibility

Research only, 2026-11-11. Nothing has been sent to a carrier.

## What Chatting+ is

Chatting+ (채팅+) is the Korean carriers' RCS: GSMA Universal Profile 2.4 with a Korean
terminal standard on top, TTAK.KO-06.0410 "RCS 서비스 단말 연동 규격" (R7 named by
namu.wiki, R8 dated 2024-12 on
https://committee.tta.or.kr/data/standard_view.jsp?pk_num=TTAK.KO-06.0410%2FR8). Like
TTAK.KO-06.0357, TTA hands the PDF out after a login and a survey. The carriers' servers
are not provisioned for Google's Jibe, so only Samsung Messages and, since iOS 26, iPhones
use it. Under the TTA profile it is Universal Profile, so a generic UP client is the base
and the Korean parts are data plus the TTA additions.

## TTAK.KO-06.0410/R9 (2025-11-21, 212 pages)

TTA hands the PDF out after a login (sha256 3c14a8a7…); it is not redistributed
here.

- **Base and additions.** It builds on GSMA RCS 6.0 "Advanced Communications Services
  and Client Specification" v7.0 (6.1). Chapter 8 adds the Korean features: reply
  (8.2), reaction (8.3), cancel message (8.4), category, room title and icon, notices,
  live alias, creator/inviter, Extended Messaging and caution alerts (8.5-8.11).
- **Clients (6.2.1).** Embedded and downloadable clients are both allowed; secondary
  devices are not. The client is named separately from the terminal (6.3.1.1.1):
  `client_vendor` (at most 4 characters), `client_version` (`Platform-Major.Minor`, e.g.
  `RCSAndr-6.0`), `terminal_vendor`, `terminal_model` (at most 10 characters) and
  `terminal_sw_version`. So an independent client is anticipated by the spec, at least
  on paper.
- **SIP User-Agent (8.1).**
  `TTA-RCS/1.0 <model>/<sw> Device_Type/<RCS_Android_Phone|RCS_iPhone|RCS_Android_PAD|RCS_iPad|RCS_Tablet_PC> <SKT|KT|LGU|OMD|token>`.
  OMD is the open-market device. There is no device type for a Linux phone.
- **First activation (figure 6-1).** HTTP GET, then 511, then HTTPS GET with MSISDN,
  IMSI and IMEI, then 200 with a cookie. The server then sends an SMS with an OTP, the
  client sends HTTPS GET with the OTP and the cookie, and the server answers 200 with the
  XML profile (VERS version/validity, TOKEN, P-CSCF_Address, Content-serveruri). Later
  runs use the token.
- **Responses (table 6-2).**
  - version and validity 0: temporarily not valid.
  - version and validity -1: "customer or device not valid, permanently". The client
    must not retry until the SIM changes or a factory reset.
  - 403: bad request; the version goes back to 0.
  
  A refusal of an unknown client could therefore come back as -1, and whether the
  server also records that against the line is not said. The first probe has to be
  exactly right.

## What stock does (SM-F711N F711NKSSFKZH5, imsservice.apk)

All three carriers have the same shape. From `res/raw/imsprofile.json`
("SKT RCS", "KT RCS", "LGU RCS") and `res/raw/globalsettings.json` (SKT_KR, KT_KR, LGU+_KR):

| | SKT | KT | LG U+ |
|---|---|---|---|
| PDN | default (internet) | default | default |
| SIP | TLS, port 9672, NAPTR DNS | same | same |
| sec-agree algorithms | hmac-sha-1-96, aes-cbc | hmac-sha-1-96, null/aes-cbc | hmac-sha-1-96, aes-cbc |
| reg event SUBSCRIBE | no | no | no |
| autoconfig (ACS) | `http://config.rcs.mnc005.mcc450.pub.connectrcs.com` | `...mnc008...` | `...mnc006...` |
| ACS server type | `sec` (WorkflowSec) | `sec` | `sec` |
| OTP SMS | binary, port 37273 | same | same |
| profile | UP_2.4, provisioning 5.0, client 2.4 | same | same |

- Services: im, ft_http, presence, slm, euc, gls, chatbot-communication. The app list
  sent to the ACS is ap2001, ap2002, urn:oma:mo:ext-3gpp-ims:1.0.
- Networks: `rcs_network_type` "internet,wifi". RCS does not ride the IMS PDN, so it does
  not need imsroha's IPsec SAs or the IMS bearer.
- User-Agent:
  `TTA-RCS/[CLIENT_VERSION] [PRODUCT_MODEL]/[BUILD_VERSION] Device_Type/RCS_Android_Phone [OMCCODE]`.
- Autoconfig (`config/workflow/WorkflowSec.java`, GSMA RCC.14):
  1. HTTP to the ACS over the mobile network first; the carrier identifies the
     subscriber there.
  2. Then HTTPS with: vers, IMSI, IMEI, terminal_model, terminal_vendor `SEC`,
     terminal_sw_version, default_sms_app, app, client_version
     `<platform>6.0`, rcs_profile, provisioning_version, rcs_state.
  3. Off the mobile network (or on HTTP 511) it adds msisdn, SMS_port and token. The
     one-time password then arrives as a binary SMS to port 37273.
- The Korean SIM path forces a new ACS run more often (`isKor()` in ConfigTrigger,
  ConfigModule and WorkflowBase).
- Registration has Korea-only rules in `core/RegistrationGovernorKor.java` (RCS-only
  tasks, MSISDN from the P-Associated-URI). Read it before writing the registration.

## What imsroha would need

The generic part works on any UP carrier with its own ACS. Jibe carriers are out: Jibe
only provisions Google Messages.

**Opt-in.** RCS is off unless the configuration turns it on: an
`[rcs]` section with `enable=true` in `/etc/imsroha/imsroha.conf`, default false, and
nothing in `data/carriers.conf` switches it on. While it is off, imsroha never contacts
the ACS: that request carries the IMSI and IMEI and can change the line's RCS state at
the carrier. It also opens no TLS registration and exposes no RCS interface, so
VoLTE/SMS behave exactly as today. Stock leaves it to the user too
(`rcs_default_enabled` -1). Turning it off again sends the ACS the
"disabled by user" rcs_state, as stock does (`OpMode.DISABLE_RCS_BY_USER`), so the
carrier falls back to SMS for this number. Spacebar's RCS transport stays inert while no
provider is on the bus.

1. **Autoconfig client.** RCC.14 HTTP then HTTPS, the parameters above, the OTP SMS
   through ModemManager's binary SMS on the configured port, and storing the XML
   (version, validity, SIP server, credentials, the FT HTTP content server). Per-carrier
   data (ACS URL, OTP port, client strings, UA format) goes in `data/carriers.conf`.
2. **SIP over TLS on the internet PDN.** NAPTR/SRV DNS, a second registration next to
   the VoLTE one, the RCS feature tags, and digest or AKA auth as the ACS says. imsroha's
   SIP stack today is UDP over IPsec on the IMS PDN, so the transport needs a TLS path.
3. **Messaging.**
   - 1-to-1 chat: CPM session over MSRP/TLS.
   - Standalone messages: pager and large-message mode.
   - CPIM, IMDN (delivered/displayed), is-composing.
   - Group chat through the conference factory.
   - File transfer over HTTP (upload, then a file-info XML).
   - Capability discovery: OPTIONS or presence.
   - Revoke, chatbots, and TTA's verified sender (공인알림) are later steps.
4. **An API for apps.** No Linux messaging app speaks RCS, and ModemManager's Messaging
   interface is SMS only. That means a `codes.noa.IMSroha` RCS interface plus a backend
   in Spacebar (Plasma Mobile's messenger), with fallback to SMS/MMS when the other side
   has no RCS.

Existing code: rust-rcs-client (github.com/Hirohumi/rust-rcs-client, Apache-2.0, last
push 2024-11, written against the three Chinese carriers). It has autoconfig, standalone
CPM, HTTP file transfer and chatbots, but no MSRP chat sessions. It is a useful reference
for the flows, not a drop-in: UP 2.4 1-to-1 chat is MSRP.

## The open question that decides it

Will `connectrcs.com`'s ACS provision a client that is not Samsung Messages?

- Stock sends terminal_vendor `SEC`, the model (SM-F711N, a supported model) and Samsung's
  client_version.
- iPhones are provisioned since iOS 26, so the server does serve non-Samsung clients.
  Whether it checks vendor, model or client strings is unknown.

Answered on 2026-11-11: yes, for LG U+. Its ACS provisioned imsroha-rcs on the first
run, with truthful terminal fields (terminal_vendor `SEC`, model SM-F711N) and
imsroha's own client fields (client_version `RCSLinux-0.2`, terminal_sw_version
`IMSroha-0.2.0`). SKT and KT have not been asked.

## Design: imsroha-rcs

Written 2026-11-11, before the code, and first tested on loopback only; the status
below has the live run on LG U+.

### Components

RCS is its own executable, `imsroha-rcs` (unit `imsroha-rcs.service`), next to
`imsroha-bearer` and `imsroha-vss-samsung`. `imsroha` and `src/sip.c` do not change: the
VoLTE binary does not link a TLS library, and its golden tests stay byte for byte the
same. `imsroha-rcs` is GLib/GIO (GDBus, GSocketClient, GTlsClientConnection from
glib-networking, GMarkup); the SIM and modem reads reuse `src/aka.c` and `src/imei.c`.

| file | does |
|---|---|
| `src/rcs/rcs_config.c` | `[rcs]` of `imsroha.conf`, the `rcs-*` keys of the carrier profile (overridable in `[carrier]`), `[device]` |
| `src/rcs/acs.c` | autoconfig: the requests (one pure builder, golden-tested), the responses (TTAK.KO-06.0410/R9 table 6-2), the XML, the per-IMSI state |
| `src/rcs/http.c` | HTTP/1.1 GET over GIO, plain or TLS, written by hand so every byte on the wire is ours (no library headers, no redirects followed) |
| `src/rcs/net.c` | every RCS socket: optional `SO_BINDTODEVICE` to the internet PDN's netdev, never the IMS netdev |
| `src/rcs/smsport.c` | SMS-DELIVER TPDUs: the application port (TS 23.040 9.2.3.24.4) and the text |
| `src/rcs/sipua.c` | a second SIP user agent: TLS, NAPTR/SRV, Digest, REGISTER, PUBLISH (presence), OPTIONS, INVITE/MESSAGE/BYE for chat |
| `src/rcs/msrp.c` | MSRP (RFC 4975) over TLS, as the active end |
| `src/rcs/cpim.c` | CPIM (RFC 3862), IMDN (RFC 5438), isComposing (RFC 3994) |
| `src/rcs/fthttp.c` | file transfer over HTTP: the FileTransfer configuration, the file-info XML, Digest, upload, download |
| `src/rcs/ft.c` | file transfer in the daemon: `SendFile`, fetching what comes in, the download directory |
| `src/rcs/bot.c` | chatbots and A2P: the Chatbot characteristic, feature tags and content types, multipart/mixed, the botinfo request |
| `src/rcs/botinfo.c` | `GetBotInfo`: the botinfo query and its cache |
| `src/rcs/rcsd.c` | the daemon: state machine, OTP from SMS, D-Bus service |

### Opt-in, and what "off" means

- `enable=` is read only from `[rcs]` in `/etc/imsroha/imsroha.conf`. Default false.
  `carriers.conf` and `[carrier]` have no key that turns RCS on; `rcs-*` keys there only
  describe how the carrier does it.
- Off and never on: `imsroha-rcs` exits 0 before it opens anything. No SIM read, no
  socket, no D-Bus name, no file in `/var/lib/imsroha/rcs`.
- Off after it was on: stock sends the ACS `rcs_state=-4` ("사용자가 명확히
  device/client에서 RCS를 disable한 경우", R9 table 6-1) when the user turns RCS off, so
  the carrier routes this number back to SMS. `imsroha-rcs` does the same, once, and
  only when the state for this IMSI says the ACS has answered us before with a
  configuration (version > 0) and the -4 has not been sent yet. It never sends it when
  there is no state, when the version is -1 or -2, or when it was already sent. Then it
  deregisters nothing (it is not registered) and exits.
- On: autoconfig, then registration, then the D-Bus interface appears. VoLTE and SMS do
  not change in any case: RCS is a separate registration on another PDN (R9 A.3.1 a:
  "VoLTE Registration에 영향을 주어서는 안된다").

### Network

RCS runs on the internet PDN or Wi-Fi (stock `rcs_network_type` "internet,wifi"; R9
6.4.3: Wi-Fi when connected, else the LTE internet APN). Every RCS socket goes through
`net.c`:

- `[rcs] interface=` binds sockets to that netdev (`SO_BINDTODEVICE`), for example
  ModemManager's bearer interface, so the first HTTP GET leaves through the carrier
  even with Wi-Fi up (network-based authentication only works there).
  `interface-ipv4=` binds IPv4 sockets elsewhere (LG U+'s internet PDN is IPv6-only with
  CLAT: `qmapmux0.0` for IPv6, `clat0` for IPv4). Unset, the routing table decides.
- `[device] ims-netdev` (imsroha0) is refused as `interface`, and nothing binds to the IMS
  address, so policy table 1042 never sees RCS traffic.
- Names resolve through the system resolver; NAPTR goes through `res_query`.

### Autoconfig (RCC.14, R9 6.3)

1. HTTP GET to `rcs-acs-url` with no parameters. On the carrier's network the ACS knows
   the subscriber from the bearer and answers 200 with a cookie; anywhere else 511.
2. HTTPS GET to the same host with the parameters below and the cookie, if any.
3. 200 with a full XML: done. 200 with no version/validity but a cookie: the ACS has
   sent an OTP by SMS; wait for it (binary SMS to `rcs-otp-port`, or a text SMS when
   `rcs-otp-type=text`) and send `GET /?OTP=<otp>` with the cookie.
4. Store and act on VERS (table 6-2):

| answer | imsroha-rcs |
|---|---|
| version > 0, full XML | store, register, next autoconfig after `validity` seconds |
| same version, VERS only | keep the stored XML, next run after `validity` |
| version 0, validity 0 | remove the XML; retry on the next start |
| version 0, validity > 0 | remove the XML; retry after `validity` |
| version -1, validity -1 | remove the XML, mark the IMSI `permanent`: no request of any kind for this IMSI again (only a new SIM, or deleting the state by hand) |
| version -2 | RCS disabled by the carrier: remove the XML, no registration, retry on the next start |
| version -3 | dormant: keep the XML, do not register |
| 403 | remove the XML, version 0, retry on the next start |
| unreachable, or no OTP SMS | keep what we have, retry 20 min, 1, 2, 4, 8 h (R9 6.3.1.2.3), then on the next start |
| 500 (twice), other errors | keep what we have, retry on the next start (table 6-2) |
| 503 + Retry-After | retry after Retry-After |
| 511 on the HTTPS GET | drop the token, start over once with MSISDN and the OTP flow |

Whatever asks for a run (a restart, a crash loop under `Restart=`, a 403 to REGISTER, a
P-CSCF that does not answer), two runs are at least 1200 s apart, the first step of
R9's ladder: the time of the last run is in the state before the first byte goes out.
The non-PS request (after a 511) is not sent without an MSISDN.

A network-initiated SMS to the port whose text is `<IMSI>-rcscfg` or `<IMPI>-rcscfg`
(R9 6.3.1.1.2) starts a run (the second with version 0).

Parameters of the HTTPS GET, in this order: `vers`, `rcs_state`, `IMSI`, `IMEI`,
`terminal_model`, `terminal_vendor`, `terminal_sw_version`, `client_vendor`,
`client_version`, `rcs_profile`, `provisioning_version`, `rcs_version` (only when the
carrier sets one), `app` (repeated), `default_sms_app`, and after a 511 or when
`[rcs] assume-mobile=false`: `msisdn`, `SMS_port`, `token`. The values:

| parameter | from |
|---|---|
| `terminal_model`, `terminal_sw_version` | `[device] model`, `build` |
| `terminal_vendor` | `[device] vendor` (`SEC` for Samsung, as stock) |
| `client_vendor`, `client_version` | `[rcs] client-vendor` (≤ 4 characters, default `IMSR`), `client-version` (`Platform-Major.Minor`, default `RCSLinux-` and imsroha's major.minor). Stock sends `SEC` and `RCSAndr-6.0`; which one the ACS accepts is the open question above |
| `rcs_profile`, `provisioning_version`, `app` | carrier (`rcs-profile`, `rcs-provisioning-version`, `rcs-app`) |
| `default_sms_app` | `[rcs] default-sms-app` (1: the RCS client is the SMS app, as with Spacebar) |
| `IMSI`, `IMEI` | the SIM over QMI UIM, the modem over QMI DMS |
| `msisdn` | `[rcs] msisdn`, else ModemManager's `OwnNumbers` |

State per IMSI in `/var/lib/imsroha/rcs/<IMSI>/`: `state` (version, validity, token,
next run, rcs_state, last HTTP status, `permanent`, `disable-sent`) and `config.xml`.

### Registration (R9 6.4, A.3-A.5)

A second, independent SIP UA. From the XML: `Private_User_Identity`,
`Public_User_Identity`, `Home_network_domain_name`, `LBO_P-CSCF_Address` (FQDN or IP,
optional port), `Ext/GSMA` `AuthType`/`Realm`/`UserName`/`UserPwd`, `psSignalling`
(SIPoTLS). The P-CSCF comes from the ACS, never from the PCO (A.3.1 b). NAPTR, then SRV
`_sips._tcp`, then the name at `rcs-sip-port` (9672). TLS with server certificate
validation against the system store (`[rcs] ca-file=` for a private CA).

- Contact: the feature tags of what is implemented, nothing else: ICSI
  `urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session` (chat) and `+sip.instance`, and
  one `+g.3gpp.iari-ref` with `rcse.dp` (presence) and `rcs.fthttp` (file transfer,
  only when the configuration has `ftAuth=1` and an `ftHTTPCSURI`), comma separated
  as in R9's examples. The chatbot tags join that list when chatbots are on (see
  "Chatbots and RCS A2P" below). Geolocation is added with that feature.
- Digest (MD5, qop=auth) with the ACS credentials. AKA is not implemented (R9's sample
  configuration says Digest).
- Capability discovery as the configuration's `CAPDISCOVERY/defaultDisc` says: 1 is
  presence (R9 6.5: PUBLISH our capabilities, an anonymous-fetch SUBSCRIBE for a peer's,
  and the IARI `rcse.dp` in Contact), 0 is OPTIONS. IR.92 table C.3.1 cites RCC.07 A.2.5
  for the parameter and gives 2 as off; 0 and 1 are from memory of RCC.07. PUBLISH
  errors are retried as R9 table 6-3 says.
- 403: rerun autoconfig once; a second 403 stops RCS until restart (A.5 b).
- Re-REGISTER at 600 s before expiry or half of short expiries. The TLS connection
  stays open with kernel TCP keepalive; nothing runs on a timer while idle.
- User-Agent: `rcs-user-agent` (stock: `TTA-RCS/2.4 <model>/<sw>
  Device_Type/RCS_Android_Phone <operator>`; R9 8.1's ABNF says `TTA-RCS/1.0`).

### Messaging

- 1-to-1 chat is a CPM session (R9 7.2): INVITE with
  `Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`,
  SDP `m=message` with `a=accept-types:message/cpim application/im-iscomposing+xml`,
  `a=accept-wrapped-types:text/plain message/imdn+xml`, `a=setup:active`. imsroha-rcs
  always opens the MSRP connection (R9: "We always have the client establish the
  connection to the server"), for MO and MT sessions alike.
- Messages: `message/cpim` around `text/plain`, with `imdn.Message-ID`, `DateTime`,
  `imdn.Disposition-Notification: positive-delivery, display`.
- Received messages: a delivered IMDN at once; displayed when the app says the user
  saw it (`MarkDisplayed`). IMDNs go in the session when one is up, else in a SIP
  MESSAGE (RCC.07; the cpm.msg ICSI on that MESSAGE is unverified).
- isComposing (RFC 3994) in the session, not CPIM-wrapped (R9 7.2.3), unless the
  carrier says `rcs-iscomposing-cpim=true`.
- Idle sessions end after `TimerIdle`; the next message opens a new one.
- Standalone messaging is "X" in R9 table 7-1, so nothing is sent in pager mode, but
  R9 7.7.3.3 requires pager and large message mode for A2P. Both are taken: a pager
  MESSAGE with CPIM is a message like one in a session, and an INVITE for the
  `cpm.largemsg` ICSI is answered `a=recvonly` and kept apart from the peer's chat
  (it neither replaces that chat nor carries what we send). IMDNs outside a session go
  in a SIP MESSAGE.

### Chatbots and RCS A2P (GSMA RCC.07 3.6, R9 7.7)

Korea's "RCS 비즈메시지": chatbots and one-way A2P senders on the carriers' MaaP
platform (`botplatform.maapservice.com`). `[rcs] chatbot=` (default true) switches it;
with false, or when the configuration has no Chatbot characteristic, nothing chatbot is
advertised or accepted.

- **Advertised**, from the Chatbot characteristic as stock's `FeatureUpdater` does it:
  - Chatbot session (`rcs.chatbot`): `ChatbotMsgTech` 1 or 2 (stock's default 1).
  - Chatbot standalone (`rcs.chatbot.sa`): `ChatbotMsgTech` 2 or 3 and SERVICES
    `standaloneMsgAuth` not 0 (2 is "receiving only" in stock; R9's sample has 2).
  - Extended bot message (`rcs.xbotmessage`, R9 7.7.4.1): with either of them, when the
    carrier's `rcs-xbotmessage` is true (the three Korean carriers; stock does it for
    Korean SIMs only).
  - In Contact (REGISTER, INVITE, our OPTIONS answers) they join the one `iari-ref`
    list, followed by `+g.gsma.rcs.botversion="#=1"` (R9 tables 6-4 and 7-7).
  - In PUBLISH they are tuples, version 1.0, with the service ids
    `org.3gpp.urn:urn-7:3gpp-application.ims.iari.rcs.chatbot`, `...rcs.chatbot.sa` and
    `...rcs.chatbot.xbotmessage`. The xbotmessage tag and its service id differ, as in
    R9 table 7-7 and stock `ServiceTuple`.
- **Who sent it** (R9 6.4.1, 7.7.3.1). P-Asserted-Identity is read before From.
  - A tel URI makes it that number's conversation, so A2P merges into the SMS/MMS
    thread.
  - A chatbot known only by its SIP URI is a conversation keyed by that URI, without
    URI parameters (`;tk=`).
  - The chatbot service id (the signals' `bot_id`) is one of these, in order: that SIP
    URI; a SIP URI on another domain next to the tel URI (when its user part is not a
    phone number); or the entity of the capability NOTIFY (R9 7.7.3.2, stock
    `PresenceUpdate`) or the PAI of an OPTIONS answer (stock `OptionsRequestController`)
    from an earlier `GetCapabilities`. A service id seen next to a tel URI is kept for
    that number's later messages and our sessions to it. Otherwise it is "".
  - A request is a chatbot's when its Contact has `+g.gsma.rcs.isbot` or it asks for
    the chatbot IARI. With chatbots off, those get 606, as stock's "chat bot sessions /
    slm not allowed".
- **What comes in**, in a session, a pager MESSAGE or a large message session, inside
  CPIM:
  - `application/vnd.gsma.botmessage.v1.0+json` (rich card, carousel),
    `application/vnd.gsma.xbotmessage.v*+json` and
    `application/vnd.gsma.openrichcard.v*+json`: `RichMessageReceived`.
  - `multipart/mixed` as stock's `ImMultipart` reads it: one message part plus an
    optional `application/vnd.gsma.botsuggestion.v1.0+json` part (the signal's
    `suggestions`). A text part with suggestions is a `RichMessageReceived` with
    `text/plain`. A text part without them, or a bare text/plain, is a
    `MessageReceived`.
  - A file-info with suggestions goes to file transfer, as stock's `ImProcessor` does
    after the split. The suggestions are not passed on.
  - Delivered and displayed IMDNs work as for text. A payload with nothing in it we
    could show gets no delivered IMDN, and 415 in pager mode, so the platform does not
    count it delivered.
  - In pager mode, an xbotmessage or open rich card above version 1.0, or any of them
    while xbotmessage is not advertised, gets 606 (R9 7.7.4.17.2, stock "doesn't have
    the xbotmessage").
- **Sessions with a chatbot** (to a sip: URI, from a chatbot, with a number whose
  service id is known, and every large message session) also offer
  `multipart/mixed`, the botmessage and botsuggestion types, and with xbotmessage
  `application/vnd.gsma.xbotmessage.v1.0+json` and
  `application/vnd.gsma.openrichcard.v1.0+json` in `accept-wrapped-types`. R9
  7.7.4.17.3 has the platform read that list before it sends an open rich card. The
  content-type strings are stock libsec-ims.so's.
- **To a chatbot**, the INVITE adds the chatbot IARI and botversion to Accept-Contact.
  That header comes from memory of RCC.07: stock builds it in libsec-ims.so, which has
  the tags but not the header as a string. `SendSuggestionResponse` sends the app's JSON
  as `application/vnd.gsma.botsuggestion.response.v1.0+json` in the chat, like any
  message. Stock (Samsung Messages `ActionsFactory`) sends no reference to the message
  it answers either, so `in_reply_to_message_id` stays in the log.
- **The network check** (R9 7.7.3.3.1): a pager MESSAGE with a delivered IMDN for a
  message id that never existed. It gets its 200 whoever it claims to be from and
  however its XML looks (R9's own sample is malformed). No IMDN goes back. No status
  signal is sent for an id we did not send this run that ends in `-bodiless`, as R9's
  example does. Other unknown ids are still reported: they may be from before a
  restart, and the app knows them.
- **botinfo** (`GetBotInfo`, RCC.07 3.6.4.1.1, R9 7.7.3.2). The request is
  `GET https://<BotinfoFQDNRoot>/bot?id=<service id>&hl=<lang>&ho=<MCC><MNC>&v=3`, or
  the service id's domain when there is no root.
  - The query is stock Samsung Messages' (`BotProfileLoaderV2`, `ki.k`): the MNC is
    padded to three digits; `v=3` is the profile version of its bot API for Korea
    (`bot_rcc07_version` 11.0); `hl` is the first two letters of `rcs-accept-language`.
  - User-Agent is `rcs-http-user-agent` (stock sends okhttp's own).
  - No credentials are sent. Stock's TTA loader has no Digest step.
  - HTTPS with the certificate checked (stock may trust any CA there).
  - The JSON goes to the app exactly as received, R9 7.7.2's extra fields included.
  - It is cached in memory for Cache-Control's max-age and revalidated with
    If-None-Match when there is an ETag. Errors are
    `codes.noa.IMSroha.Rcs.Error.NotAvailable`.

### File transfer over HTTP (GSMA RCC.07, R9 7.4.1.1)

The wire format below is stock's (`UploadFileTask`, `DownloadFileTask`,
`HttpAuthGenerator`, `FtHttpIncomingMessage` in imsservice.apk) and R9's examples;
RCC.07 itself was not at hand.

The file goes to the carrier's content server; the chat carries only the file-info
XML the server answers with (CPIM content type `application/vnd.gsma.rcs-ft-http+xml`,
offered in the SDP's `accept-wrapped-types` and published as the
`org.openmobilealliance:File-Transfer-HTTP` tuple, version 1.0, R9 table 6-4).

- Configuration: `ftAuth` (SERVICES), and from FileTransfer `ftHTTPCSURI`,
  `ftHTTPCSUser`, `ftHTTPCSPwd`, `MaxSizeFileTr`, `ftWarnSize`, `ftAutAccept`, and
  from Ext (R9 B.1) `ftHTTPExtraCSURI` and `MaxSizeExtraFileTr`. They are read from
  the stored `config.xml` at registration; the password and user never reach the log.
  LG U+ provisions ftAuth 1, MaxSizeFileTr 5120 KB, MaxSizeExtraFileTr 307200 KB, a
  content server and a large-content server.
- Sending (`SendFile`): the file is opened with the D-Bus caller's rights (see below),
  must be a regular, non-empty file, and goes to `ftHTTPCSURI` up to `MaxSizeFileTr`,
  to `ftHTTPExtraCSURI` above that up to `MaxSizeExtraFileTr` (0: no limit, R9 B.1),
  and is refused above. The upload is what stock's `UploadFileTask` does: an empty
  POST; a 401 is answered with HTTP Digest (`ftHTTPCSUser`/`ftHTTPCSPwd`, uri =
  path and query); then `multipart/form-data` with `tid` (a UUID, `text/plain`) and
  `File` (the name form-encoded as stock sends it), streamed from the file. The
  server's file-info goes out unchanged as a chat message in the session (one is
  opened if needed), with delivered and displayed IMDNs as for text.
- Receiving: a file-info in a chat is a message like any other: delivered at once
  (stock marks it delivered before the download), displayed on `MarkDisplayed`. It is
  not fetched when `until` has passed or its `file-size` is over the limit (stock's
  `MaxSizeFileTrIncoming` when given, else the larger of the two upload limits). The
  thumbnail (if any) and then the file are fetched over the URL's scheme and stored
  under a part name, then renamed to the file-name's last component (percent and `+`
  decoded as stock does, no `/`, no leading dot, existing files never replaced:
  `name (2).ext`). What arrives is capped by the limit whatever the file-info or
  Content-Length says. The thumbnail is `thumb-<message-id>.<ext>`.
- Credentials go only to our content servers: a data URL on the host of
  `ftHTTPCSURI` or `ftHTTPExtraCSURI`, or on one of the carrier's
  `rcs-ft-auth-hosts`, over https (also plain http with `rcs-ft-auth-http=true`). A
  peer's file-info pointing anywhere else is fetched without them, so it cannot
  collect a Digest answer for the user's credentials; the log names the host whose
  401 went unanswered. This is stricter than stock (`DownloadFileTask` answers any
  401) and than R9's sample, whose data URLs are plain `http://rcs-seoul1...:80` on
  another host than its `ftHTTPCSURI`. Where LG U+'s data URLs point is not known
  yet: if receiving fails with "unauthorized", that host goes into
  `rcs-ft-auth-hosts`.
- Where files go: `[rcs] download-dir=` (for the messaging app: `<dir>/<IMSI>/`), or
  `<state-dir>/<IMSI>/files`, which is root's alone (the state directory is 0700).
- imsroha-rcs runs as root and any local user may call it (the bus policy), so it
  never opens a file with its own rights: `SendFile` opens the path with the
  caller's uid, gid and groups from the bus (`GetConnectionCredentials`), and
  received files are created with the uid and gid of `download-dir`'s owner. Both
  switch only the worker's filesystem identity (`setfsuid`, `setfsgid` and the raw
  `setgroups` system call are per thread on Linux) for the `open`, and switch back.

### D-Bus: `codes.noa.IMSroha.Rcs`

Bus name `codes.noa.IMSroha.Rcs`, object `/codes/noa/IMSroha/Rcs`, interface
`codes.noa.IMSroha.Rcs`. It exists only while RCS is enabled. Numbers are E.164
(`+8210...`) or national; imsroha-rcs normalises them with `country-code`.

```
property  s State           "configuring" | "waiting-otp" | "registering" | "registered"
                            | "unregistered" | "disabled-by-network"
method    SendMessage(s number, s text) -> (s message_id)
                            number may be a chatbot's sip: URI too
method    SetComposing(s number, b active)
method    MarkDisplayed(s number, s message_id)
method    SendFile(s number, s path) -> (s message_id)
                            path absolute, opened as the caller; status signals as for text
method    GetCapabilities(s number) -> (a{sv} caps)   "chat": b, "ft-http": b, "known": b,
                            "chatbot": b (the peer has the bot role, isbot; not merely
                            the chatbot tuple every phone has), "bot-id": s (its service
                            id, when known); number may be a sip: URI
                            (anonymous fetch or OPTIONS, as the configuration says)
method    SendSuggestionResponse(s number, s in_reply_to_message_id, s response_json)
                            -> (s message_id)   the JSON as
                            application/vnd.gsma.botsuggestion.response.v1.0+json in that
                            conversation; status signals as for text
method    GetBotInfo(s bot_id) -> (s json)   the botinfo JSON as the server sent it, cached
signal    RichMessageReceived(s number, s message_id, s content_type, s body,
                       s suggestions, s bot_id, x timestamp_ms)
                            content_type: application/vnd.gsma.botmessage.v1.0+json,
                            application/vnd.gsma.xbotmessage.v1.0+json,
                            application/vnd.gsma.openrichcard.v1.0+json, or text/plain
                            (bot text with suggestions); body and suggestions (the
                            botsuggestion JSON, "" when none) exactly as received; number
                            +E.164 for a tel URI, else the chatbot's sip: URI; bot_id ""
                            when unknown
signal    MessageReceived(s number, s message_id, s text, x timestamp_ms)
signal    MessageStatusChanged(s message_id, s status)   "sent" | "delivered" | "displayed" | "failed"
signal    ComposingChanged(s number, b active)
signal    FileReceived(s number, s message_id, s path, s content_type, t size,
                       s thumbnail_path, x timestamp_ms)   thumbnail_path "" when none
signal    FileReceiveFailed(s number, s message_id, s reason)
                            "expired" | "too-large" | "unauthorized" | "gone" | "invalid" | "failed"
signal    StateChanged(s state)
error     codes.noa.IMSroha.Rcs.Error.NotReady (not registered), .Failed,
          .NotAvailable (chatbots off or not provisioned, no botinfo)
```

Strings from the network that are not UTF-8 reach the signals with U+FFFD in place
of the bad bytes.

`SendMessage` returns when the message is handed to the session; "sent" follows the
MSRP 200, "failed" an error or a session that could not be set up, so the app can fall
back to SMS. `SendFile` returns once the file is open and fits; "failed" follows if
the upload fails, and the app can fall back to MMS (R9 7.4.1.1.1: "파일 업로드 실패시는
MMS로 fallback"). Group chat (`CreateGroup`, `SendGroupMessage`, the conference event
package) comes later on the same interface.

### Carrier data (`carriers.conf`, `rcs-*`)

`rcs-acs-url`, `rcs-otp-port`, `rcs-otp-type`, `rcs-otp-regex`, `rcs-profile`,
`rcs-provisioning-version`, `rcs-version`, `rcs-app`, `rcs-user-agent`,
`rcs-http-user-agent`, `rcs-sip-port`, `rcs-iscomposing-cpim`, `rcs-standalone`,
`rcs-ft-auth-hosts`, `rcs-ft-auth-http`, `rcs-xbotmessage`. The
three Korean carriers get stock's values (globalsettings.json `SKT_KR`, `KT_KR`,
`LGU+_KR`; imsprofile.json `SKT RCS`, `KT RCS`, `LGU RCS`).

### Generic and Korean

Generic (GSMA UP, RCC.07/RCC.14, OMA CPM): the whole flow above, the XML, SIP/TLS,
MSRP, CPIM, IMDN, isComposing. Korean, all as data or behind a carrier key: the ACS URL,
the OTP port and its UCS-2 text, `-rcscfg` requests, the TTA User-Agent, isComposing
without CPIM, no standalone messaging sent (A2P's is received), R9 7.7.4's extended bot
message (`rcs-xbotmessage`), and the chapter 8 additions (reply, reaction,
cancel; not implemented yet: CPIM headers in the `Extended-RCS <http://www.tta.or.kr>`
namespace, ignored when received as RFC 3862 says).

### Status (2026-11-11)

**Working on LG U+** (Galaxy Z Flip3, 0.2.0-4): the ACS run with the OTP SMS
(configuration version 15, valid two weeks), registration over TLS to the P-CSCF
from NAPTR/SRV, capabilities through presence, and a 1-to-1 chat both ways with a
Samsung phone over MSRPoTLS, with delivered and displayed reports. SKT and KT are
untried.

On loopback (`meson test`: `rcs-acs-request`, `rcs-acs-flow`, `rcs-smsport`,
`rcs-daemon`, `rcs-cert`, `rcs-bot`, `rcs-rbm`, each in a network namespace with
nothing but `lo`; also
clean under ASan/UBSan): every ACS outcome, the first activation with the OTP SMS,
the ACS floor with an unreachable P-CSCF and with two 403s to REGISTER, chat both ways
with IMDNs and isComposing, presence (PUBLISH, anonymous fetch), the -4 request, the
MSRP client certificate, and file transfer against a fake content server
(`tests/rcs/fake-cs.py`, Digest on every request): binary files both ways byte for
byte, the large-file server, the thumbnail over chunked coding, a file name that tries
to leave the directory, an expired and an oversize file-info never fetched, no
credentials for another host (`rcs-ft` covers the parsing, the limits and Digest
against RFC 2617 and RFC 7616's examples). Chatbots (`rcs-rbm` against a fake
chatbot platform, `tests/rcs/fake-pcscf.py --rbm`, and `tests/rcs/fake-botinfo.py`):
- The tags in REGISTER, our OPTIONS answer and PUBLISH.
- A chat to `sip:bot@...` with its Accept-Contact and SDP, carrying R9 table 7-8's
  rich card (without header and footer), the same card with them as an xbotmessage,
  and a carousel with suggestions, then our suggestion response.
- A chat from a chatbot: text with suggestions, then plain text.
- From a tel URI, all in the number's thread with their IMDNs to the tel URI:
  - R9 table 7-8 b's open rich card in pager mode.
  - A 60 KB card in pager mode, more than one read of the connection.
  - A rich card in large message mode, answered recvonly with the bot types.
- The network check; an xbotmessage v1.3 refused.
- "chatbot" and "bot-id" for bots, an A2P number and a phone.
- botinfo fetched, cached, revalidated and unknown.
- With `chatbot=false`, nothing advertised, chatbot traffic refused and a person's
  message still taken.

Every signal's arguments are checked exactly. `rcs-bot` covers the Chatbot
characteristic, multipart/mixed, content-type versions, URIs and the botinfo request.
Chatbots have not been tried on LG U+. File transfer has not been tried on LG
U+. A messaging app's side: Spacebar patches 0004-0007 in `spacebar/`.

Not done yet, or different from R9's own examples:

- R9's INVITE examples use `TCP/MSRP` with `msrp://...;tcp` and the real local port,
  `accept-types:message/cpim` only, `Session-Expires: 7200;refresher=uac`, and every
  request carries P-Access-Network-Info. imsroha-rcs follows `psMedia` (MSRPoTLS in
  the sample: `msrps://`), puts port 9 in the SDP, offers no session timer and sends no
  P-Access-Network-Info.
- With MSRPoTLS the MSRP relay wants a client certificate (LG U+'s answers a
  connection without one with the TLS alert "Certificate is required"). As Samsung's
  stack does, imsroha-rcs makes a self-signed RSA-2048 certificate for the registered
  address (CN and SAN URI), keeps it with its key in `<state-dir>/<IMSI>/msrp-cert.pem`
  (0600), makes a new one 30 days before it expires or when the address changes,
  presents it on every MSRP connection and names its hash in the SDP
  (`a=fingerprint:SHA-1 ...`, RFC 4975 14.1).
- The P-CSCF's certificate is checked against the SRV target when NAPTR/SRV found
  one, against the configured name otherwise.

- AKA for the RCS registration (only Digest, what R9's sample configuration has).
- OTP for carriers whose SMS stays with the modem (SKT) is untested: ModemManager
  patch 0008 hands port-addressed SMS from the modem to imsroha's `TakePortPdu`, which
  puts them out on `PortPduReceived` like the ones over IMS. The text OTP
  (`rcs-otp-type=text`) of such a carrier still goes to the messaging app, not to
  imsroha-rcs.
- Group chat (conference factory, conference event package), revoke,
  presence, the chapter 8 Korean additions.
- File transfer: no thumbnail is made or sent (stock sends one), no pause and resume
  (R9 7.4.3), no group file transfer, no `cbftHTTPCSURI` for files to chatbots, and no
  MMS fallback inside imsroha-rcs (the app gets "failed"). `ftAutAccept=0` is not
  honoured: every file that fits is fetched. `ftWarnSize` is read but nothing warns.
  The data URL of a peer's file-info is fetched wherever it points (no credentials
  unless it is our server), as stock does by default. Opening files as the caller or
  the download directory's owner is not exercised by the tests: the network namespace
  has only root.
- The ACS `rcsDisabledState` (UP 2.x) is not read; `-rcscfg` requests only arrive
  through SMS over IMS, like the OTP.
- Chatbots, not done:
  - Nothing is sent in pager mode, so a chatbot that only takes standalone messages
    (`ChatbotMsgTech` 3) cannot be written to.
  - No chatbot tokens or anonymization (`tk=`, `PrivacyDisable`, stock's
    `RequestChatbotAnonymize`), no spam report, no `botsharedclientdata`, no search in
    `ChatbotDirectory`, and no Deep Link handling (R9 7.7.5; that is the app's).
  - botinfo is cached in memory only, so a restart asks again.
  - An xbotmessage or open rich card above v1.0 that comes in a session is passed to
    the app; only pager mode can refuse it.
  - The Accept-Contact of an INVITE to a chatbot is from memory of RCC.07, not stock.
  - `SendFile` takes phone numbers only, so no files are sent to a chatbot.
  - The tests are loopback only.
