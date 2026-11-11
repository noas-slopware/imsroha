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

Noa got the PDF; it lives at linux-zflip3 `scratch/tta/rcs/TTAK.KO-06.0410R9.pdf`
(sha256 3c14a8a7…), with the text in `r9.txt`.

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

**Opt-in (Noa, 2026-11-11).** RCS is off unless the configuration turns it on: an
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

The cheapest test is one ACS run (HTTP over the phone's LG U+ data, then HTTPS) with
truthful terminal fields and imsroha's own client fields; it needs Noa's go. If it
answers with a config, the rest is protocol work with public specs (RCC.07, RCC.14,
RCC.71, OMA CPM) plus TTAK.KO-06.0410. If it refuses, the response says on what.

## Design: imsroha-rcs

Written 2026-11-11, before the code. Everything below was built and tested on loopback
only; no request has gone to a carrier.

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
  `urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session` (chat) and `+sip.instance`.
  File transfer, geolocation, chatbot and presence tags are added with those features.
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
- Standalone messaging (pager mode) is "X" in R9 table 7-1, so Korea gets none. It is
  implemented for receiving (a MESSAGE with CPIM is a chat message) and for IMDNs.

### D-Bus: `codes.noa.IMSroha.Rcs`

Bus name `codes.noa.IMSroha.Rcs`, object `/codes/noa/IMSroha/Rcs`, interface
`codes.noa.IMSroha.Rcs`. It exists only while RCS is enabled. Numbers are E.164
(`+8210...`) or national; imsroha-rcs normalises them with `country-code`.

```
property  s State           "configuring" | "waiting-otp" | "registering" | "registered"
                            | "unregistered" | "disabled-by-network"
method    SendMessage(s number, s text) -> (s message_id)
method    SetComposing(s number, b active)
method    MarkDisplayed(s number, s message_id)
method    GetCapabilities(s number) -> (a{sv} caps)   "chat": b, "ft-http": b, "known": b
                            (anonymous fetch or OPTIONS, as the configuration says)
signal    MessageReceived(s number, s message_id, s text, x timestamp_ms)
signal    MessageStatusChanged(s message_id, s status)   "sent" | "delivered" | "displayed" | "failed"
signal    ComposingChanged(s number, b active)
signal    StateChanged(s state)
```

`SendMessage` returns when the message is handed to the session; "sent" follows the
MSRP 200, "failed" an error or a session that could not be set up, so the app can fall
back to SMS. Group chat (`CreateGroup`, `SendGroupMessage`, the conference event
package) and file transfer (`SendFile`, HTTP upload to `ftHTTPCSURI`) come later on the
same interface.

### Carrier data (`carriers.conf`, `rcs-*`)

`rcs-acs-url`, `rcs-otp-port`, `rcs-otp-type`, `rcs-otp-regex`, `rcs-profile`,
`rcs-provisioning-version`, `rcs-version`, `rcs-app`, `rcs-user-agent`,
`rcs-http-user-agent`, `rcs-sip-port`, `rcs-iscomposing-cpim`, `rcs-standalone`. The
three Korean carriers get stock's values (globalsettings.json `SKT_KR`, `KT_KR`,
`LGU+_KR`; imsprofile.json `SKT RCS`, `KT RCS`, `LGU RCS`).

### Generic and Korean

Generic (GSMA UP, RCC.07/RCC.14, OMA CPM): the whole flow above, the XML, SIP/TLS,
MSRP, CPIM, IMDN, isComposing. Korean, all as data or behind a carrier key: the ACS URL,
the OTP port and its UCS-2 text, `-rcscfg` requests, the TTA User-Agent, isComposing
without CPIM, no standalone messaging, and the chapter 8 additions (reply, reaction,
cancel; not implemented yet: CPIM headers in the `Extended-RCS <http://www.tta.or.kr>`
namespace, ignored when received as RFC 3862 says).

### Status (2026-11-11)

Built and tested on loopback only (`meson test`: `rcs-acs-request`, `rcs-acs-flow`,
`rcs-smsport`, `rcs-daemon`, each in a network namespace with nothing but `lo`; also
clean under ASan/UBSan). Covered: every ACS outcome, the first activation with the OTP
SMS, the ACS floor with an unreachable P-CSCF and with two 403s to REGISTER, chat both
ways with IMDNs and isComposing, presence (PUBLISH, anonymous fetch), the -4 request.
No request has gone to any carrier. Spacebar's side is the patch series in
linux-zflip3 `userspace/spacebar/` (0004-0006), compile-checked only.

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
- OTP for carriers whose SMS stays with the modem (SKT): imsroha-rcs takes the OTP
  from imsroha's `PduReceived`, which only carries SMS over IMS. ModemManager drops
  the application port, so that needs ModemManager to keep it, or a QMI WMS path.
- The OTP SMS also reaches ModemManager, so the messaging app shows it.
- Group chat (conference factory, conference event package), file transfer over
  HTTP, revoke, chatbots, presence, the chapter 8 Korean additions.
- The ACS `rcsDisabledState` (UP 2.x) is not read; `-rcscfg` requests only arrive
  through SMS over IMS, like the OTP.
