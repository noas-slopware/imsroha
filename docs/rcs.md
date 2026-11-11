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
