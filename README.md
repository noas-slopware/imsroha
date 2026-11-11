# IMSroha

Userspace IMS for Linux phones whose modem speaks Qualcomm QMI: VoLTE calls and SMS
over IMS without Android, behind an unmodified dialer and SMS app. Named after Iroha
Sakayori (CPK), with the IMS up front.

The modem brings up the IMS PDN and runs AKA on the SIM. Everything above that
(registration, SMS, calls, RTP and AMR) runs here. ModemManager, with the patches in
`modemmanager/`, hands its Voice and Messaging interfaces to the daemon over D-Bus,
so plasma-dialer, spacebar, GNOME Calls and Chatty keep talking to ModemManager only.
RCS chat and file transfer reach the user through Spacebar with the patches in
`spacebar/` (also MMS and SMS fixes for Korean carriers).

## Status

| carrier | PLMN | state |
|---|---|---|
| LG U+ | 450 06 | **tested, working** on the Galaxy Z Flip3 (2026-11-11): registers with TTAK.KO-06.0357/R6 sec-agree (IPsec ESP, `hmac-sha-1-96`/`aes-cbc`), SMS and VoLTE calls both ways, DTMF. LG U+ refuses the reg event (489 "REG EVENT OFF") and puts no P-CSCF in the PCO; the profile's is used. **RCS (Chatting+) working** too: autoconfiguration with the OTP SMS, registration, 1-to-1 chat both ways with a Samsung phone, delivered and displayed reports |
| KT | 450 08 | profile from the stock Samsung firmware; has never registered; RCS untried |
| SKT | 450 05, 450 03 | profile from the stock Samsung firmware; has never registered; SMS stays with the modem, and ModemManager hands the port-addressed ones (RCS's OTP) to imsroha (`TakePortPdu`, ModemManager patch 0008), untested |
| anything else | | plain 3GPP: P-CSCF from the PCO, identity from the ISIM or derived from the IMSI |

All three Korean carriers get what TTAK.KO-06.0357/R6 (the Korean VoLTE terminal
standard) asks for: sec-agree with IPsec ESP (TS 33.203) with no way around it, the
reg event subscription, `+sip.instance`, its SDP offer, its session timer and its
User-Agent. `docs/korea-tta.md` goes through R6 and where imsroha stands.

Tested on: the Galaxy Z Flip3 (SM8350, IPA, QRTR) in
[linux-zflip3](https://github.com/noas-slopware/linux-zflip3), on LG U+, where it is
the phone's IMS stack. Nothing in the code
is tied to it any more. The modem is found as a QRTR node or a QMI device, the data
path from the netdev's driver (`ipa`, `mhi_net`, `qmi_wwan`, `bam-dmux`), and the IMS
profile by its APN.

## Pieces

| binary | unit | does |
|---|---|---|
| `imsroha-bearer` | `imsroha-bearer.service` | starts the IMS PDN (the 3GPP profile whose APN is `ims`) on its own QMAP mux id, creates the rmnet link `imsroha0`, puts the address on it, policy-routes traffic from that address over it, and writes `/run/imsroha/pdn` (interface, address, PCO P-CSCFs, DNS) |
| `imsroha` | `imsroha.service` | reads the SIM (ISIM, else USIM: IMSI, EF_AD, EF_SMSP), picks the carrier profile, registers (IMS AKA, sec-agree with IPsec through `ip xfrm`, reg event), and does SMS (TS 24.341) and VoLTE (INVITE, PRACK, UPDATE, AMR-WB/AMR over RTP, RFC 4733 DTMF). D-Bus `codes.noa.IMSroha` |
| `imsroha-audio` | `imsroha-audio.service` (user, graphical session) | call PCM between `/run/imsroha/audio.sock` and PipeWire |
| `imsroha-rcs` | `imsroha-rcs.service` | RCS (GSMA Universal Profile chat, Korea's Chatting+), **off unless `[rcs] enable=true`**: autoconfiguration, its own SIP registration over TLS on the internet PDN, 1-to-1 chat over MSRP with IMDN and isComposing, file transfer over HTTP. D-Bus `codes.noa.IMSroha.Rcs`; `docs/rcs.md` |
| `imsroha-vss-samsung` | `imsroha-vss-samsung.service` | Samsung modems only: sends the IPC that ungates IMS registration (vendor QMI service 227). Exits at once on any other modem |

The bearer upholds the daemon: every new PDN gets a fresh `imsroha` and a fresh
REGISTER. The MT-SMS inbox (`/var/lib/imsroha/inbox`) holds a message from before the
RP-ACK until ModemManager has it (`AckPdu`). An MT-SMS with application port
addressing (TS 23.040 9.2.3.24.4/5: RCS's OTP and configuration requests, visual
voicemail) is for an application, as on Android: it goes out on `PortPduReceived`
only and never reaches ModemManager or a messaging app. So does the RCS OTP of a
carrier that sends it as plain text (`rcs-otp-type=text`), when `[rcs] enable=true`
(port 0). WAP push (MMS notifications)
stays with ModemManager. Both SMS signals are delivered to root only. Where SMS stays
with the modem (`sms-over-ip=false`), ModemManager (patch 0008) does not expose a
port-addressed SMS the modem received either: it calls `TakePortPdu(q port, s pdu)`,
root only like every method, with the same PDU form (`00`, then the TPDU, in hex), and
imsroha puts it out on `PortPduReceived`. Each part of a concatenated one comes on its
own.

## Configuration

`/etc/imsroha/imsroha.conf`, every key optional (`data/imsroha.conf` lists them):

- `[device]`: `qrtr-node` or `qmi-device`, `data-netdev`, `data-endpoint-type`,
  `data-endpoint-iface`, `mux-id` (3), `ims-netdev` (`imsroha0`), `profile` (0 = by
  APN), `apn` (`ims`), `route-table` and `route-priority` (1042), `mtu-fallback`
  (1428, when the modem reports no MTU), the User-Agent placeholders `model`, `build`,
  `operator` and `device-type`, and `vendor` (RCS's terminal_vendor).
- `[rcs]`: `enable=true` turns RCS on (off by default); see `docs/rcs.md`.
- `[carrier]`: overrides any key of the carrier profile.

`/usr/share/imsroha/carriers.conf` holds the carrier profiles, matched by the SIM's
MCC+MNC: home domain, fallback P-CSCFs, User-Agent template, SMS over IP or not, how
the MT-SMS RP-ACK goes back, SMSC, IPsec, payload types, Session-Expires, SIP and
RTP ports, and the country code for national numbers. The comments at the top of the
file explain each key and where the Korean values come from.

Korean carriers check the User-Agent (TTA-VoLTE, TTAK.KO-06.0357) and want the
Korean model number in it. Set `model=` (`SM-F711N`, not `SM-F711B`).

## Building

```sh
meson setup build
meson compile -C build
meson test -C build
```

Needs glib, libqmi (1.36 or newer), libqrtr-glib, libsystemd, alsa-lib, opencore-amr
and vo-amrwbenc. `packaging/PKGBUILD` builds the Arch package from this checkout.
`modemmanager/PKGBUILD` builds ModemManager 1.24.2 with the backend. Enable with
`systemctl enable --now imsroha-bearer.service`; the bearer starts the rest.

`tests/sip-golden.c` runs the SIP layer against a fake P-CSCF on loopback: REGISTER,
the AKA 401, MO and MT SMS, a cancelled MO call and an answered MT call. With the
random fields masked, the output must match:

- `tests/golden-lguplus.txt`: an LG U+ card with an ISIM and `tests/lguplus-recorded.conf`.
  Byte for byte what the code sent before it left linux-zflip3.
- `tests/golden-lguplus-tta.txt`: the same card with the shipped LG U+ profile (R6).
- `tests/golden-kt.txt`: a KT card without an ISIM, with sec-agree and the reg event.
- `esp-loopback`: the KT run again with the real `ip xfrm`, in a user and network
  namespace. The fake P-CSCF answers through the SAs, and every SA has to carry
  packets.

## Related work

Other people doing IMS from userspace on Linux, none of them on a Korean carrier as
far as I could find:

- [Catcrafts/imsd](https://forgejo.catcrafts.net/Catcrafts/imsd): IMS daemon for
  the Fairphone 6 on Nura, with IPsec, on several European carriers (GPL-3.0-only).
  Also where the layout of the WDS IPv6 P-CSCF TLV (0x2E) used here comes from.
- [MercuryWorkshop/NekoIMS](https://github.com/MercuryWorkshop/NekoIMS): IMS client on
  BareSIP, VoWiFi and VoLTE.
- [ajmwagar/hyphae](https://github.com/ajmwagar/hyphae),
  [damonto/ims-go](https://github.com/damonto/ims-go),
  [deeeeeeeeap/shannon-ims](https://github.com/deeeeeeeeap/shannon-ims): IMS stacks
  in Rust and Go.

## License

GPL-3.0-only, see `LICENSE`. The ModemManager patches are GPL-2.0-or-later, like
ModemManager.
