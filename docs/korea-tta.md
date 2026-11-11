# Korean VoLTE: TTAK.KO-06.0357/R6 and the stock profiles

The Korean carriers share one terminal standard, TTAK.KO-06.0357 "사업자 간 UICC
이동성 제공을 위한 VoLTE 단말 규격" (VoLTE terminal for UICC portability between
operators). imsroha follows **R6** (2026-06-26, 64 pages), the current revision. TTA
hands the PDF out after a login and a survey at
https://committee.tta.or.kr/data/standard_view.jsp?commit_code=PG1105&pk_num=TTAK.KO-06.0357%2FR6

R6's own change log: "IPSec off 기능 삭제" (the IPsec-off behaviour removed) and
"로밍 긴급호 Emergency Regi 추가" (emergency registration when roaming). The first is
the change a January 2026 news piece announced
(https://www.mt.co.kr/tech/2026/01/26/2026012520060256692): R5 let a terminal carry on
without IPsec when negotiation failed, R6 does not. The `IPsec_enabled` leaf of the
TTA management object (5.5) is still there, so the carrier can still switch IPsec off.

The second source is Samsung's IMS profile in the stock SM-F711N firmware
F711NKSSFKZH5 (imsservice.apk, res/raw/imsprofile.json and friends), where
data/carriers.conf takes the SKT and KT values R6 does not fix.

## What R6 requires, and where imsroha is

| R6 | requirement | imsroha |
|---|---|---|
| 5.2.1 | ICSI `urn:urn-7:3gpp-service.ims.icsi.mmtel` in Contact; `+g.3gpp.smsip` when the UE does SMS over IP | yes; smsip per carrier (`sms-over-ip`) |
| 5.2.1 | `User-Agent: TTA-VoLTE/4.0 <model>/<sw> Device_Type/<type> <operator>`, operator = the carrier that first sold the device: `SKT` / `KT` / `LGU` / `OMD` (open market) / token. 5.2.2 still says `TTA-VoLTE/3.0` | template per carrier. Stock Samsung sends `TTA-VoLTE/3.0` and its OMC code (SKC/KTC/LUC) of the SIM's network, and so does imsroha; LG U+ has accepted `TTA-VoLTE/1.0 ... LUC` |
| 5.2.1 | SUBSCRIBE to the reg event package (TS 24.229 5.1.1.3); stop after 489 | `reg-event` per carrier (on for SKT and KT, off for LG U+ as recorded); one dialog, refreshed with each registration; a NOTIFY that terminates our contact re-registers |
| 5.2.1 | Contact `+sip.instance` with the IMEI URN (TS 23.003 13.8) | `sip-instance` per carrier (on for SKT and KT); the IMEI from QMI DMS |
| 5.2.1 | ISIM IMPU: one record = normal and emergency; two = first emergency, second normal. No ISIM: temporary IMPU from the IMSI | yes (the record on the home domain; without an ISIM the temporary IMPU registers and everything else uses the first P-Associated-URI) |
| 5.2.1 | 305 on re-registration: another P-CSCF; 503 without Retry-After = 500; try every P-CSCF from DM/PCO, then a new IMS PDN | P-CSCF list with failover on timeouts |
| 5.2.2 | IMS-AKA, sec-agree and IPsec (TS 24.229, 33.203); integrity mandatory, confidentiality optional; no way around IPsec | `ipsec` per carrier = `IPsec_enabled`; when on, a REGISTER only ever completes over IPsec: no Security-Server, SAs that will not install, or silence over them mean a new attempt with sec-agree after a back-off |
| 5.2.2 | Security-Client `alg=hmac-sha-2-256-128` with `ealg=aes-cbc` and `ealg=null`; without sha-2-256, `alg=hmac-sha-1-96` with the same two | `hmac-sha-1-96` with `aes-cbc,null` for SKT and KT. `hmac-sha-2-256-128` needs the TS 33.220 KDF for its ESP key, which is not implemented yet |
| 5.2.3 | SIP R-URI with `user=phone` and the local number; tel URI with `phone-context`; tel preferred | INVITE: `tel:` with `phone-context`; MESSAGE: `sip:<number>@<domain>;user=phone` (Samsung's `UriGeneratorKr` does the same for all three) |
| 5.4.2 | Table 5-4: AMR-WB and AMR-NB each octet-aligned and bandwidth-efficient, WB/NB telephone-event, ptime 20, maxptime 120, b=AS, b=RS:0, b=RR:2500, o= username = the phone number | `sdp-tta` and the `pt-*-be` PTs for SKT and KT; LG U+ keeps its recorded offer |
| 5.5 | the TTA VoLTE management object over OMA-DM: P-CSCF, SIP timers, ports, payload types, `SMS_PSI`, `IPsec_enabled`, ... | no DM client; these come from carriers.conf |
| 6.2.5 | AMR and AMR-WB in both RFC 4867 payload formats | both: an offer's per-PT fmtp decides, octet-aligned preferred when both are offered, and the answer mirrors it |
| 9 | the network does SMS over NAS or over IP (DM decides); the UE supports both | `sms-over-ip` per carrier |
| 9.3 | MO-SMS Request-URI = the SMS PSI from DM | `sms-psi` per carrier; without it, the destination as above |

Not implemented: EVS, video, emergency calls and registration (8.2, R6's roaming
emergency registration), supplementary services beyond what the network does itself.

## Other evidence

A Korean write-up of VoLTE on Quectel modems on all three networks
(https://blog.naver.com/jhnotepad/223505876518, 2024-07-08). That is
modem-side IMS set through AT commands and NV items, so it is not this
approach, but it records what the networks accept:

- KT and SKT want a non-carrier device's IMEI registered with them: KT as
  "PTA-VoLTE" (or it shows up as OPENMODEL4 after a USIM change), SKT as
  "OMD 기타LTE핸드셋_VOLTE". LG U+ needs nothing.
- KT's User-Agent there is `TTA-VoLTE/3.0 EC25E/A04 Device_Type/Modem OMD`:
  TTA 3.0 with the `OMD` operator token.
- SKT's IMS domain is `sktims.net`, as in the stock profile. The post makes
  MO-SMS work on SKT by turning on SMS over IMS (`+g.3gpp.smsip`), where
  Samsung's stock SKT profile leaves SMS on NAS: SKT seems to take both.
  imsroha keeps stock's choice; `sms-over-ip=true` in [carrier] tries the other.
