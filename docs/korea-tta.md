# Korean VoLTE: TTAK.KO-06.0357 and the stock profiles

The Korean carriers share one terminal standard, TTAK.KO-06.0357 "사업자 간 UICC
이동성 제공을 위한 VoLTE 단말 규격" (VoLTE terminal for UICC portability between
operators). R6 (2026-06-26, 64 pages) is current. TTA only hands out the PDF after
a login, so what follows is from R5 (2022-06-29), read from the public copy at
https://www.scribd.com/document/935960136/TTAK-KO-06-0357R5-2. Check it against R6
when someone has that file. A January 2026 news piece says the standard was being
changed because it let terminals without end-to-end encryption onto the core
(https://www.mt.co.kr/tech/2026/01/26/2026012520060256692), and R6 may be that change.

The second source is Samsung's IMS profile in the stock SM-F711N firmware
F711NKSSFKZH5 (imsservice.apk, res/raw/imsprofile.json and friends), which is
where data/carriers.conf takes its SKT and KT values from.

## What R5 requires, and where imsroha is

| R5 | requirement | imsroha |
|---|---|---|
| 5.2.1 | ICSI `urn:urn-7:3gpp-service.ims.icsi.mmtel` in Contact; `+g.3gpp.smsip` when the UE does SMS over IP | yes; smsip per carrier (`sms-over-ip`) |
| 5.2.1 | `User-Agent: TTA-VoLTE/4.0 <model>/<sw> Device_Type/<type> <operator>`, operator = the carrier that first sold the device: `SKT` / `KT` / `LGU` / `OMD` (open market) / token. 5.2.2 says `TTA-VoLTE/3.0` in the same document | template per carrier. Stock Samsung sends `TTA-VoLTE/3.0` and its OMC code (SKC/KTC/LUC) of the SIM's network; LG U+ has accepted `TTA-VoLTE/1.0 ... LUC` |
| 5.2.1 | SUBSCRIBE to the reg event package (TS 24.229 5.1.1.3); stop after 489 | `reg-event` per carrier (on for SKT and KT, off for LG U+ as recorded); one dialog, refreshed with each registration; a NOTIFY that terminates our contact re-registers. Stock: `subscribe_for_reg` true |
| 5.2.1 | Contact `+sip.instance` with the IMEI URN (TS 23.003 13.8) | `sip-instance` per carrier (on for SKT and KT); the IMEI comes from QMI DMS |
| 5.2.1 | ISIM IMPU: one record = normal and emergency; two = first emergency, second normal. No ISIM: temporary IMPU from the IMSI | yes (the record on the home domain; without an ISIM the temporary IMPU registers and everything else uses the first P-Associated-URI) |
| 5.2.1 | 305 on re-registration: another P-CSCF; 503 without Retry-After = 500; try every P-CSCF from DM/PCO, then a new IMS PDN | P-CSCF list with failover on timeouts |
| 5.2.2 | IMS-AKA, sec-agree and IPsec (TS 24.229, 33.203); integrity mandatory, confidentiality optional; **if IPsec negotiation fails, go on without sec-agree/IPsec** | `ipsec` per carrier, with that fallback |
| 5.2.2 | Security-Client default `alg=hmac-sha-2-256-128, prot=esp, ealg=aes-cbc`; without sha-2-256, `alg=hmac-sha-1-96, prot=esp, ealg=aes-cbc` | `ipsec-alg` / `ipsec-ealg`. Stock offers `hmac-sha-1-96` with `aes-cbc` (SKT, LG U+) or `null,aes-cbc` (KT) |
| 5.2.2 | unprotected REGISTER: `Authorization` with `algorithm=AKAv1-MD5` | the first REGISTER carries an empty Authorization without algorithm (what LG U+ answers to) |
| 5.2.3 | SIP R-URI with `user=phone` and the local number; tel URI with `phone-context`; tel preferred | INVITE: `tel:` with `phone-context`; MESSAGE: `sip:<number>@<domain>;user=phone` (Samsung's `UriGeneratorKr` does the same for all three) |
| 5.5 | the TTA VoLTE management object over OMA-DM: P-CSCF, SIP timers, ports, payload types, `SMS_PSI`, `IPsec_enabled`, ... | no DM client; these come from carriers.conf |
| 9.1 | SMS over NAS or over IP, as the DM server says | `sms-over-ip` per carrier |
| 9.3 | MO-SMS Request-URI = the SMS PSI from DM | `sms-psi` per carrier; without it, the destination as above |
