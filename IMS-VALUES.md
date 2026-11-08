# IMS PDN values baked into b2q-imsd

Source: ModemManager debug logs captured read-only on 2026-11-07 22:16 (same boot,
no disconnect) plus the `ims_bearer.py` holder's logged `Get Current Settings` result.
`evidence/SM-F711N-m0.md`, "Phase 0 MM-identical IMS setup confirms modem gate".

**These are recorded values, not choices.** Do not change, round, renumber or
"correct" any of them to fit a convention; if the modem hands out something different
on a later boot, record the new values and flag the difference instead.

## PDN / WDS

| item | value |
|---|---|
| APN | `ims` |
| 3GPP profile | 4 (`lte_ims`), APN and PDP stored in modem EFS |
| IP family | IPv6 |
| MUX id | 3 |
| data format | EMBEDDED / 1 (`rmnet` mux, QMAPv5, raw-ip) |
| MTU | 1400 |
| interface | `qmapmux0.3` |
| address | `2001:4430:1055:864b:ecee:e210:6fc9:6cff/64` |
| gateway | `2001:4430:1055:864b:edb1:6ec5:aca3:bea9` |
| DNS | `2001:4430:5:601:2::1`, `2001:4430:4:601::1` |
| P-CSCF | via PCO first; the PCO flag is set on the WDS start result |

Dotted-quad/profile notes that matter when coding the WDS calls:

- The client that started the network is the only one that can read the settings back.
  A fresh client gets `QMI_ERR_OUT_OF_CALL` (15) from `Get Current Settings`. imsd must
  do `Start Network` itself and keep the WDS client that owns the handle.
- Video/IPv4 are not part of this PDN; do not add a second WDS client for it.
- The mux link flags on the working bearer: `ingress-map-cksumv5` +
  `egress-map-cksumv5`; `ip -d` shows only `INGRESS_DEAGGREGATION`, which matches
  ModemManager's own internet link, so it is not the reason traffic is gated.
- Link/address/route are created by imsd, not by NetworkManager or ModemManager.
  Never let MM create a bearer for this PDN: `mm_iface_modem_count_bearers`' assertion
  `(max >= ctx.count)` has crashed MM twice.

## P-CSCF discovery order

1. PCO from the WDS `Start Network` result (authoritative; the flag is set).
2. 3GPP DNS realm: `ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org`.
3. Carrier fallback.

For LG U+ (`45006`) the realm would be `ims.mnc006.mcc450.3gppnetwork.org`, with the
MNC zero-padded to three digits in the usual 3GPP way.

**UNCONFIRMED against the carrier.** `45006` -> `mnc006` is the 3GPP padding
convention, not something we have seen U+ use, and nothing in the evidence shows that
this realm exists or that it resolves to a P-CSCF for this subscription. Treat step 2
as a candidate only: keep the name in the code behind the PCO path, log which source
produced the P-CSCF, and only then decide. Do not present it as the carrier's realm.

## Not baked in, deliberately

- A-PLMN/realm for SIP (`ims.mnc006...` above) is discovery input, not a constant.
- ISIM identities (IMPI/IMPU) and AKA material come from the UIM ISIM application over
  QMI, never from this file.
- The address/gateway are per-PDN-session values. The constants above are the
  recorded ones; code should still take what `Start Network` returns and only fall
  back to these for logging/diagnostics.
