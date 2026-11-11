# ModemManager patches

Upstream project: ModemManager, https://gitlab.freedesktop.org/mobile-broadband/ModemManager

Apply to: **1.24.2**.
Upstream license: GPL-2.0-or-later.

Patches, in order:

- `0001-broadband-modem-qmi-add-imsroha-backend-for-voice-and-messaging.patch` connects the
  Voice and Messaging interfaces to `imsroha` over D-Bus when the modem port carries
  `ID_MM_IMSROHA`.
- `0002-port-qmi-reset-only-the-default-mux-link-on-IPA.patch` is kept for reference
  and is **not** applied. Skipping the parent reset and deleting only `qmapmux0.0`
  preserves `qmapmux0.3` but makes WDA report `raw-ip` with aggregation disabled for
  the default endpoint, so every bearer connect fails with
  `No more data format combinations supported`. The full reset is required until the
  WDA/DPM path is reworked.
- `0003-iface-modem-do-not-abort-when-the-bearer-count-exceeds.patch` turns the
  `max >= ctx.count` assertion into a warning when ModemManager is stopped with an
  active bearer, so it does not dump core during a restart.
- `0004-call-ims-send-DTMF-through-imsroha.patch` implements `SendDtmf` on the IMS
  call: it forwards the digits to `codes.noa.IMSroha.SendDtmf`, which sends them as RFC 4733
  `telephone-event` packets. Without it ModemManager answers every `SendDtmf` with
  "Sending dtmf is not supported by this modem".
- `0005-port-qmi-keep-the-IPA-QMAP-data-path-when-another-PDN.patch` is option 4 of
  `PLAN-IMS-COEXISTENCE.md`. While `rmnet_ipa0` carries a link ModemManager does not
  own (the IMS PDN's `qmapmux0.3`), ModemManager reads the data format without opening
  the DPM port (DPM Open Port puts the endpoint back to raw-ip without aggregation,
  visible at every boot). If the modem already runs raw-ip with QMAP aggregation, it
  keeps that and deletes only its own `qmapmux0.0`; otherwise it runs the full setup as
  before. The first version (1.24.2-12) kept the path whenever the IMS link existed: on a
  boot where `imsroha-bearer` came up before ModemManager's first connect, the modem was
  never switched to QMAP, rmnet dropped every downlink packet, and IMS did not register
  (2026-11-11 04:05-04:12).

- `0006-broadband-modem-qmi-leave-SMS-with-the-modem-where-the-carrier-has-no-SMS-over-IP.patch`
  keeps Messaging on the modem's own WMS path when imsroha's carrier profile for the
  SIM says `sms-over-ip=false` (SKT), and hands only Voice to imsroha there.
- `0007-netlink-fix-use-after-free-calling-completion_fn-on-transaction-completion.patch`
  is upstream 9317cbc4 (Dan Williams, 2026-10-04), after 1.24.2: `transaction_complete()`
  freed the transaction through the hash table before calling its `completion_fn`. On
  the Flip3 a NetworkManager restart made ModemManager reconnect and crash there (a jump
  to 0x30), and LTE stayed down for 30 s while it restarted and probed again.
- `0008-broadband-modem-qmi-hand-port-addressed-SMS-to-imsroha.patch` is for the
  carriers of 0006: there the modem receives the RCS OTP (a binary SMS to application
  port 37273) over WMS, and ModemManager, which ignored the port header, showed it in
  the messaging app while imsroha-rcs never got it. It parses the application port IEs
  (TS 23.040 9.2.3.24.4/5, IEI 0x04 and 0x05) into the `MMSmsPart`. With the imsroha
  backend, a received SMS-DELIVER part for any port but WAP push (2948, 2949) goes to
  `codes.noa.IMSroha.TakePortPdu` as `00` (no SMSC address) plus the TPDU in hex, the
  form `PortPduReceived` carries, instead of the SMS list, and is then deleted from
  modem storage. Every part of a concatenated one goes on its own. If imsroha is not
  there or refuses it, the part becomes a message as before. WAP push and modems
  without `ID_MM_IMSROHA` are unchanged.

## What 0002 tried, and why it is not applied

`internal_reset()` used to bring `rmnet_ipa0` down and call
`qmi_device_delete_all_links()`. On the Galaxy Z Flip3 the IPA data path carries more than one PDN:
`imsroha-bearer` keeps the IMS profile on mux id 3 as `imsroha0` (then `qmapmux0.3`) on the same parent.
Deleting every link destroyed the IMS bearer, `imsroha` deregistered, and VoLTE went
away whenever ModemManager restarted.

For the `ipa` net driver 0002 skips the parent reset and deletes only
`qmapmux0.0`, the default link ModemManager owns and recreates. A missing link is not
fatal, because the first setup has nothing to delete. The deletion callback completes
the reset task, so `internal_setup_data_format()` still runs with the same `QmiDevice`
and the WDA and DPM negotiation sequence is unchanged.

That keeps `qmapmux0.3`, but WDA then reports the wrong data format for the default
endpoint (see the 0002 entry above), so the shipped package keeps the full reset: a
ModemManager restart still deletes `qmapmux0.3`, and `imsroha-bearer` and `imsroha`
come back on their own a few seconds later. The real fix needs the WDA/DPM rework
described in `PLAN-IMS-COEXISTENCE.md`. If 0002 is revived, do not skip the reset task
completion, or the data format setup machine does not start.

## Build

`PKGBUILD` builds 1.24.2 with 0001 and 0003 to 0008 applied in `prepare()`:

```sh
makepkg -s
```

Install with `pacman -U`, restart `ModemManager` and check:

```sh
ip -br link | grep -e qmapmux -e imsroha
systemctl status imsroha-bearer imsroha
```

With the full reset, the IMS link (`imsroha0`) is deleted on the restart;
`imsroha-bearer` brings it back within its restart delay and `imsroha` registers
again. `qmapmux0.0` comes back when ModemManager reconnects the data bearer.

The patches are `git format-patch` output against the upstream release; apply with
`patch -p1` or `git apply`. They are licensed like the project they patch
(GPL-2.0-or-later). The PKGBUILD is GPL-3.0-only like the rest of this repository.
