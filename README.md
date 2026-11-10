# ModemManager patches

Upstream project: ModemManager, https://gitlab.freedesktop.org/mobile-broadband/ModemManager

Apply to: **1.24.2** (the tag the phone's `modemmanager` package is built from).
Upstream license: GPL-2.0-or-later.

Patches, in order:

- `0001-broadband-modem-qmi-add-b2q-imsd-backend-for-voice-a.patch` connects the
  Voice and Messaging interfaces to `b2q-imsd` over D-Bus when the modem port carries
  `ID_MM_B2Q_IMS`.
- `0002-port-qmi-reset-only-the-default-mux-link-on-IPA.patch` is kept for reference
  and is **not** applied. Skipping the parent reset and deleting only `qmapmux0.0`
  preserves `qmapmux0.3` but makes WDA report `raw-ip` with aggregation disabled for
  the default endpoint, so every bearer connect fails with
  `No more data format combinations supported`. The full reset is required until the
  WDA/DPM path is reworked.
- `0003-iface-modem-do-not-abort-when-the-bearer-count-exceeds.patch` turns the
  `max >= ctx.count` assertion into a warning when ModemManager is stopped with an
  active bearer, so it does not dump core during a restart.
- `0004-call-ims-send-DTMF-through-b2q-imsd.patch` implements `SendDtmf` on the IMS
  call: it forwards the digits to `org.b2q.Imsd.SendDtmf`, which sends them as RFC 4733
  `telephone-event` packets. Without it ModemManager answers every `SendDtmf` with
  "Sending dtmf is not supported by this modem".

## What 0002 tried, and why it is not applied

`internal_reset()` used to bring `rmnet_ipa0` down and call
`qmi_device_delete_all_links()`. On b2q the IPA data path carries more than one PDN:
`b2q-ims-bearer` keeps profile 4 on mux id 3 as `qmapmux0.3` on the same parent.
Deleting every link destroyed the IMS bearer, `b2q-imsd` deregistered, and VoLTE went
away whenever ModemManager restarted.

For the `ipa` net driver 0002 skips the parent reset and deletes only
`qmapmux0.0`, the default link ModemManager owns and recreates. A missing link is not
fatal, because the first setup has nothing to delete. The deletion callback completes
the reset task, so `internal_setup_data_format()` still runs with the same `QmiDevice`
and the WDA and DPM negotiation sequence is unchanged.

That keeps `qmapmux0.3`, but WDA then reports the wrong data format for the default
endpoint (see the 0002 entry above), so the shipped package keeps the full reset: a
ModemManager restart still deletes `qmapmux0.3`, and `b2q-ims-bearer` and `b2q-imsd`
come back on their own a few seconds later. The real fix needs the WDA/DPM rework
described in `PLAN-IMS-COEXISTENCE.md`. If 0002 is revived, do not skip the reset task
completion, or the data format setup machine does not start.

## Build

`PKGBUILD` is the local b2q recipe at `pkgrel=11`, with 0001, 0003 and 0004 applied in
`prepare()`. Build on the phone as the `build` user:

```sh
su build -c 'cd /home/build/modmgr-links && makepkg -s --noconfirm'
```

Install as root with `pacman -U`. Restart `ModemManager` and check:

```sh
ip -br link | grep qmapmux
systemctl status b2q-ims-bearer b2q-imsd
```

With the full reset, `qmapmux0.3` is deleted on the restart; `b2q-ims-bearer` brings it
back within its restart delay and `b2q-imsd` registers again. `qmapmux0.0` comes back
when ModemManager reconnects the data bearer.

Authors: Noa Himesaka <himesaka@noa.codes>.

The patches are `git format-patch` output against the upstream release; apply with
`patch -p1` or `git apply`. They are licensed like the project they patch. The
PKGBUILD is MIT.
