# Phase 1.5: ModemManager backend switch for b2q-imsd

Design only. No ModemManager source lives in this repo and nothing here is applied to
one. The goal is that plasma-dialer and spacebar keep speaking only
`org.freedesktop.ModemManager1` and keep working unmodified, while MM's Voice and
Messaging paths are served by `b2q-imsd` over SIP instead of by the QMI voice/SMS
services this modem does not publish.

Precedent for the packaging: the phone's libqmi fork — Arch PKGBUILD, patches applied
in `prepare()`, rebuilt as user `build`, `pkgrel` bumped. Same shape here.

## 1. Constraints

- **MM's D-Bus API does not change.** No new interfaces, properties, methods or signals
  visible to apps; `org.freedesktop.ModemManager1.xml` stays byte-identical. Call
  objects stay at `/org/freedesktop/ModemManager1/Call/<n>`, SMS at
  `/org/freedesktop/ModemManager1/SMS/<n>`, owned by MM's existing state machines.
- **One backend switch**, not a second code path smeared through the plugin. Default
  build behaves exactly like upstream, including with no daemon present.
- **MM never manages the IMS PDN.** The bearer belongs to imsd's own WDS client.
  Touching `mm_iface_modem_count_bearers` is what crashed MM twice on 2026-11-07.
- Patch set stays small and upstream-shaped so it can be dropped when MM grows real
  IMS support.

Symbol names below are the ones MM uses today (`mm-iface-modem-voice.c`,
`mm-call.c`, `mm-sms-qmi.c`, ...). Confirm each against the exact `modemmanager`
version packaged for the phone before writing a patch: `sources.lock` pins no MM.

## 2. Shape of the patch

New internal interface, one header, one implementation per backend:

```
src/mm-ims-backend.h          MMImsBackend (GInterface-like struct of ops)
src/mm-ims-backend-none.c     default: every call returns MM_CORE_ERROR_UNSUPPORTED
src/mm-ims-backend-b2q.c      sd-bus client for org.b2q.Imsd
```

Proposed ops (minimum for Phase 1.5):

```
create_call(backend, number, out call_id)
hangup_call(backend, call_id)
send_sms(backend, number, text, out ref)
```

Plus a signal-handler registration for incoming call / incoming SMS / state changes.
`mm-modem.c` (or the QMI plugin's `mm-broadband-modem-qmi.c`) gets one pointer,
`MMImsBackend *ims_backend`, created by the same place that chooses plugin/build
variant. `mm_ims_backend_is_available()` is the single question the voice and messaging
paths ask.

Selection: a udev property on the modem device, `ID_MM_B2Q_IMS=1`, set by a udev rule
shipped in the same package. One rule, per-device, reversible with `udevadm test`, and
it keeps the switch out of the D-Bus surface. Without the property, MM builds the none
backend and behaves as it does today.

Split into four patches, each independently reviewable:

1. `0001-ims-add-backend-interface.patch` — header, none backend, meson wiring, udev
   property read, `ims_backend` field on `MMModem`.
2. `0002-ims-voice-outgoing.patch` — `handle_create_call` in
   `mm-iface-modem-voice.c` delegates to the backend; `MMCall` objects still created
   and owned by MM.
3. `0003-ims-messaging-outgoing.patch` — new `mm-sms-ims.c` implementing `MMSms`'s
   send path for the backend; `mm-iface-modem-messaging.c` picks it when the backend is
   available instead of `mm-sms-qmi.c`.
4. `0004-ims-incoming-inject.patch` — internal, non-D-Bus entry points (§5).

`meson.build`: nothing optional to toggle in the end — the backend compiles whenever
`libsystemd` is available (MM already links it for sd-bus via `WITH_SYSTEMD_JOURNAL`?
check; if not, the none backend keeps `-Dims_backend=disabled` the default).

## 3. D-Bus contract between imsd and MM

Private to the two daemons; never exposed to apps. `b2q-imsd` already claims
`org.b2q.Imsd` at `/org/b2q/Imsd`.

Existing:

```
GetState() -> i           0 down, 1 registering, 2 up
```

Added for the backend (kept to what the two MM paths need):

```
CreateCall(s number) -> u call_id
HangupCall(u call_id)
SendSms(s number, s text) -> s ref
```

```
signal RegistrationStateChanged(i state)
signal CallAdded(u call_id, s number, i direction)
signal CallStateChanged(u call_id, i state, i reason)
signal SmsReceived(s ref, s number, s text, t timestamp)
signal SmsDeliveryReport(s ref, i status)
```

State numbers are imsd's own enum, mapped in `mm-ims-backend-b2q.c` to
`MMCallState` / `MMSmsState` / `MMModemState` (`MM_CALL_STATE_DIALING`,
`RINGING_OUT`, `RINGING_IN`, `ACTIVE`, `HELD`, `WAITING`, `TERMINATED`;
`MM_SMS_STATE_SENDING`, `SENT`, `DELIVERED`; ...). Map there, not in imsd, so imsd
never encodes ModemManager's ABI.

Backend lifetime: name-owner watch on `org.b2q.Imsd` with
`org.freedesktop.DBus.NameOwnerChanged`; appearance and disappearance flip
`mm_ims_backend_is_available()` and emit the modem's state change that makes MM re-sync.
No timers, no polling — D-Bus signals and PJSIP's ioqueue only, consistent with Phase 1.

## 4. Outgoing

**Voice.** `handle_create_call()` (org.freedesktop.ModemManager1.Modem.Voice) keeps
its argument validation and its `MMCall` creation, then:

- backend available → `create_call(number)`; the returned `call_id` is stored on the
  `MMCall` as the backend handle, state starts at `MM_CALL_STATE_DIALING`, and
  `CallAdded` reaches apps through MM exactly as it does for QMI calls.
- backend unavailable or the call fails → return the same error apps see today
  (`MM_CORE_ERROR_UNSUPPORTED` from the missing QMI voice service). No silent fallback
  into a code path that cannot work on this modem.

`MMCall`'s state machine and its D-Bus properties (`Number`, `Direction`, `State`,
`StateReason`, `AudioPort`, `AudioFormat`) stay MM's. `AudioPort`/`AudioFormat` are
reported empty/`unknown` — audio is out of scope until q6voice exists; the field is
already optional in MM. Hangup and DTMF go through `hangup_call` and are refused with
`MM_CORE_ERROR_UNSUPPORTED` until imsd implements them.

**SMS.** `Messaging` (`org.freedesktop.ModemManager1.Modem.Messaging`) still creates the
`MMSms` object, keeps `Create`/`List`/`Delete`, and emits `Added`. Only the transport
changes: `mm-sms-ims.c` implements `send`/`store`-less behaviour by calling `send_sms()`
and driving `MM_SMS_STATE_SENDING` → `SENDING`-failed or `SENT`/`DELIVERED` from
`SmsDeliveryReport`. `+CMGS`-style refs are imsd's `SmsReceived` `ref`, opaque to MM's
API. Segment handling (multipart concatenation) stays in imsd: MM's `MMSms` already has
`Text`/`Data` and the RP-DATA reassembly belongs next to the SIP MESSAGE codec.

## 5. Incoming

New internal functions, declared in headers, called only by the backend client inside
MM's process — **not** D-Bus methods:

```
mm_iface_modem_voice_inject_incoming_call(modem, number, backend_call_id, ...)
mm_iface_modem_messaging_inject_incoming_sms(modem, number, text, ref, timestamp, ...)
```

Each mirrors what the QMI indication handlers do today (create `MMCall`/`MMSms`, insert
into the modem's list, emit `CallAdded`/`Added` and the `Messaging::Added` signal), but
takes plain values instead of QMI TLVs. `backend_call_id` is stored on the `MMCall` so
`CallStateChanged` can find the object; unknown ids are logged and dropped, never
asserted on.

Ordering guarantee: the `CallAdded`/`SmsReceived` signal is processed in MM's main
context before the corresponding state change, so apps always see the object first.
The QMI plugin's voice/messaging interfaces must be running with the plugin disabled
for those services (the modem has no ims/imsa), so there is no double source: with the
backend available, `MMIfaceModemVoice` reports no QMI voice support and leaks nothing.

## 6. Failure and fallback

| situation | behaviour |
|---|---|
| imsd not built/installed | none backend; MM exactly as today |
| imsd installed but not running | backend unavailable, calls/SMS fail with `UNSUPPORTED` (today's behaviour) |
| imsd dies mid-call | active calls move to `MM_CALL_STATE_TERMINATED` with `MM_CALL_STATE_REASON_UNKNOWN`; MM emits the normal hangup signal |
| imsd starts after MM | name-owner watch flips availability, modem state re-emitted, no restart needed |
| SIP REGISTER not up | `create_call`/`send_sms` return an error; imsd decides (queueing is imsd's business, not MM's) |

No path may create, remove or re-count MM bearers; no path may call
`mm_bearer_list_*` for the IMS PDN.

## 7. Packaging (phone side, not executed from this repo)

Same pattern as the libqmi fork: keep `pkgname=modemmanager`, bump `pkgrel`, apply the
four patches in `prepare()`, build as user `build` with `makepkg`, install with
`pacman -U`. The package keeps `install=/usr/lib/systemd/system/ModemManager.service`,
which is what makes the `b2q-ims.conf` drop-in path stable.

Repo layout when the patches are actually written (proposed, not created here):

```
patches/modemmanager/0001-ims-add-backend-interface.patch
patches/modemmanager/0002-ims-voice-outgoing.patch
patches/modemmanager/0003-ims-messaging-outgoing.patch
patches/modemmanager/0004-ims-incoming-inject.patch
userspace/rootfs/usr/lib/udev/rules.d/99-b2q-ims.rules    ID_MM_B2Q_IMS=1
```

The udev rule and the drop-in ship in the same package, so an unpatched MM never sees
a property it does not handle.

## 8. Verification

- `mmcli -m <n> --voice-create-call="+82..."` then `mmcli -m <n> --voice-list-calls`:
  object appears at `.../Call/1`, `State` walks dialing → active with the backend
  available and without any QMI voice service.
- `mmcli -m <n> --messaging-create-sms="text=...,number=+82..."` then
  `--messaging-send`; the SIP MESSAGE is accepted and the object reaches `sent`.
- plasma-dialer places and ends a call; spacebar sends an SMS and shows an incoming
  one, with no app-side change and no side bus.
- `busctl introspect org.freedesktop.ModemManager1 $(mmcli -m <n> --voice)` and
  `busctl tree` before/after the patch: identical interface set.
- Regression: internet bearer still works, `org.freedesktop.ModemManager1` still
  exports Modem3gpp/Simple/Cdma as before, and MM does not restart.

## 9. Non-goals and open questions

Out of scope: audio (q6voice/adsp), ViLTE, RCS/UT, SS/UT interface, emergency calls,
MM's `Messaging` storage, any app-side change, any new app-visible D-Bus API.

Open:

- Whether `MMCall` can be fully driven with no `MMBearer` attached (audio port lookup
  is bearer-scoped). If not, the backend passes a null bearer and the call still
  exports zeroed audio properties.
- Whether MM's Voice interface requires a SIM to be present for `CreateCall`; the
  IMS identity is on ISIM and MM reads the USIM, so a `SIM_MISSING` guard may have to
  be relaxed for the backend path only.
- Supporting-security (IPsec) if LG U+ requires it on REGISTER; that is imsd's
  problem, invisible to this patch.
