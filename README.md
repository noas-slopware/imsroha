# imsd — userspace IMS for the Galaxy Z Flip3 (b2q)

`b2q-imsd` owns the IMS PDN and speaks SIP on it, so SMS and VoLTE signaling do not
depend on the modem's absent IMS app. Dialers never talk to it directly: the
ModemManager package carries a backend switch that delegates MM's Voice and Messaging
paths to this daemon over D-Bus (Phase 1.5), so plasma-dialer and spacebar stay
unmodified.

State right now: registration (ISIM AKA), SMS both ways, MMS notifications,
and VoLTE calls in and out work on LG U+. Received SMS go through a durable inbox
before the RP-ACK (`inbox.c`) and reach ModemManager as raw TPDUs. Call audio is
AMR-WB over RTP here, with the PCM handed to `b2q-ims-audio` in the user session,
which plays and records it through PipeWire.

## Layout and where each file ships

```
imsd/src/imsd.c                     daemon entry, D-Bus vtable (org.b2q.Imsd), event loop
imsd/src/sip.c, sip.h               SIP: REGISTER, MESSAGE (SMS), INVITE/BYE/CANCEL, RTP, AMR-WB
imsd/src/aka.c, aka.h               ISIM AKA: 401 RAND/AUTN -> UIM authenticate -> RES/CK/IK
imsd/src/sms.c, sms.h               MO-SMS RP-DATA/SMS-SUBMIT encoder
imsd/src/inbox.c, inbox.h           MT-SMS inbox in /var/lib/b2q-imsd/inbox (GetPendingPdus/AckPdu)
imsd/src/audio.c, audio.h           call PCM over /run/b2q-imsd/audio.sock to the user session
imsd/src/dbus.c, dbus.h             signal emitters + bus/path/error constants
imsd/src/ims_audio.c                b2q-ims-audio: user-session bridge between the socket and PipeWire
imsd/src/ims_bearer.c               b2q-ims-bearer: brings up and holds the IMS PDN on qmapmux0.3
imsd/src/vss_manager.c              b2q-vss-manager: VSS registration ungate at boot
imsd/systemd/b2q-imsd.service       ships to /usr/lib/systemd/system/b2q-imsd.service
imsd/systemd/b2q-ims-bearer.service ships to /usr/lib/systemd/system/b2q-ims-bearer.service
imsd/systemd/b2q-ims-audio.service  ships to /usr/lib/systemd/user/b2q-ims-audio.service
imsd/systemd/ModemManager.service.d/b2q-ims.conf
                                    ships to /usr/lib/systemd/system/ModemManager.service.d/b2q-ims.conf
imsd/packaging/PKGBUILD             on-phone aarch64 package recipe
```

For the repo's rootfs overlay the same two unit paths are written out as
`userspace/rootfs/usr/lib/systemd/system/b2q-imsd.service` and
`userspace/rootfs/usr/lib/systemd/system/ModemManager.service.d/b2q-ims.conf`. They are
**not** duplicated there: the package installs them (the file contents below are the
source of truth) and the overlay gets them from the package. `tools/build-rootfs.sh`
copies `userspace/rootfs/.` over the staged rootfs, so once the imsd package is in the
rootfs package list the copies come from `pacman`, not from this tree.

Ordering mirrors `b2q-sim-provision.service`:

- `After=`/`Wants=` `rmtfs.service` and `b2q-sim-provision.service`
- `Before=ModemManager.service`, with the reverse `After=`/`Wants=` in the MM drop-in
- `WantedBy=multi-user.target`

`rmtfs.service` is not in this repo; it comes from the `rmtfs` package on the phone.

## Packaging

`packaging/PKGBUILD` builds `b2q-imsd` for `aarch64` and installs the binary plus the two
unit files. It compiles all five `src/*.c` files in one gcc pass (there is no Makefile
yet), linking `libpjproject` and `libsystemd` through `pkg-config`.

- `depends=('pjproject' 'systemd-libs')` (`libsystemd` for sd-bus).
- `pjproject` 2.17-1 is installed on the phone (built there as `build`, installed
  `2026-11-07`), so `pkg-config --exists libpjproject` resolves and the recipe builds.
- `source=()` — the recipe takes the checkout path from `$B2Q_IMSD_SRC` because the tree
  is copied to the phone, not fetched.

On-phone steps (phone side, **not** run from this checkout and never run by an agent
without being asked):

```sh
scp -r userspace/imsd root@<phone>:/home/build/
su build -c 'cd /home/build/imsd/packaging && B2Q_IMSD_SRC=/home/build/imsd makepkg -s'
pacman -U b2q-imsd-0.1.0-1-aarch64.pkg.tar.zst
systemctl enable --now b2q-imsd.service
```

The ModemManager patch gets its own package, same precedent as the phone's libqmi fork
(Arch PKGBUILD, `provides`/`conflicts` against `modemmanager`, rebuilt as `build`).
Design and package notes: `PHASE15-MM-BACKEND.md`.

## Rules

- No polling loops anywhere: sd-event I/O and timers, QMI indications, sd-bus, poll() in the audio bridge.
- Never restart `rmtfs` while the modem is up.
- Do not create MM-managed second bearers; MM's `count_bearers` assertion has crashed it
  twice. The IMS PDN is this daemon's own WDS client.
