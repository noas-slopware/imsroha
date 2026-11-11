# Spacebar patches

Upstream project: Spacebar, https://invent.kde.org/plasma-mobile/spacebar

Apply to: **6.3.4** (the PKGBUILD here, based on the AUR's).
Upstream license: GPL-2.0-only OR GPL-3.0-only.

Patches, in order:

- `0001-daemon-close-the-connection-after-every-MMSC-request.patch`: `Connection: close`
  after every MMSC request. LG U+'s MMSC answers an M-Send.req on a keep-alive
  connection with "format corrupt" (0xe2), as Android's MmsService avoids too.
- `0002-Parse-national-own-numbers-and-late-modem-country-co.patch`: an own number
  stored nationally (010..., as Korean SIMs do) no longer becomes `+010...`, so an
  incoming MMS stops listing the user as a recipient and keeps its attachments; also
  a modem country code that arrives late.
- `0003-daemon-store-a-received-message-only-once.patch`: a message still listed when
  the modem appears is no longer stored (and notified) twice.
- `0004-database-remember-the-transport-of-a-message-SMS-MMS.patch`: a `transport`
  column (NULL for SMS/MMS, `rcs`).
- `0005-daemon-RCS-chat-through-IMSroha-when-it-is-there.patch`: 1-to-1 text over RCS
  through `imsroha-rcs` (`codes.noa.IMSroha.Rcs`, see `docs/rcs.md`) when the peer has
  chat; SMS otherwise and when RCS fails.
- `0006-app-mark-RCS-messages-show-when-the-other-side-is-ty.patch`: RCS messages are
  marked "Chat", typing is shown, displayed reports go back when a chat is read.
- `0007-daemon-app-send-and-receive-files-over-RCS-through-I.patch`: file transfer over
  RCS (`SendFile`, `FileReceived`, `FileReceiveFailed`). Received files become
  attachments like MMS parts; sending uses RCS when the peer has ft-http and falls
  back to MMS. Needs `[rcs] download-dir=` set to a directory the user owns.

0004-0007 are inert without imsroha-rcs on the bus. Build: `cd spacebar && makepkg -sC`
(`-C`: 0004 creates a file, so a stale `src/` makes `prepare()` fail).
