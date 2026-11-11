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

- `0008-app-decode-attachment-images-for-the-screen-s-pixels.patch`: attachment images
  are decoded for the screen's pixels. Qt scales `Image.sourceSize` by the device pixel
  ratio only for SVG/PDF, so photos were decoded at the logical size and looked blurry
  on a scaled display (2.6 on the Galaxy Z Flip3). Not IMS-specific; for upstream.

- `0009-daemon-send-RCS-read-reports-for-messages-that-arriv.patch`: read reports for
  messages that arrive in the chat on screen. They are stored as read at once, so
  `markChatAsRead` (where 0005 sends `MarkDisplayed`) never sees them; `saveMessage`
  sends it then, unless the screen is locked.

- `0010-daemon-RCS-chatbot-messages-through-IMSroha.patch`: RCS chatbot messages
  (`RichMessageReceived`): RCC.07 rich cards and carousels, TTA R9's extended bot
  message and open rich card, texts with suggestions. Stored with their body, chip
  list and bot ID (new columns, a `BotInfo` table), and a readable summary as the
  text, which the list, the notification and any fallback show. Suggestion responses
  (`SendSuggestionResponse`, never as SMS) and chatbot information (`GetBotInfo`,
  kept a day). A shared `lib/chatbot` reads the formats.
- `0011-app-show-RCS-chatbot-messages-their-suggestions-and-.patch`: the app side:
  header and footer outside the card, cards, carousels, open rich cards, the chip
  list under the newest message, the actions (URL, dial, map, calendar, draft, copy,
  share as copy), pictures fetched into the conversation's attachment folder, the
  bot's name, icon and description, and no input where R9 says the sender takes no
  replies. Needs Qt Network (in qt6-base).

0004-0007 and 0009-0011 are inert without imsroha-rcs on the bus. Build: `cd spacebar && makepkg -sC`
(`-C`: 0004 creates a file, so a stale `src/` makes `prepare()` fail).
