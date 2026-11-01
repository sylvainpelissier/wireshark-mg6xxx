# Wireshark Paradox MG6xxx dissector

The serial communication with a Paradox MG6xxx panel is encrypted. This Lua dissector decrypts and decodes it,
which makes it possible to debug the commands sent to the panel and the panel's
replies.

It works on USB captures of the panel's serial adapter (it registers as a
heuristic dissector on `usb.bulk`). The adapter can split frames across USB
transfers, so the dissector reassembles them and checks the CRC of each frame.

## Usage

Requires Wireshark 4.6 or later (for the Lua gcrypt bindings).

```sh
wireshark -X lua_script:mg6xxx.lua capture.pcapng
```

or copy `mg6xxx.lua` to `~/.local/lib/wireshark/plugins/` to load it
automatically.

The settings are under *Preferences > Protocols > MG6xxx*, and the display
filter prefix is `mg6xxx`.

## Session key

All data frames (command `0x24`) are encrypted with AES-256 using a session key
the panel generates at login:

1. The PC sends a login request containing the username and a credential
   derived from the PC password.
2. The panel answers with a login reply encrypted with the **PC password**.
   This reply contains the session id (selector and mode) and the 16-byte
   **session key**.
3. All following data frames of that session are encrypted with the session
   key.

So decryption needs two things:

- **The PC password.** Set it in the *PC password* preference (default:
  `admin`). It decrypts the login reply.
- **The login in the capture.** The session key is taken from the login reply
  and used for the rest of the capture. It is shown in the decrypted login
  reply as *Session key* (`mg6xxx.login.session_key`).

If the capture starts in the middle of a session (no login in it), take the
session key from an earlier capture that has the login and paste it into the
*Session keys (hex)* preference. Several keys can be given, separated by
commas or spaces. Each key is only used if it decrypts a header that matches
the frame's session selector and mode, so a wrong key is never applied.

Without a session key, data frames are flagged with a "No session key" expert
note and their payload is shown encrypted.

## What is decoded

Frame layout: `DE | cmd (LE16) | LEN (LE16) | lenA | lenB | A | B | body | CRC16-MODBUS (LE)`

| Command | Supported |
| --- | --- |
| `0x00` Identify | Frame header |
| `0x01` Login | Request (password block, username) and reply (status, decrypted session id, session key and user label) |
| `0x24` Data | Decrypted header (transaction id, fragment, ack/data, service, session) and the records below |
| Other, N × 37-byte body | Cleartext events sent by the panel (zone OK/open, partition arm/disarm/alarm), using the layout from [bmpc/mg6250_mqtt](https://github.com/bmpc/mg6250_mqtt). Not yet checked against a capture. |

Data frame services:

- **`0x17` Objects**: reads and writes of panel objects:
  - zone, keypad, repeater and siren serials and labels;
  - panel clock (date, battery and AC voltage; the voltage scale is assumed);
  - user codes (BCD; seen when changing a user code);
  - zone status (open/closed);
  - the system change counter that BabyWare polls.
- **`0x18` Control**: arm, arm stay, arm sleep and disarm.
- **`0x1a` Programming**: the begin/end markers BabyWare puts around writes.

Anything not recognised is shown as "Uninterpreted", so the remaining bytes
are still visible.

## Tested hardware

Tested only with an MG6250 panel. Other MG6xxx panels using the same protocol
may work but have not been tested.
