-- Paradox MG6xxx serial protocol, as seen in USB captures
-- of the panel's serial adapter.
--
-- Decodes what PAI implements: identify (0x00), login (0x01) and the
-- AES-encrypted record protocol (0x24): header, acks and service 0x17 object
-- reads (zone/keypad/repeater/siren labels and serials, panel clock), and
-- writes (op 0x01, e.g. a user code), the service 0x1a programming
-- session around them, service 0x18 control commands (arm, arm stay, arm
-- sleep, disarm), zone open/closed and alarm flags
-- (object 0x1e), partition exit delay/armed/alarm (object 0x25, provisional)
-- and the change counter BabyWare polls (object 0x1c).
-- Also the cleartext event frames the panel sends on its own, using the
-- layout of https://github.com/bmpc/mg6250_mqtt (paradox_serial_connect.py):
-- any other command whose body is N x 37 bytes. Not yet checked against a
-- capture: the command code of these frames is unknown.
-- Everything else is shown as "Uninterpreted".
--
-- Frame: DE | cmd (LE16) | LEN (LE16) | lenA | lenB | A | B | body | CRC16-MODBUS (LE)
--
-- Usage:
--   wireshark -X lua_script:mg6xxx.lua capture.pcapng
--   or copy this file to ~/.local/lib/wireshark/plugins/
-- The PC password (default "admin") is under Preferences > Protocols > MG6xxx.
-- Decryption needs the login in the capture: the session key comes from it.
-- For a capture started in the middle of a session, paste the key from the
-- earlier capture (field mg6xxx.login.session_key) into the "Session keys"
-- preference; each key is checked against the frame's selector and mode.
-- Requires Wireshark >= 4.6 (Lua gcrypt bindings).

local p = Proto("mg6xxx", "Paradox MG6xxx")

p.prefs.password = Pref.string("PC password", "admin",
    "PC password used to decrypt the login reply (the session key is in it)")
p.prefs.session_keys = Pref.string("Session keys (hex)", "",
    "For captures without the login: 16-byte session keys in hex, separated by "
        .. "commas or spaces. Copy one from Session key (mg6xxx.login.session_key) "
        .. "in the capture that has the login. A key is used only if the decrypted "
        .. "header matches the frame's selector and mode.")
p.prefs.bridge_port = Pref.uint("Serial bridge TCP port", 6638,
    "TCP port of a serial-over-TCP bridge (ESPHome stream_server, ser2net) carrying "
        .. "the panel's serial bytes. The panel is on the side using this port.")

local CMD = { [0x00] = "Identify", [0x01] = "Login", [0x24] = "Data" }
local LOGIN_STATUS = {
    [0x00] = "accepted",
    [0x05] = "busy (previous session still open)",
    [0x81] = "rejected: unknown session id",
    [0x83] = "rejected: unknown user",
    [0x84] = "rejected: bad PW_BLOCK credential",
    [0x85] = "busy (previous session still open)",
}
local KIND = { [0x40] = "Data", [0x80] = "Ack" }
local SERVICE = { [0x17] = "Objects", [0x18] = "Control", [0x1a] = "Programming", [0x22] = "Event log" }
local OP = { [0x00] = "Read", [0x01] = "Write" }
local OBJ = {
    [0x0001] = "Zone",
    [0x0003] = "Doorbell",
    [0x0005] = "PGM output",
    [0x0007] = "User",
    [0x0009] = "Keypad",
    [0x000b] = "Repeater",
    [0x000d] = "Siren",
    [0x0011] = "Phone number",
    [0x0015] = "IP receiver?",
    [0x0016] = "Account",
    [0x0017] = "System settings",
    [0x001c] = "System",
    [0x0019] = "Installer / PC login",
    [0x001a] = "Area",
    [0x001e] = "Zone status",
    [0x0024] = "Clock",
    [0x0025] = "Partition status",
}
-- objects whose field 0 is a serial and field 1 a 16-byte label
local LABELLED = { [0x0001] = true, [0x0009] = true, [0x000b] = true, [0x000d] = true }
local OBJ_CLOCK = 0x0024
-- Field 3: [2030] entry delay audio | [2031] exit delay audio (BabyWare wrote
-- 02 05 after selecting Tonality 3 for the exit delay, exit-delay-audio).
-- One byte each: the exit delay sound is not set per arm type.
local OBJ_SETTINGS = 0x0017
local DELAY_AUDIO = {
    [0] = "No tone",
    [1] = "Beeping",
    [2] = "Countdown",
    [3] = "Tonality 1",
    [4] = "Tonality 2",
    [5] = "Tonality 3",
    [6] = "Tonality 4",
}
-- Zone field 0: device (2) | definition | partition | options | ?
-- (change-zone: BabyWare wrote definition 09 -> 08 for zones 4-7)
local OBJ_ZONE = 0x0001
-- MG6250 programming guide, table 4 (BabyWare's names)
local ZONE_DEFINITION = {
    [0] = "Disabled",
    [1] = "Entry Delay 1",
    [2] = "Entry Delay 2",
    [3] = "Entry Delay 1 (Full Arm)",
    [4] = "Entry Delay 2 (Full Arm)",
    [5] = "Follow",
    [6] = "Follow (Sleep / Full Arm)",
    [7] = "Follow (Full Arm)",
    [8] = "Instant",
    [9] = "Instant (Sleep / Full Arm)",
    [10] = "Instant (Full Arm)",
    [11] = "Instant Fire",
    [12] = "Delayed Fire",
    [13] = "Instant Fire Silent",
    [14] = "Delayed Fire Silent",
    [15] = "24Hr Buzzer",
    [16] = "24Hr Burglary",
    [17] = "24Hr Hold Up",
    [18] = "24Hr Gas",
    [19] = "24Hr Heat",
    [20] = "24Hr Water",
    [21] = "24Hr Freeze",
    [22] = "24Hr Panic",
    [23] = "Follow No Pre-Alarm",
    [24] = "Instant No Pre-Alarm",
    [25] = "Keyswitch Maintain",
    [26] = "Keyswitch Momentary",
    [27] = "Entry Delay 1 (Sleep / Full Arm)",
    [28] = "Entry Delay 2 (Sleep / Full Arm)",
    [29] = "Unarmed",
    [33] = "Custom 1",
    [34] = "Custom 2",
    [35] = "Custom 3",
    [36] = "Custom 4",
}
-- table 5
local ZONE_PARTITION = { [1] = "Partition 1", [2] = "Partition 2", [3] = "Both partitions" }
-- table 6, options 4-5
local ZONE_ALARM_TYPE = { [0] = "Audible", [1] = "Silent", [2] = "Audible pulse", [3] = "Report only" }
local OBJ_SYSTEM = 0x001c -- field 1 byte 0: change counter
local OBJ_ZONE_STATUS = 0x001e -- field 0 byte 0: non-zero = open (04 in alarm), byte 1: flags
-- disarmed 00 00 00; exit delay 01 / 02 / 03 00 01, armed 05 / 06 / 07
-- 00 00 for stay / sleep / full arm (armed-stay-*, slepp-armed-*,
-- alarm-ir-etage); alarm (full arm, zone 15) 77 02 40, provisional.
-- Index 1-2: partition 1-2 (BabyWare reads both, #2 stayed zero).
local OBJ_PARTITION_STATUS = 0x0025
local ARM_MODE = { [0] = "Disarmed", [1] = "Stay", [2] = "Sleep", [3] = "Full" }

-- Cleartext events (bmpc/mg6250_mqtt): codes and sub-events it handles
local EVENT_LEN = 37
local EVENT = { [0] = "Zone OK", [1] = "Zone open", [2] = "Partition status" }
local PARTITION_EVENT = {
    [0x02] = "Silent alarm",
    [0x03] = "Buzzer alarm",
    [0x04] = "Steady alarm",
    [0x05] = "Pulse alarm",
    [0x07] = "Alarm stopped",
    [0x0b] = "Disarm",
    [0x0c] = "Arm",
}

local function is_event_frame(cmd, n)
    return not CMD[cmd] and n > 9 and (n - 9) % EVENT_LEN == 0
end
local SERVICE_OBJECTS = 0x17
local SERVICE_CONTROL = 0x18
local SERVICE_PROGRAMMING = 0x1a
local SERVICE_EVENT_LOG = 0x22
-- Event codes = the decimal event numbers of the MG6250 programming guide,
-- tables 11 and 12 (saved events). 489 stored events matched by date with
-- BabyWare's report (captures/events.pdf); its wording is used where known.
-- Table 10 (zone open/OK, partition status) is not saved in the log.
-- Sub-event is a number: { name, what it counts }
local LOG_EVENT_NUMBER = {
    [7] = { "Remote Access", "user" },
    [8] = { "Remote PGM1", "user" },
    [9] = { "Remote PGM2", "user" },
    [10] = { "Remote PGM3", "user" },
    [11] = { "Remote PGM4", "user" },
    [12] = { "Remote PGM5", "user" },
    [13] = { "Remote PGM6", "user" },
    [14] = { "User remote access granted", "user" },
    [15] = { "PGM activation via phone", "output" },
    [16] = { "Smoke beep acknowledgement", "zone" },
    [17] = { "TX delay zone", "zone" },
    [18] = { "Zone Signal Strength Weak 1", "zone" },
    [19] = { "Zone Signal Strength Weak 2", "zone" },
    [20] = { "Zone Signal Strength Weak 3", "zone" },
    [21] = { "Zone Signal Strength Weak 4", "zone" },
    [22] = { "Battery voltage level", "value" },
    [23] = { "DC voltage level", "value" },
    [24] = { "Fire delay started", "zone" },
    [25] = { "Fire delay cancelled", "zone" },
    [26] = { "User code entered", "user" },
    [28] = { "StayD pass acknowledgment", "zone" },
    [29] = { "Cold start", "zone" },
    [30] = { "Cold start PGM", "output" },
    [31] = { "Cold start keypad", "keypad" },
    [32] = { "Cold start repeater", "repeater" },
    [33] = { "Cold start siren", "siren" },
    [40] = { "Arming with User Code", "user" },
    [42] = { "Disarm with User Code", "user" },
    [43] = { "Disarm after Alarm with User Code", "user" },
    [44] = { "Cancel Alarm with User Code", "user" },
    [46] = { "Zone Bypassed on arming", "zone" },
    [47] = { "Zone in Alarm", "zone" },
    [48] = { "Fire alarm", "zone" },
    [49] = { "Zone Restore Alarm", "zone" },
    [50] = { "Fire alarm restore", "zone" },
    [51] = { "Zone shutdown", "zone" },
    [53] = { "Paramedic alarm", "user" },
    [57] = { "Tamper trouble", "zone" },
    [58] = { "Tamper restore", "zone" },
    [59] = { "Low battery", "zone" },
    [60] = { "Low battery restore", "zone" },
    [61] = { "Supervision trouble", "zone" },
    [62] = { "Supervision restore", "zone" },
    [63] = { "PGM tamper trouble", "PGM" },
    [64] = { "PGM tamper trouble restore", "PGM" },
    [65] = { "PGM supervision loss", "PGM" },
    [66] = { "PGM supervision loss restore", "PGM" },
    [67] = { "Keypad supervision loss", "keypad" },
    [68] = { "Keypad supervision loss restore", "keypad" },
    [69] = { "Keypad low battery", "keypad" },
    [70] = { "Keypad low battery restore", "keypad" },
    [71] = { "Keypad AC trouble", "keypad" },
    [72] = { "Keypad AC trouble restore", "keypad" },
    [73] = { "Repeater supervision loss", "repeater" },
    [74] = { "Repeater supervision loss restore", "repeater" },
    [75] = { "Repeater low battery", "repeater" },
    [76] = { "Repeater low battery restore", "repeater" },
    [77] = { "Repeater AC trouble", "repeater" },
    [78] = { "Repeater AC trouble restore", "repeater" },
    [79] = { "Siren tamper trouble", "siren" },
    [80] = { "Siren tamper trouble restore", "siren" },
    [81] = { "Siren supervision loss", "siren" },
    [82] = { "Siren supervision loss restore", "siren" },
    [83] = { "Siren low battery", "siren" },
    [84] = { "Siren low battery restore", "siren" },
    [85] = { "Siren AC trouble", "siren" },
    [86] = { "Siren AC trouble restore", "siren" },
}
-- Sub-event selects the event
local LOG_EVENT_SUB = {
    [6] = {
        [1] = "CLEAR + ENTER pressed",
        [3] = "Stay Arming",
        [4] = "Sleep Arming",
        [5] = "Arm in Force mode",
        [6] = "Full arm when armed in Stay mode",
        [7] = "PC fail to communicate",
        [8] = "Utility Key 1 pressed",
        [9] = "Utility Key 2 pressed",
        [10] = "Utility Key 3 pressed",
        [11] = "Utility Key 4 pressed",
        [12] = "Utility Key 5 pressed",
        [13] = "Utility Key 6 pressed",
        [14] = "Tamper generated alarm",
        [15] = "Supervision loss generated alarm",
        [16] = "Doorbell 1 battery trouble",
        [17] = "Doorbell 1 battery trouble restore",
        [18] = "Doorbell 2 battery trouble",
        [19] = "Doorbell 2 battery trouble restore",
        [20] = "Sleep to full arm",
        [21] = "Firmware upgrade",
        [22] = "Missing SIM card",
        [23] = "StayD mode activated",
        [24] = "StayD mode deactivated",
        [25] = "IP registration status change",
        [26] = "GPRS registration status change",
        [27] = "Remote access denied",
        [28] = "Fail to communicate to central station channel(s)",
        [29] = "Fail to communicate to central station channel(s) restore",
        [30] = "User call ended due to central polling",
    },
    [41] = {
        [0] = "Auto-arming",
        [1] = "Late to close",
        [2] = "No movement arming",
        [3] = "Partial Arming",
        [4] = "Quick Arming",
        [5] = "Software Arming",
        [6] = "Arming with keyswitch",
    },
    [45] = {
        [0] = "Auto-arm cancelled",
        [1] = "PC Disarm",
        [2] = "Disarmed After alarm with software",
        [3] = "Cancel Alarm with software",
        [4] = "Paramedic alarm cancelled",
        [5] = "Disarm with keyswitch",
        [6] = "Disarm with keyswitch after an alarm",
        [7] = "Alarm cancelled with keyswitch",
    },
    [52] = {
        [0] = "Panic emergency",
        [1] = "Panic medical",
        [2] = "Panic fire",
        [3] = "Recent closing",
        [4] = "Global shutdown",
        [5] = "Duress alarm",
        [6] = "Keypad lockout",
    },
    [54] = {
        [0] = "Power Up",
        [1] = "Test Report",
        [2] = "Software Access",
        [3] = "Software Access Finished",
        [4] = "Installer on site",
        [5] = "Installer out",
        [6] = "Closing delinquency delay elapsed",
        [7] = "Fail to arm",
    },
}
local LOG_TROUBLE = {
    [0] = "Telephone line",
    [1] = "AC Failure",
    [2] = "Battery failure",
    [3] = "RTC",
    [4] = "Console Tamper",
    [5] = "RF jamming",
    [6] = "GSM no service",
    [7] = "GSM Supervision",
    [8] = "IP no service",
    [9] = "IP supervision loss",
    [10] = "IP receiver lost",
    [11] = "Fail to communicate to central",
    [12] = "Fail to comm. personal reporting",
}
local LOG_TYPE = { [1] = "System", [2] = "Zone", [5] = "User" }
local LOG_OP = { [0x00] = "Read events", [0x01] = "Event range" }
local LOG_EVENT_LEN = 36

local function log_event_name(code, sub)
    local number = LOG_EVENT_NUMBER[code]
    if number then
        return string.format("%s, %s %d", number[1], number[2], sub)
    elseif code == 55 or code == 56 then
        local trouble = LOG_TROUBLE[sub] or string.format("sub %d", sub)
        return (code == 55 and "Trouble: " or "Trouble restore: ") .. trouble
    end
    local names = LOG_EVENT_SUB[code]
    return names and names[sub] or string.format("event %d sub %d", code, sub)
end
-- service 0x1a byte 0; BabyWare brackets every write with Begin ... End
local PROGRAMMING_OP = { [0x00] = "Begin", [0x01] = "End" }
local VOLTS_PER_STEP = 0.08 -- clock field 2 (battery, AC); one reading
-- receive-all: users 1-16, field 1 label, field 4 code (System Master's
-- matches the user code). 0x19 field 1 has the same layout and holds the
-- installer code (A6 27 for 0627: A = digit 0?); change-user-code wrote
-- 0x19, not 0x07. 0x19 field 3: login name and PC password, 16 bytes each.
local OBJ_USER = 0x0007
local OBJ_INSTALLER = 0x0019
local OBJ_AREA = 0x001a -- field 1 byte 0: exit delay (30 s, as on arming)
-- label field of objects whose field 0 is not a serial
local LABEL_FIELD = { [0x0003] = 1, [0x0005] = 1, [0x0007] = 1, [0x001a] = 2 }
-- service 0x18 action byte, one capture each
local CONTROL_ACTION = {
    [0x10] = "Disarm", -- arm-full-09
    [0x11] = "Arm stay", -- stay
    [0x12] = "Arm sleep", -- arm-sleep-09
    [0x13] = "Arm", -- arm-full-09
}

local DIR_IN = 1 -- USB IN endpoint: panel -> host

local f = {
    sof = ProtoField.uint8("mg6xxx.sof", "Start of frame", base.HEX),
    cmd = ProtoField.uint16("mg6xxx.cmd", "Command", base.HEX, CMD),
    len = ProtoField.uint16("mg6xxx.len", "Length", base.DEC),
    lena = ProtoField.uint8("mg6xxx.lena", "Field A length", base.DEC),
    lenb = ProtoField.uint8("mg6xxx.lenb", "Field B length", base.DEC),
    fielda = ProtoField.bytes("mg6xxx.fielda", "Field A (uninterpreted)"),
    fieldb = ProtoField.bytes("mg6xxx.fieldb", "Field B (uninterpreted)"),
    session = ProtoField.uint8("mg6xxx.session", "Session id", base.HEX),
    mode = ProtoField.uint8("mg6xxx.mode", "Session mode", base.HEX),
    crc = ProtoField.uint16("mg6xxx.crc", "CRC16-MODBUS", base.HEX),

    pw_header = ProtoField.bytes("mg6xxx.login.header", "PW block header"),
    client = ProtoField.bytes("mg6xxx.login.client", "Client field (not checked by the panel)"),
    pw_len = ProtoField.uint8("mg6xxx.login.pw_len", "PC password length", base.DEC),
    credential = ProtoField.bytes("mg6xxx.login.credential", "Credential (AES(pw, pw))"),
    pw_trailer = ProtoField.bytes("mg6xxx.login.trailer", "PW block trailer"),
    user_len = ProtoField.uint8("mg6xxx.login.user_len", "Username length", base.DEC),
    user = ProtoField.string("mg6xxx.login.user", "Username"),
    status = ProtoField.uint8("mg6xxx.login.status", "Login status", base.HEX, LOGIN_STATUS),
    login_enc = ProtoField.bytes("mg6xxx.login.encrypted", "Encrypted reply"),
    selector = ProtoField.uint8("mg6xxx.login.selector", "Selector (session id)", base.HEX),
    lmode = ProtoField.uint8("mg6xxx.login.mode", "Mode (session id, 2nd byte)", base.HEX),
    session_key = ProtoField.bytes("mg6xxx.login.session_key", "Session key"),
    user_label = ProtoField.string("mg6xxx.login.label", "User label"),

    enc_header = ProtoField.bytes("mg6xxx.data.enc_header", "Encrypted header"),
    tid = ProtoField.uint8("mg6xxx.data.tid", "Transaction id", base.DEC),
    frag = ProtoField.uint16("mg6xxx.data.frag", "Fragment", base.HEX),
    frag_num = ProtoField.uint16("mg6xxx.data.frag.num", "Number", base.DEC, nil, 0x7fff),
    frag_last = ProtoField.bool("mg6xxx.data.frag.last", "Last", 16, nil, 0x8000),
    kind = ProtoField.uint8("mg6xxx.data.kind", "Kind", base.HEX, KIND),
    service = ProtoField.uint8("mg6xxx.data.service", "Service", base.HEX, SERVICE),
    hsel = ProtoField.uint8("mg6xxx.data.selector", "Selector", base.HEX),
    hmode = ProtoField.uint8("mg6xxx.data.mode", "Mode", base.HEX),
    has_data = ProtoField.uint8("mg6xxx.data.has_data", "Has data", base.DEC),
    pad_count = ProtoField.uint8("mg6xxx.data.pad", "Padding count", base.DEC),
    enc_data = ProtoField.bytes("mg6xxx.data.encrypted", "Encrypted data"),

    op = ProtoField.uint8("mg6xxx.rec.op", "Operation", base.HEX, OP),
    rlen = ProtoField.uint8("mg6xxx.rec.len", "Record length", base.DEC),
    obj = ProtoField.uint16("mg6xxx.rec.obj", "Object", base.HEX, OBJ),
    idx = ProtoField.uint16("mg6xxx.rec.index", "Index", base.DEC),
    sel_fid = ProtoField.uint8("mg6xxx.rec.select", "Requested field", base.DEC),
    fid = ProtoField.uint8("mg6xxx.field.id", "Field id", base.DEC),
    flen = ProtoField.uint16("mg6xxx.field.len", "Field length", base.DEC),
    serial = ProtoField.bytes("mg6xxx.field.serial", "Serial (zero: nothing enrolled)"),
    -- zone field 0; options bits as the guide's table 6 (options 1-8 = bits 0-7):
    -- 87 on every zone, matching the defaults, alarm type audible
    zone_device = ProtoField.bytes("mg6xxx.field.zone_device",
        "Device (zero: nothing enrolled; part of the RF serial?)"),
    zone_def = ProtoField.uint8("mg6xxx.field.zone_definition", "Zone definition", base.DEC, ZONE_DEFINITION),
    zone_partition = ProtoField.uint8("mg6xxx.field.zone_partition", "Partition", base.DEC, ZONE_PARTITION),
    zone_options = ProtoField.uint8("mg6xxx.field.zone_options", "Options (provisional)", base.HEX),
    zone_opt_shutdown = ProtoField.bool("mg6xxx.field.zone_options.auto_shutdown",
        "Auto zone shutdown", 8, nil, 0x01),
    zone_opt_bypass = ProtoField.bool("mg6xxx.field.zone_options.bypassable", "Bypassable", 8, nil, 0x02),
    zone_opt_supervision = ProtoField.bool("mg6xxx.field.zone_options.rf_supervision",
        "RF supervision", 8, nil, 0x04),
    zone_opt_alarm_type = ProtoField.uint8("mg6xxx.field.zone_options.alarm_type", "Alarm type",
        base.DEC, ZONE_ALARM_TYPE, 0x18),
    zone_opt_intellizone = ProtoField.bool("mg6xxx.field.zone_options.intellizone",
        "Intellizone delay", 8, nil, 0x20),
    zone_opt_delay_tx = ProtoField.bool("mg6xxx.field.zone_options.delay_transmission",
        "Delay arm transmission", 8, nil, 0x40),
    zone_opt_force = ProtoField.bool("mg6xxx.field.zone_options.force_arming", "Force arming", 8, nil, 0x80),
    label = ProtoField.string("mg6xxx.field.label", "Label"),
    entry_audio = ProtoField.uint8("mg6xxx.field.entry_delay_audio", "Entry delay audio [2030]",
        base.DEC, DELAY_AUDIO),
    exit_audio = ProtoField.uint8("mg6xxx.field.exit_delay_audio", "Exit delay audio [2031]",
        base.DEC, DELAY_AUDIO),
    date = ProtoField.string("mg6xxx.field.date", "Panel date"),

    ev_seq = ProtoField.uint8("mg6xxx.event.seq", "Sequence", base.DEC),
    ev_event = ProtoField.uint8("mg6xxx.event.event", "Event", base.DEC, EVENT),
    ev_sub = ProtoField.uint8("mg6xxx.event.sub", "Sub-event", base.DEC),
    ev_area = ProtoField.uint8("mg6xxx.event.area", "Area", base.DEC),
    ev_date = ProtoField.string("mg6xxx.event.date", "Date"),
    ev_typed = ProtoField.uint8("mg6xxx.event.typed", "Typed (meaning unknown)", base.HEX),
    ev_label = ProtoField.string("mg6xxx.event.label", "Label"),

    log_op = ProtoField.uint8("mg6xxx.log.op", "Operation", base.HEX, LOG_OP),
    log_first = ProtoField.uint32("mg6xxx.log.first", "First event", base.HEX),
    log_last = ProtoField.uint32("mg6xxx.log.last", "Last event", base.HEX),
    log_count = ProtoField.uint32("mg6xxx.log.count", "Count", base.DEC),
    log_number = ProtoField.uint32("mg6xxx.log.number", "Event number", base.HEX),
    log_code = ProtoField.uint8("mg6xxx.log.code", "Event code", base.HEX),
    log_sub = ProtoField.uint8("mg6xxx.log.sub", "Sub-event (zone or user number)", base.DEC),
    log_area = ProtoField.uint8("mg6xxx.log.area", "Area", base.DEC),
    log_date = ProtoField.string("mg6xxx.log.date", "Date"),
    log_type = ProtoField.uint8("mg6xxx.log.type", "Label type", base.DEC, LOG_TYPE),
    log_label = ProtoField.string("mg6xxx.log.label", "Label"),
    ctl_serial = ProtoField.bytes("mg6xxx.control.serial", "Panel serial (as in the identify reply)"),
    battery = ProtoField.float("mg6xxx.field.battery", "Battery voltage (assumed 0.08 V/step)"),
    ac = ProtoField.float("mg6xxx.field.ac", "AC voltage (assumed 0.08 V/step)"),
    user_code = ProtoField.string("mg6xxx.field.user_code", "Code (BCD, first 4 digits)"),
    pc_login = ProtoField.string("mg6xxx.field.pc_login", "Login name"),
    pc_password = ProtoField.string("mg6xxx.field.pc_password", "PC password"),
    area_exit_delay = ProtoField.uint8("mg6xxx.field.area_exit_delay", "Exit delay (s)", base.DEC),
    user_code_rep = ProtoField.uint8("mg6xxx.field.user_code_rep",
        "Repeats digits 1-2 (in both captures; meaning unknown)", base.HEX),
    prog_op = ProtoField.uint8("mg6xxx.programming.op", "Programming", base.HEX, PROGRAMMING_OP),
    zone_open = ProtoField.bool("mg6xxx.field.zone_open", "Zone open"),
    -- zone status byte 1, provisional (alarm-ir-etage, set-sms)
    zone_flags = ProtoField.uint8("mg6xxx.field.zone_flags", "Zone flags (provisional)", base.HEX),
    zone_exit_delay = ProtoField.bool("mg6xxx.field.zone_exit_delay",
        "Exit delay (all zones, after arm)", 8, nil, 0x04),
    zone_in_alarm = ProtoField.bool("mg6xxx.field.zone_in_alarm", "In alarm", 8, nil, 0x10),
    zone_alarm_memory = ProtoField.bool("mg6xxx.field.zone_alarm_memory",
        "Alarm in memory (also set on a closed zone after an alarm)", 8, nil, 0x20),
    part_state = ProtoField.uint8("mg6xxx.field.partition_state", "State (provisional)", base.HEX),
    part_arming = ProtoField.uint8("mg6xxx.field.partition_arm_mode",
        "Arm mode (from the arm on, exit delay included)", base.DEC, ARM_MODE, 0x03),
    part_armed = ProtoField.bool("mg6xxx.field.partition_armed", "Armed (exit delay over)", 8, nil, 0x04),
    part_alarm = ProtoField.bool("mg6xxx.field.partition_alarm",
        "Alarm (0x10, 0x20, 0x40: all set in the one sample)", 8, nil, 0x70),
    part_flags2 = ProtoField.uint8("mg6xxx.field.partition_flags2",
        "Flags (alarm: 0x02, meaning unknown)", base.HEX),
    part_flags3 = ProtoField.uint8("mg6xxx.field.partition_flags3", "Flags", base.HEX),
    part_exit_delay = ProtoField.bool("mg6xxx.field.partition_exit_delay", "Exit delay", 8, nil, 0x01),
    part_alarm3 = ProtoField.bool("mg6xxx.field.partition_alarm3", "Alarm (meaning unknown)", 8, nil, 0x40),
    change_counter = ProtoField.uint8("mg6xxx.field.change_counter",
        "Change counter (BabyWare re-reads zone status when it changes)", base.DEC),
    ctl_action = ProtoField.uint8("mg6xxx.control.action", "Action", base.HEX, CONTROL_ACTION),

    uninterp = ProtoField.bytes("mg6xxx.uninterpreted", "Uninterpreted"),
    padding = ProtoField.bytes("mg6xxx.padding", "Padding"),
}
p.fields = f

local e_discard = ProtoExpert.new("mg6xxx.discarded", "Bytes outside a valid frame (lost bytes or bad CRC)",
    expert.group.MALFORMED, expert.severity.WARN)
local e_nokey = ProtoExpert.new("mg6xxx.nokey",
    "No session key: login not captured (set the Session keys preference) or wrong password",
    expert.group.DECRYPTION, expert.severity.NOTE)
p.experts = { e_discard, e_nokey }


-- ---------------------------------------------------------------------------
-- Paradox AES-256-ECB: standard AES on each 16-byte block transposed
-- (row-major state), key padded to 32 bytes with 0xEE.
-- ---------------------------------------------------------------------------
local function transpose(s)
    local out = {}
    for off = 0, #s - 16, 16 do
        for row = 0, 3 do
            for k = 0, 3 do
                local i = off + k * 4 + row + 1
                out[#out + 1] = s:sub(i, i)
            end
        end
    end
    return table.concat(out)
end

local ciphers = {}

local function decrypt(data, key)
    local n = #data - #data % 16
    if n == 0 then
        return ""
    end
    local c = ciphers[key]
    if not c then
        c = GcryptCipher.open(GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0)
        c:setkey(ByteArray.new((key .. string.rep("\xee", 32)):sub(1, 32), true))
        ciphers[key] = c
    end
    local out = c:decrypt(nil, ByteArray.new(transpose(data:sub(1, n)), true))
    return transpose(out:raw())
end

-- The panel encrypts a padded 48-byte login reply but sends 47 bytes: guess
-- the missing byte so the last block (end of the user label) decrypts, as PAI does.
local function decrypt_login_reply(enc, key)
    if #enc % 16 == 15 then
        for guess = 0, 255 do
            local plain = decrypt(enc .. string.char(guess), key)
            if plain:sub(-4) == string.rep("\xee", 4) then
                return plain
            end
        end
    end
    return decrypt(enc .. string.rep("\xee", -#enc % 16), key)
end

local function crc16(s)
    local crc = 0xFFFF
    for i = 1, #s do
        crc = crc ~ s:byte(i)
        for _ = 1, 8 do
            if crc & 1 == 1 then
                crc = (crc >> 1) ~ 0xA001
            else
                crc = crc >> 1
            end
        end
    end
    return crc
end

-- ---------------------------------------------------------------------------
-- Stream reassembly (first pass only; later passes reuse per_packet)
-- ---------------------------------------------------------------------------
local streams, devices, per_packet

local function reset()
    streams, devices, per_packet, ciphers = {}, {}, {}, {}
end
reset()
p.init = reset

local function body_offset(frame)
    return 8 + frame:byte(6) + frame:byte(7) -- 1-based index of the session id
end

-- A successful login reply carries the session key, encrypted with the PC password.
local function learn_session(dev, dir, frame)
    if dir ~= DIR_IN or frame:byte(2) ~= 0x01 or frame:byte(3) ~= 0x00 then
        return
    end
    local b = body_offset(frame)
    if frame:byte(b + 1) ~= 0x00 then
        return
    end
    local plain = decrypt_login_reply(frame:sub(b + 2, #frame - 2), p.prefs.password)
    if #plain >= 18 then
        devices[dev].key = plain:sub(3, 18)
    end
end

local function configured_keys()
    local keys = {}
    for word in p.prefs.session_keys:gmatch("[^,%s]+") do
        local hex = word:gsub("[:%-]", "")
        if #hex == 32 and hex:match("^%x+$") then
            keys[#keys + 1] = ByteArray.new(hex):raw()
        end
    end
    return keys
end

-- A data frame without a session key yet: try the configured keys. The right
-- one decrypts a header that repeats the frame's selector and mode.
local function find_session_key(dev, frame)
    if devices[dev].key or frame:byte(2) ~= 0x24 or frame:byte(3) ~= 0x00 then
        return
    end
    local b = body_offset(frame)
    local enc = frame:sub(b + 2, b + 17)
    if #enc < 16 then
        return
    end
    for _, key in ipairs(configured_keys()) do
        local header = decrypt(enc, key)
        if header:byte(8) == frame:byte(b) and header:byte(9) == frame:byte(b + 1) then
            devices[dev].key = key
            return
        end
    end
end

local function feed(dev, dir, data)
    local sk = dev .. "/" .. dir
    local buf = (streams[sk] or "") .. data
    local res = { frames = {}, discarded = 0 }
    while true do
        local i = buf:find("\xde", 1, true)
        if not i then
            res.discarded = res.discarded + #buf
            buf = ""
            break
        end
        if i > 1 then
            res.discarded = res.discarded + i - 1
            buf = buf:sub(i)
        end
        if #buf < 5 then
            break
        end
        local n = buf:byte(4) | (buf:byte(5) << 8)
        if n >= 9 and n <= 4096 then
            if #buf < n then
                break
            end
            local frame = buf:sub(1, n)
            if crc16(frame:sub(1, n - 2)) == (frame:byte(n - 1) | (frame:byte(n) << 8)) then
                find_session_key(dev, frame)
                res.frames[#res.frames + 1] = { data = frame, key = devices[dev].key }
                learn_session(dev, dir, frame)
                buf = buf:sub(n + 1)
                goto continue
            end
        end
        -- not a valid frame at this 0xDE: drop it and resynchronise
        res.discarded = res.discarded + 1
        buf = buf:sub(2)
        ::continue::
    end
    res.pending = #buf
    streams[sk] = buf
    return res
end

-- ---------------------------------------------------------------------------
-- Dissection
-- ---------------------------------------------------------------------------
local function add_uninterp(tree, t, o, e)
    if e > o then
        tree:add(f.uninterp, t(o, e - o))
    end
end

local function add_padding(tree, t, o)
    if t:len() > o then
        tree:add(f.padding, t(o, t:len() - o))
    end
end

local function dissect_login(t, o, e, tree, dir)
    if dir ~= DIR_IN then
        if e - o < 48 then
            add_uninterp(tree, t, o, e)
            return "Login request"
        end
        tree:add(f.pw_header, t(o, 3))
        tree:add(f.client, t(o + 3, 8))
        tree:add(f.pw_len, t(o + 11, 1))
        tree:add(f.credential, t(o + 12, 32))
        tree:add(f.pw_trailer, t(o + 44, 4))
        o = o + 48
        local user = ""
        if o < e then
            local ulen = t(o, 1):uint()
            tree:add(f.user_len, t(o, 1))
            if ulen > 0 and o + 1 + ulen <= e then
                tree:add(f.user, t(o + 1, ulen))
                user = t(o + 1, ulen):string()
            end
            o = o + 1 + ulen
        end
        add_uninterp(tree, t, o, e)
        return "Login request user=" .. user
    end

    if o >= e then
        return "Login reply"
    end
    local status = t(o, 1):uint()
    tree:add(f.status, t(o, 1))
    o = o + 1
    local info = "Login reply: " .. (LOGIN_STATUS[status] or string.format("status 0x%02x", status))
    if o >= e then
        return info
    end
    tree:add(f.login_enc, t(o, e - o))
    if status ~= 0x00 then
        return info
    end
    local plain = decrypt_login_reply(t(o, e - o):raw(), p.prefs.password)
    local d = ByteArray.new(plain, true):tvb("Decrypted login reply")
    local dt = tree:add(p, d(), "Decrypted login reply (PC password key)")
    if d:len() >= 39 then
        dt:add(f.selector, d(0, 1))
        dt:add(f.lmode, d(1, 1))
        dt:add(f.session_key, d(2, 16))
        dt:add(f.uninterp, d(18, 5))
        dt:add(f.user_label, d(23, 16))
        add_uninterp(dt, d, 39, d:len())
    else
        add_uninterp(dt, d, 0, d:len())
    end
    return info
end

-- Known field values; anything else is uninterpreted
local function interpret_value(rt, ft, obj, fid, v, size)
    if obj == OBJ_ZONE and fid == 0 and size >= 5 then
        ft:add(f.zone_device, v(0, 2))
        ft:add(f.zone_def, v(2, 1))
        ft:add(f.zone_partition, v(3, 1))
        local ot = ft:add(f.zone_options, v(4, 1))
        for _, o in ipairs({ f.zone_opt_shutdown, f.zone_opt_bypass, f.zone_opt_supervision,
            f.zone_opt_alarm_type, f.zone_opt_intellizone, f.zone_opt_delay_tx, f.zone_opt_force }) do
            ot:add(o, v(4, 1))
        end
        add_uninterp(ft, v, 5, size)
        local def = v(2, 1):uint()
        rt:append_text(": " .. (ZONE_DEFINITION[def] or string.format("definition %d", def)))
    elseif LABELLED[obj] and fid == 0 then
        ft:add(f.serial, v)
    elseif LABELLED[obj] and fid == 1 then
        ft:add(f.label, v)
        rt:append_text(": " .. v:string():gsub("[%z ]+$", ""))
    elseif obj == OBJ_ZONE_STATUS and fid == 0 then
        local open = v(0, 1):uint() ~= 0
        ft:add(f.zone_open, v(0, 1), open)
        rt:append_text(open and ": open" or ": closed")
        if size >= 2 then
            local flags = v(1, 1):uint()
            local zt = ft:add(f.zone_flags, v(1, 1))
            zt:add(f.zone_exit_delay, v(1, 1))
            zt:add(f.zone_in_alarm, v(1, 1))
            zt:add(f.zone_alarm_memory, v(1, 1))
            if flags & 0x10 ~= 0 then
                rt:append_text(", in alarm")
            elseif flags & 0x20 ~= 0 then
                rt:append_text(", alarm in memory")
            end
        end
        add_uninterp(ft, v, 2, size)
    elseif obj == OBJ_PARTITION_STATUS and fid == 0 and size >= 3 then
        local state, flags3 = v(0, 1):uint(), v(2, 1):uint()
        local st = ft:add(f.part_state, v(0, 1))
        st:add(f.part_arming, v(0, 1))
        st:add(f.part_armed, v(0, 1))
        st:add(f.part_alarm, v(0, 1))
        ft:add(f.part_flags2, v(1, 1))
        local t3 = ft:add(f.part_flags3, v(2, 1))
        t3:add(f.part_exit_delay, v(2, 1))
        t3:add(f.part_alarm3, v(2, 1))
        add_uninterp(ft, v, 3, size)
        local mode = string.lower(ARM_MODE[state & 0x03])
        if state & 0x70 ~= 0 then
            rt:append_text(": alarm")
        elseif flags3 & 0x01 ~= 0 then
            rt:append_text(": exit delay (" .. mode .. ")")
        elseif state & 0x04 ~= 0 then
            rt:append_text(": armed (" .. mode .. ")")
        elseif state == 0 then
            rt:append_text(": disarmed")
        end
    elseif obj == OBJ_SETTINGS and fid == 3 and size >= 2 then
        ft:add(f.entry_audio, v(0, 1))
        ft:add(f.exit_audio, v(1, 1))
        add_uninterp(ft, v, 2, size)
        local exit = v(1, 1):uint()
        rt:append_text(": exit delay audio " .. (DELAY_AUDIO[exit] or string.format("%d", exit)))
    elseif obj == OBJ_SYSTEM and fid == 1 then
        ft:add(f.change_counter, v(0, 1))
        add_uninterp(ft, v, 1, size)
    elseif obj == OBJ_CLOCK and fid == 2 and size >= 2 then
        -- 42 00 0c while BabyWare showed Battery 5.3 V, AC 0.0: 0.08 V/step
        -- fits that one reading; the third byte is unknown
        local battery = v(0, 1):uint() * VOLTS_PER_STEP
        local ac = v(1, 1):uint() * VOLTS_PER_STEP
        ft:add(f.battery, v(0, 1), battery):append_text(string.format(" V (raw %d)", v(0, 1):uint()))
        ft:add(f.ac, v(1, 1), ac):append_text(string.format(" V (raw %d)", v(1, 1):uint()))
        add_uninterp(ft, v, 2, size)
        rt:append_text(string.format(", battery %.1f V, AC %.1f V", battery, ac))
    elseif obj == OBJ_CLOCK and fid == 1 and size >= 6 then
        local date = string.format("%02d%02d-%02d-%02d %02d:%02d", v(0, 1):uint(), v(1, 1):uint(),
            v(2, 1):uint(), v(3, 1):uint(), v(4, 1):uint(), v(5, 1):uint())
        ft:add(f.date, v(0, 6), date)
        add_uninterp(ft, v, 6, size)
        rt:append_text(": " .. date)
    elseif LABEL_FIELD[obj] == fid then
        ft:add(f.label, v)
        rt:append_text(": " .. v:string():gsub("[%z ]+$", ""))
    elseif obj == OBJ_INSTALLER and fid == 3 and size >= 32 then
        ft:add(f.pc_login, v(0, 16))
        ft:add(f.pc_password, v(16, 16))
        add_uninterp(ft, v, 32, size)
    elseif obj == OBJ_AREA and fid == 1 then
        ft:add(f.area_exit_delay, v(0, 1))
        add_uninterp(ft, v, 1, size)
    elseif ((obj == OBJ_USER and fid == 4) or (obj == OBJ_INSTALLER and fid == 1)) and size >= 2 then
        -- 4225 -> 42 25 42 00, 1234 -> 12 34 12 00: byte 2 repeats the first
        -- two digits (a 6-digit field filled cyclically?); byte 3 unknown
        -- (00 in 0x19, 05 or 07 in the users)
        ft:add(f.user_code, v(0, 2), tostring(v(0, 2):bytes()))
        if size >= 3 then
            local rep = ft:add(f.user_code_rep, v(2, 1))
            if v(2, 1):uint() ~= v(0, 1):uint() then
                rep:append_text(" (differs from digits 1-2: not seen before)")
            end
        end
        add_uninterp(ft, v, 3, size)
    else
        ft:add(f.uninterp, v)
    end
end

local function dissect_records(d, tree, dir)
    local n = d:len()
    local i = 0
    local groups = {} -- {name, lo, hi} per run of the same op and object
    while i + 6 <= n do
        local len = d(i + 1, 1):uint()
        if len < 6 or i + len > n then
            break
        end
        local op = d(i, 1):uint()
        local obj = d(i + 2, 2):uint()
        local idx = d(i + 4, 2):uint()
        local rt = tree:add(p, d(i, len), string.format("Record: %s %s #%d",
            OP[op] or string.format("op 0x%02x", op), OBJ[obj] or string.format("object 0x%04x", obj), idx))
        rt:add(f.op, d(i, 1))
        rt:add(f.rlen, d(i + 1, 1))
        rt:add(f.obj, d(i + 2, 2))
        rt:add(f.idx, d(i + 4, 2))
        local e = i + len
        if op == 0x01 and dir ~= DIR_IN then
            -- write request: flags byte, then id | len (BE16) | value
            add_uninterp(rt, d, i + 6, math.min(i + 7, e))
            local j = i + 7
            while j + 3 <= e do
                local fid = d(j, 1):uint()
                local size = d(j + 1, 2):uint()
                if j + 3 + size > e then
                    break
                end
                local ft = rt:add(p, d(j, 3 + size), "Field " .. fid)
                ft:add(f.fid, d(j, 1))
                ft:add(f.flen, d(j + 1, 2))
                if size > 0 then
                    interpret_value(rt, ft, obj, fid, d(j + 3, size), size)
                end
                j = j + 3 + size
            end
            add_uninterp(rt, d, j, e)
        elseif op == 0x01 then
            -- write reply: 2 status bytes, then id | 2 bytes (00 00 so far) per field
            add_uninterp(rt, d, i + 6, math.min(i + 8, e))
            local j = i + 8
            while j + 3 <= e do
                local ft = rt:add(p, d(j, 3), "Field " .. d(j, 1):uint() .. " written")
                ft:add(f.fid, d(j, 1))
                ft:add(f.uninterp, d(j + 1, 2))
                j = j + 3
            end
            add_uninterp(rt, d, j, e)
        elseif op ~= 0x00 then
            add_uninterp(rt, d, i + 6, e)
        elseif dir ~= DIR_IN then
            -- read request: flags byte, then (field id, 00) pairs
            if i + 6 < e then
                rt:add(f.uninterp, d(i + 6, 1))
            end
            local j = i + 7
            while j + 2 <= e do
                rt:add(f.sel_fid, d(j, 1))
                if d(j + 1, 1):uint() ~= 0 then
                    rt:add(f.uninterp, d(j + 1, 1))
                end
                j = j + 2
            end
            add_uninterp(rt, d, j, e)
        else
            -- read reply: 2 status bytes, then id | status | len (BE16) | value
            add_uninterp(rt, d, i + 6, math.min(i + 8, e))
            local j = i + 8
            while j + 4 <= e do
                local fid = d(j, 1):uint()
                local size = d(j + 2, 2):uint()
                if j + 4 + size > e then
                    break
                end
                local ft = rt:add(p, d(j, 4 + size), "Field " .. fid)
                ft:add(f.fid, d(j, 1))
                if d(j + 1, 1):uint() ~= 0 then
                    ft:add(f.uninterp, d(j + 1, 1))
                end
                ft:add(f.flen, d(j + 2, 2))
                if size > 0 then
                    local v = d(j + 4, size)
                    interpret_value(rt, ft, obj, fid, v, size)
                end
                j = j + 4 + size
            end
            add_uninterp(rt, d, j, e)
        end
        local name = string.format("%s %s", OP[op] or string.format("op 0x%02x", op),
            OBJ[obj] or string.format("0x%04x", obj))
        local g = groups[#groups]
        if g and g.name == name then
            g.lo, g.hi = math.min(g.lo, idx), math.max(g.hi, idx)
        else
            groups[#groups + 1] = { name = name, lo = idx, hi = idx }
        end
        i = e
    end
    if i < n then
        tree:add(f.padding, d(i, n - i))
    end
    local parts = {}
    for _, g in ipairs(groups) do
        parts[#parts + 1] = g.name .. (g.lo == g.hi and (" #" .. g.lo) or string.format(" #%d-%d", g.lo, g.hi))
    end
    return #parts > 0 and (" " .. table.concat(parts, ", ")) or ""
end

-- Service 0x18 (arm-sleep-09, arm-full-09): request and reply both start
-- with 00 ff | 5 zero bytes | panel serial (as in the identify reply). The
-- request then has the action byte and 6 bytes that were 01 00 01 00 00 00 in
-- every capture (the partition is probably in there, not confirmed); the
-- reply has 3 bytes, 00 00 00 so far (status?).
local function dissect_control(d, len, tree, dir)
    if len < 11 then
        add_uninterp(tree, d, 0, len)
        add_padding(tree, d, len)
        return ""
    end
    tree:add(f.uninterp, d(0, 7))
    tree:add(f.ctl_serial, d(7, 4))
    local info
    if dir ~= DIR_IN then
        if len > 11 then
            local action = d(11, 1):uint()
            tree:add(f.ctl_action, d(11, 1))
            add_uninterp(tree, d, 12, len)
            info = " " .. (CONTROL_ACTION[action] or string.format("action 0x%02x", action))
        else
            info = " command"
        end
    else
        add_uninterp(tree, d, 11, len)
        info = " reply" .. (len > 11 and (" " .. tostring(d(11, len - 11):bytes()):lower()) or "")
    end
    add_padding(tree, d, len)
    return info
end

-- Service 0x1a: byte 0 begins (00) or ends (01) a programming session around
-- writes. The rest (00 00 00, ff ff ff ff, then 3c 00 on Begin: maybe a 60 s
-- timeout) and the reply's trailing 00 00 are not decoded.
local function dissect_programming(d, len, tree, dir)
    if len < 1 then
        add_padding(tree, d, 0)
        return ""
    end
    local op = d(0, 1):uint()
    tree:add(f.prog_op, d(0, 1))
    add_uninterp(tree, d, 1, len)
    add_padding(tree, d, len)
    return " " .. (PROGRAMMING_OP[op] or string.format("op 0x%02x", op)) .. (dir == DIR_IN and " reply" or "")
end

-- Service 0x22, records: op | len | ...; numbers are LE32.
-- range request 01: 00 01 01 | first | ff ff ff ff
-- range reply   01: 5 status | first | last | count
-- read request  00: 00 01 01 | first | last | 00 00 00 00
-- read reply    00: 5 status | first | last | count | events (one record per
--                   fragment, 5 events each)
-- event = number | 1f | code | sub-event | area | century year month day hour
--         minute | 5 unknown | label type | label (16)
local function dissect_event_log(d, tree, dir)
    local n = d:len()
    local i = 0
    local info = ""
    while i + 2 <= n and d(i, 1):uint() ~= 0xee do
        local op, len = d(i, 1):uint(), d(i + 1, 1):uint()
        if len < 2 or i + len > n then
            break
        end
        local name = LOG_OP[op] or string.format("op 0x%02x", op)
        local rt = tree:add(p, d(i, len), "Record: " .. name)
        rt:add(f.log_op, d(i, 1))
        rt:add(f.rlen, d(i + 1, 1))
        local head = dir == DIR_IN and 7 or 5
        if op > 0x01 or len < head + 8 then
            add_uninterp(rt, d, i + 2, i + len)
        else
            add_uninterp(rt, d, i + 2, i + head)
            local a = i + head
            rt:add_le(f.log_first, d(a, 4))
            rt:add_le(f.log_last, d(a + 4, 4))
            local first, last = d(a, 4):le_uint(), d(a + 4, 4):le_uint()
            local text = last == 0xffffffff and string.format(" 0x%x", first)
                or string.format(" 0x%x-0x%x", first, last)
            rt:append_text(text)
            info = info .. " " .. name .. text
            a = a + 8
            if a + 4 <= i + len then
                if dir == DIR_IN then
                    rt:add_le(f.log_count, d(a, 4))
                else
                    add_uninterp(rt, d, a, a + 4)
                end
                a = a + 4
            end
            while dir == DIR_IN and op == 0x00 and a + LOG_EVENT_LEN <= i + len do
                local date = string.format("%02d%02d-%02d-%02d %02d:%02d", d(a + 8, 1):uint(), d(a + 9, 1):uint(),
                    d(a + 10, 1):uint(), d(a + 11, 1):uint(), d(a + 12, 1):uint(), d(a + 13, 1):uint())
                local ename = log_event_name(d(a + 5, 1):uint(), d(a + 6, 1):uint())
                local et = rt:add(p, d(a, LOG_EVENT_LEN),
                    string.format("Event 0x%x: %s, %s", d(a, 4):le_uint(), date, ename))
                et:add_le(f.log_number, d(a, 4))
                add_uninterp(et, d, a + 4, a + 5)
                et:add(f.log_code, d(a + 5, 1))
                et:add(f.log_sub, d(a + 6, 1))
                et:add(f.log_area, d(a + 7, 1))
                et:add(f.log_date, d(a + 8, 6), date)
                add_uninterp(et, d, a + 14, a + 19)
                et:add(f.log_type, d(a + 19, 1))
                et:add(f.log_label, d(a + 20, 16))
                a = a + LOG_EVENT_LEN
            end
            add_uninterp(rt, d, a, i + len)
        end
        i = i + len
    end
    add_padding(tree, d, i)
    return info
end

local function dissect_data(t, o, e, tree, dir, key, root)
    if o >= e then
        return "Data"
    end
    tree:add(f.mode, t(o, 1))
    o = o + 1
    if e - o < 16 then
        add_uninterp(tree, t, o, e)
        return "Data"
    end
    tree:add(f.enc_header, t(o, 16))
    if not key then
        root:add_proto_expert_info(e_nokey)
        add_uninterp(tree, t, o + 16, e)
        return "Data (no session key)"
    end
    local h = ByteArray.new(decrypt(t(o, 16):raw(), key), true):tvb("Decrypted header")
    local ht = tree:add(p, h(), "Header (session key)")
    ht:add(f.tid, h(0, 1))
    if h(1, 1):uint() ~= 0 then
        ht:add(f.uninterp, h(1, 1))
    end
    local fragt = ht:add_le(f.frag, h(2, 2))
    fragt:add_le(f.frag_num, h(2, 2))
    fragt:add_le(f.frag_last, h(2, 2))
    ht:add(f.kind, h(4, 1))
    ht:add(f.service, h(5, 1))
    if h(6, 1):uint() ~= 0 then
        ht:add(f.uninterp, h(6, 1))
    end
    ht:add(f.hsel, h(7, 1))
    ht:add(f.hmode, h(8, 1))
    ht:add(f.padding, h(9, 7))

    local tid, frag = h(0, 1):uint(), h(2, 2):le_uint()
    local kind, service = h(4, 1):uint(), h(5, 1):uint()
    local info = string.format("%s tid=%d frag=%d%s %s", KIND[kind] or string.format("kind 0x%02x", kind),
        tid, frag & 0x7fff, frag & 0x8000 ~= 0 and "L" or "",
        SERVICE[service] or string.format("svc 0x%02x", service))
    o = o + 16
    if o >= e then
        return info
    end
    tree:add(f.has_data, t(o, 1))
    local has = t(o, 1):uint()
    o = o + 1
    if has == 0 or o >= e then
        add_uninterp(tree, t, o, e)
        return info
    end
    tree:add(f.pad_count, t(o, 1))
    local pad = t(o, 1):uint()
    o = o + 1
    if o >= e then
        return info
    end
    tree:add(f.enc_data, t(o, e - o))
    local d = ByteArray.new(decrypt(t(o, e - o):raw(), key), true):tvb("Decrypted data")
    local dt = tree:add(p, d(), "Data (session key)")
    if service == SERVICE_OBJECTS then
        info = info .. dissect_records(d, dt, dir)
    elseif service == SERVICE_EVENT_LOG then
        info = info .. dissect_event_log(d, dt, dir)
    elseif service == SERVICE_CONTROL or service == SERVICE_PROGRAMMING then
        -- the panel's padding count is one more than the bytes it pads
        local len = d:len() - pad + (dir == DIR_IN and pad > 0 and 1 or 0)
        len = math.max(0, math.min(len, d:len()))
        if service == SERVICE_CONTROL then
            info = info .. dissect_control(d, len, dt, dir)
        else
            info = info .. dissect_programming(d, len, dt, dir)
        end
    else
        add_uninterp(dt, d, 0, d:len())
    end
    return info
end

-- event = seq | 5 unknown | event | sub-event | area | century year month
-- day hour minute | 5 unknown | typed | label (16)
local function dissect_events(t, o, e, tree)
    local infos = {}
    while o + EVENT_LEN <= e do
        local v = t(o, EVENT_LEN)
        local event, sub = v(6, 1):uint(), v(7, 1):uint()
        local date = string.format("%02d%02d-%02d-%02d %02d:%02d", v(9, 1):uint(), v(10, 1):uint(),
            v(11, 1):uint(), v(12, 1):uint(), v(13, 1):uint(), v(14, 1):uint())
        local label = v(21, 16):string():gsub("[%z ]+$", "")
        local name = EVENT[event] or string.format("Event %d", event)
        if event == 2 then
            name = name .. ": " .. (PARTITION_EVENT[sub] or string.format("sub-event %d", sub))
        end
        local et = tree:add(p, v, string.format("Event: %s, area %d, %s, %s", name, v(8, 1):uint(), date, label))
        et:add(f.ev_seq, v(0, 1))
        et:add(f.uninterp, v(1, 5))
        et:add(f.ev_event, v(6, 1))
        local st = et:add(f.ev_sub, v(7, 1))
        if event == 2 and PARTITION_EVENT[sub] then
            st:append_text(" (" .. PARTITION_EVENT[sub] .. ")")
        end
        et:add(f.ev_area, v(8, 1))
        et:add(f.ev_date, v(9, 6), date)
        et:add(f.uninterp, v(15, 5))
        et:add(f.ev_typed, v(20, 1))
        et:add(f.ev_label, v(21, 16))
        infos[#infos + 1] = name .. (label ~= "" and (" " .. label) or "")
        o = o + EVENT_LEN
    end
    add_uninterp(tree, t, o, e)
    return "Event: " .. table.concat(infos, ", ")
end

local function dissect_frame(t, root, dir, key)
    local n = t:len()
    local cmd = t(1, 2):le_uint()
    if is_event_frame(cmd, n) then
        local ft = root:add(p, t(), "Frame: cleartext events")
        ft:add(f.sof, t(0, 1))
        ft:add_le(f.cmd, t(1, 2))
        ft:add_le(f.len, t(3, 2))
        ft:add(f.uninterp, t(5, 2)) -- the field A/B lengths in other frames
        local info = dissect_events(t, 7, n - 2, ft)
        ft:add_le(f.crc, t(n - 2, 2)):append_text(" [correct]")
        ft:append_text(": " .. info)
        return info
    end
    local ft = root:add(p, t(), "Frame: " .. (CMD[cmd] or string.format("command 0x%04x", cmd)))
    ft:add(f.sof, t(0, 1))
    ft:add_le(f.cmd, t(1, 2))
    ft:add_le(f.len, t(3, 2))
    ft:add(f.lena, t(5, 1))
    ft:add(f.lenb, t(6, 1))
    local o = 7
    local la, lb = t(5, 1):uint(), t(6, 1):uint()
    if la > 0 then
        ft:add(f.fielda, t(o, la))
    end
    o = o + la
    if lb > 0 then
        ft:add(f.fieldb, t(o, lb))
    end
    o = o + lb
    local e = n - 2
    local info
    if o < e then
        ft:add(f.session, t(o, 1))
        o = o + 1
    end
    if cmd == 0x00 then
        add_uninterp(ft, t, o, e)
        info = dir == DIR_IN and "Identify reply" or "Identify"
    elseif cmd == 0x01 then
        info = dissect_login(t, o, e, ft, dir)
    elseif cmd == 0x24 then
        info = dissect_data(t, o, e, ft, dir, key, root)
    else
        add_uninterp(ft, t, o, e)
        info = string.format("Command 0x%04x", cmd)
    end
    ft:add_le(f.crc, t(n - 2, 2)):append_text(" [correct]")
    ft:append_text(": " .. info)
    return info
end

-- Decode the serial bytes of one packet; dev names the link (USB device or
-- TCP connection), dir is DIR_IN for panel -> host.
local function dissect_bytes(tvb, pinfo, tree, dev, dir)
    if not pinfo.visited then
        if not devices[dev] then
            -- claim a device on its first frame start: DE + a known command,
            -- or a length that fits cleartext events
            if tvb:len() < 5 or tvb(0, 1):uint() ~= 0xde then
                return false
            end
            local cmd, len = tvb(1, 2):le_uint(), tvb(3, 2):le_uint()
            if not CMD[cmd] and not is_event_frame(cmd, len) then
                return false
            end
            devices[dev] = {}
        end
        per_packet[pinfo.number] = feed(dev, dir, tvb:raw())
    end
    local res = per_packet[pinfo.number]
    if not res then
        return false
    end

    local who = dir == DIR_IN and "Panel→Host" or "Host→Panel"
    pinfo.cols.protocol = "MG6xxx"
    local root = tree:add(p, tvb(), "Paradox MG6xxx, " .. who)
    if res.discarded > 0 then
        root:add_proto_expert_info(e_discard, string.format("%d bytes discarded (no valid frame)", res.discarded))
    end
    local infos = {}
    for i, fr in ipairs(res.frames) do
        local t = ByteArray.new(fr.data, true):tvb(#res.frames > 1 and ("MG6xxx frame " .. i) or "MG6xxx frame")
        infos[#infos + 1] = dissect_frame(t, root, dir, fr.key)
    end
    if res.pending > 0 then
        root:add(p, tvb(), string.format("%d bytes buffered until the frame completes", res.pending))
    end
    pinfo.cols.info = who .. " " .. (#infos > 0 and table.concat(infos, "; ") or "[frame continues]")
    return true
end

local function heuristic(tvb, pinfo, tree)
    -- USB addresses are "host" and "bus.device.endpoint". They are set even
    -- when no tree is built (first pass), unlike usb.* field values.
    local src, dst = tostring(pinfo.src), tostring(pinfo.dst)
    local dir, ep
    if dst == "host" then
        dir, ep = DIR_IN, src
    elseif src == "host" then
        dir, ep = 0, dst
    end
    local dev = ep and ep:match("^(%d+%.%d+)%.%d+$")
    if tvb:len() == 0 or not dev then
        return false
    end
    return dissect_bytes(tvb, pinfo, tree, dev, dir)
end

p:register_heuristic("usb.bulk", heuristic)

-- Serial-over-TCP bridge: the TCP payload is the raw serial stream, split
-- anywhere; feed() reassembles the frames per connection and direction.
function p.dissector(tvb, pinfo, tree)
    local port = p.prefs.bridge_port
    local dir
    if pinfo.src_port == port then
        dir = DIR_IN
    elseif pinfo.dst_port == port then
        dir = 0
    else
        return 0
    end
    -- One link per bridge, not per TCP connection: the panel keeps its
    -- session when the client reconnects (seen when the ESP32 dropped it).
    local panel = dir == DIR_IN and pinfo.src or pinfo.dst
    local dev = string.format("tcp %s:%d", tostring(panel), port)
    if tvb:len() == 0 or not dissect_bytes(tvb, pinfo, tree, dev, dir) then
        return 0
    end
    return tvb:len()
end

local registered_port
local function register_bridge_port()
    local tcp = DissectorTable.get("tcp.port")
    if registered_port then
        tcp:remove(registered_port, p)
    end
    registered_port = p.prefs.bridge_port
    tcp:add(registered_port, p)
end
p.prefs_changed = register_bridge_port
register_bridge_port()
