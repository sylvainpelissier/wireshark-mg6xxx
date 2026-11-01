-- Paradox MG6xxx serial protocol, as seen in USB captures
-- of the panel's serial adapter.
--
-- Decodes what PAI implements: identify (0x00), login (0x01) and the
-- AES-encrypted record protocol (0x24): header, acks and service 0x17 object
-- reads (zone/keypad/repeater/siren labels and serials, panel clock), and
-- writes (op 0x01, e.g. a user code), the service 0x1a programming
-- session around them, service 0x18 control commands (arm, arm stay, arm
-- sleep, disarm), zone open/closed
-- (object 0x1e) and the change counter BabyWare polls (object 0x1c).
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
local SERVICE = { [0x17] = "Objects", [0x18] = "Control", [0x1a] = "Programming" }
local OP = { [0x00] = "Read", [0x01] = "Write" }
local OBJ = {
    [0x0001] = "Zone",
    [0x0009] = "Keypad",
    [0x000b] = "Repeater",
    [0x000d] = "Siren",
    [0x001c] = "System",
    [0x0019] = "User",
    [0x001e] = "Zone status",
    [0x0024] = "Clock",
}
-- objects whose field 0 is a serial and field 1 a 16-byte label
local LABELLED = { [0x0001] = true, [0x0009] = true, [0x000b] = true, [0x000d] = true }
local OBJ_CLOCK = 0x0024
local OBJ_SYSTEM = 0x001c -- field 1 byte 0: change counter
local OBJ_ZONE_STATUS = 0x001e -- field 0 byte 0: 1 = open

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
-- service 0x1a byte 0; BabyWare brackets every write with Begin ... End
local PROGRAMMING_OP = { [0x00] = "Begin", [0x01] = "End" }
local VOLTS_PER_STEP = 0.08 -- clock field 2 (battery, AC); one reading
local OBJ_USER = 0x0019 -- field 1: code, BCD (change-user-code captures)
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
    label = ProtoField.string("mg6xxx.field.label", "Label"),
    date = ProtoField.string("mg6xxx.field.date", "Panel date"),

    ev_seq = ProtoField.uint8("mg6xxx.event.seq", "Sequence", base.DEC),
    ev_event = ProtoField.uint8("mg6xxx.event.event", "Event", base.DEC, EVENT),
    ev_sub = ProtoField.uint8("mg6xxx.event.sub", "Sub-event", base.DEC),
    ev_area = ProtoField.uint8("mg6xxx.event.area", "Area", base.DEC),
    ev_date = ProtoField.string("mg6xxx.event.date", "Date"),
    ev_typed = ProtoField.uint8("mg6xxx.event.typed", "Typed (meaning unknown)", base.HEX),
    ev_label = ProtoField.string("mg6xxx.event.label", "Label"),

    ctl_serial = ProtoField.bytes("mg6xxx.control.serial", "Panel serial (as in the identify reply)"),
    battery = ProtoField.float("mg6xxx.field.battery", "Battery voltage (assumed 0.08 V/step)"),
    ac = ProtoField.float("mg6xxx.field.ac", "AC voltage (assumed 0.08 V/step)"),
    user_code = ProtoField.string("mg6xxx.field.user_code", "User code (BCD, first 4 digits)"),
    user_code_rep = ProtoField.uint8("mg6xxx.field.user_code_rep",
        "Repeats digits 1-2 (in both captures; meaning unknown)", base.HEX),
    prog_op = ProtoField.uint8("mg6xxx.programming.op", "Programming", base.HEX, PROGRAMMING_OP),
    zone_open = ProtoField.bool("mg6xxx.field.zone_open", "Zone open"),
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
    if LABELLED[obj] and fid == 0 then
        ft:add(f.serial, v)
    elseif LABELLED[obj] and fid == 1 then
        ft:add(f.label, v)
        rt:append_text(": " .. v:string():gsub("[%z ]+$", ""))
    elseif obj == OBJ_ZONE_STATUS and fid == 0 then
        local open = v(0, 1):uint() ~= 0
        ft:add(f.zone_open, v(0, 1), open)
        add_uninterp(ft, v, 1, size)
        rt:append_text(open and ": open" or ": closed")
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
    elseif obj == OBJ_USER and fid == 1 and size >= 2 then
        -- 4225 -> 42 25 42 00, 1234 -> 12 34 12 00: byte 2 repeats the first
        -- two digits (a 6-digit field filled cyclically?); byte 3 unknown
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

p:register_heuristic("usb.bulk", heuristic)
