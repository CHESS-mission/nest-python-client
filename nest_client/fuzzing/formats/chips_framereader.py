"""
CHIPS FrameReader — inbound UART format descriptions.
Reverse-engineered from: CHESS/Components/FrameReader/FrameReader.cpp

W2 MVP framing (diverges from full CHIPS spec):
  No CRC, no byte stuffing, no sequence number.
  Sync = 0xAA 0x55 (spec uses 0x7E).
"""

from nest_client.fuzzing.message_format import (
    Enum, Flags, Integer, Length, MessageFormat, Payload, RawBytes, Sync
)

_SOURCE = "CHESS/Components/FrameReader/FrameReader.cpp"

# ---------------------------------------------------------------------------
# TYPE=0x01 — EventAction Mode command
# Payload: U32 big-endian EventActionModes enum value.
# Guard in source: if (len >= 4) — frames with len<4 are parsed but ignored.
# ---------------------------------------------------------------------------

FRAME_EVENT_ACTION_MODE = MessageFormat(
    name        = "FrameReader / TYPE=0x01 EventAction Mode",
    transport   = "uart",
    source      = _SOURCE,
    description = (
        "Set the spacecraft operating mode.  "
        "Payload is a 4-byte big-endian U32 cast to EventActionModes.  "
        "Values outside the enum are cast unconditionally (potential UB)."
    ),
    sections    = [
        Sync("sync",
             value=b"\xAA\x55",
             description="Two-byte frame start marker. Bad value → FRAME_BAD_SYNC + cursor++."),

        Length("len",
               bits=16, endian="big", targets="payload", max_valid=65530,
               description="Payload byte count. If cursor+5+len>buffer → FRAME_BAD_LEN + break."),

        Enum("type",
             bits=8,
             values={"EVENT_ACTION_MODE": 0x01},
             description="Command type byte. 0x01 dispatches to eventActionModeOut port."),

        Enum("mode",
             bits=32, endian="big",
             values={
                 "LEOP":              0x00000000,
                 "COM":               0x00000001,
                 "CHARGE":            0x00000002,
                 "MEASURE":           0x00000003,   # → HIGHPOLLING in OBCSensorsManager
                 "DOWNLINK":          0x00000004,
                 "SAFE":              0x00000005,   # → OFF in OBCSensorsManager
                 "SAFE_SAFE_CHARGE":  0x00000006,
                 "SAFE_SAFE_DETUMBLE":0x00000007,
                 "SAFE_SAFE_COM":     0x00000008,
             },
             description=(
                 "EventActionModes U32. Values 9–0xFFFFFFFF are out-of-enum. "
                 "F' casts them unconditionally to the enum type."
             )),
    ],
)

# ---------------------------------------------------------------------------
# TYPE=0x02 — OBC Poll command
# No payload. Triggers an immediate sensor poll cycle.
# ---------------------------------------------------------------------------

FRAME_OBC_POLL = MessageFormat(
    name        = "FrameReader / TYPE=0x02 OBC Poll",
    transport   = "uart",
    source      = _SOURCE,
    description = "Trigger an immediate sensor poll.  Payload: none (LEN=0).",
    sections    = [
        Sync("sync", value=b"\xAA\x55"),

        Length("len",
               bits=16, endian="big", targets="payload", max_valid=0,
               description="Must be 0 for a valid OBC Poll frame."),

        Enum("type",
             bits=8,
             values={"OBC_POLL": 0x02},
             description="0x02 dispatches to obcPollOut port."),
    ],
)

# ---------------------------------------------------------------------------
# Generic frame — for TYPE-level and structural mutations
# (unknown type, oversized LEN, truncated payload)
# ---------------------------------------------------------------------------

FRAME_GENERIC = MessageFormat(
    name        = "FrameReader / Generic frame (structural mutations)",
    transport   = "uart",
    source      = _SOURCE,
    description = (
        "Covers structural edge cases that apply regardless of command type: "
        "bad sync, overflow LEN, unknown TYPE, and variable payload."
    ),
    sections    = [
        Sync("sync", value=b"\xAA\x55",
             description="Frame delimiter. Corrupted sync triggers per-byte rejection."),

        Length("len",
               bits=16, endian="big", targets="payload", max_valid=1024,
               description="Payload length field."),

        Enum("type",
             bits=8,
             values={"EVENT_ACTION_MODE": 0x01, "OBC_POLL": 0x02},
             description=(
                 "Command type. Values other than 0x01/0x02 are silently accepted "
                 "(FramesParsed++) but no port is called."
             )),

        Payload("payload",
                length_from="len", max_valid=1024,
                description="Command payload. Size and content vary by TYPE."),
    ],
)

FORMATS = [FRAME_EVENT_ACTION_MODE, FRAME_OBC_POLL, FRAME_GENERIC]
