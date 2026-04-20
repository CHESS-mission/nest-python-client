"""
message_format.py
-----------------
Pure data model for describing message wire formats.

This file contains NO mutation logic.  It only describes structure.
A format file simply instantiates a MessageFormat with a list of sections.

Section types
-------------
  Sync        fixed magic bytes (frame delimiters)
  Integer     fixed-width integer  (u8, u16be, i16be, u32le, …)
  Enum        integer with a named set of valid values
  Length      integer whose value encodes the byte-count of another section
  Payload     variable-length opaque byte string
  Crc         checksum computed over a named range of sections
  Flags       bit-packed fields inside one integer word
  Float       IEEE-754 floating-point value
  RawBytes    fixed-length opaque byte block (padding, ignored fields, …)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Union


# ---------------------------------------------------------------------------
# Section definitions (the format vocabulary)
# ---------------------------------------------------------------------------

@dataclass
class Sync:
    """
    Fixed magic byte(s) used as a frame delimiter or start-word.

    Mutations: each byte replaced by every non-magic value,
    partial matches (only first byte correct), all-zeros, all-0xFF.
    """
    name: str
    value: bytes                         # e.g. b"\xAA\x55"  or  b"\xDE\xAD\xBE\xEF"
    description: str = ""


@dataclass
class Integer:
    """
    A fixed-width unsigned or signed integer.

    Mutations: min, max, min±1, max±1, 0, 0xFF…, bit-flips,
    protocol-magic values (0x7E, 0xAA, 0x55, …).
    """
    name: str
    bits: int                            # 8 | 16 | 32 | 64
    signed: bool = False
    endian: str = "big"                  # "big" | "little"
    description: str = ""


@dataclass
class Enum:
    """
    An integer field whose meaningful values are a named set.

    Mutations: every valid named value (corpus seeds) + every
    out-of-enum value up to 2^bits – 1.
    """
    name: str
    bits: int
    values: dict[str, int]               # label → wire value
    endian: str = "big"
    description: str = ""


@dataclass
class Length:
    """
    An integer field that encodes the byte-count of *targets* section.

    Mutations: 0, 1, nominal, max_valid, max_valid+1, 0xFFFF/0xFF,
    values that would make the frame overflow a typical buffer.
    """
    name: str
    bits: int
    endian: str = "big"
    targets: str = ""                    # name of the Payload section it sizes
    max_valid: int = 1024                # maximum accepted by the receiver
    description: str = ""


@dataclass
class Payload:
    """
    Variable-length byte block, often sized by a preceding Length field.

    Mutations: size 0, 1, max_valid, max_valid+1; fill with 0x00,
    0xFF, 0x55, 0xAA; stuffing-trigger patterns (0x7E, 0x7D).
    """
    name: str
    length_from: str = ""               # name of the Length section; "" = standalone
    max_valid: int = 1024
    description: str = ""


@dataclass
class Crc:
    """
    Checksum appended to the frame, covering a slice of sections.

    Mutations: valid (baseline), bit-inverted, zero, 0xFF…,
    single-bit flips (one per bit position).
    """
    name: str
    bits: int                           # 8 | 16 | 32
    algorithm: str                      # "crc16_kermit" | "crc32" | "sum8" | …
    covers: list[str]                   # section names included in the checksum
    endian: str = "little"
    description: str = ""


@dataclass
class BitField:
    """One named field within a Flags section."""
    name: str
    bit_offset: int                     # LSB position (0 = least significant)
    bit_width: int = 1
    description: str = ""


@dataclass
class Flags:
    """
    A single integer word whose bits are individually named.

    Mutations: each flag toggled independently; all set; all clear;
    reserved bits set; illegal combinations.
    """
    name: str
    bits: int                           # total word size in bits
    fields: list[BitField]
    endian: str = "big"
    description: str = ""


@dataclass
class Float:
    """
    IEEE-754 floating-point value.

    Mutations: +0, -0, NaN (quiet + signalling), +Inf, -Inf,
    max finite, min positive normal, min positive subnormal,
    and any domain-specific boundary values.
    """
    name: str
    bits: int = 32                      # 32 | 64
    endian: str = "big"
    description: str = ""


@dataclass
class RawBytes:
    """
    Fixed-length block that the receiver either ignores or passes through
    without interpreting (e.g. padding, reserved, unknown future fields).

    Mutations: all-zeros, all-0xFF, alternating 0x55/0xAA, random.
    """
    name: str
    length: int                         # byte count
    description: str = ""


# Union type for type hints
Section = Union[Sync, Integer, Enum, Length, Payload, Crc, Flags, Float, RawBytes]


# ---------------------------------------------------------------------------
# Top-level container
# ---------------------------------------------------------------------------

@dataclass
class MessageFormat:
    """
    Complete wire-format description of one message type.

    This is the only thing a format file needs to produce.
    The mutation engine consumes it without any additional configuration.
    """
    name: str
    transport: str                       # "uart" | "i2c_write" | "i2c_read"
    sections: list[Section]
    description: str = ""
    source: str = ""                     # e.g. path to the C++ file this was derived from
