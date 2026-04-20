"""
mutation_engine.py
------------------
Derives all structure-aware mutation cases from a MessageFormat.

The engine knows HOW to mutate each section type intelligently.
Format files know nothing about mutation — they only describe structure.

Usage
-----
    from nest_client.fuzzing.mutation_engine import MutationEngine
    from nest_client.fuzzing.formats.chips_framereader import FORMATS

    engine = MutationEngine()
    for fmt in FORMATS:
        for mut in engine.mutations(fmt):
            print(mut)

A Mutation carries:
  - which message and section it targets
  - a strategy label (why this value was chosen)
  - a human-readable description
  - the mutated section value (pre-encoding; not raw bytes)

Encoding to actual wire bytes is the responsibility of the caller,
because it requires knowledge of the framing protocol (byte-stuffing,
CRC recomputation, etc.).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Iterator

from .message_format import (
    BitField, Crc, Enum, Flags, Float, Integer, Length,
    MessageFormat, Payload, RawBytes, Section, Sync,
)


# ---------------------------------------------------------------------------
# Mutation case
# ---------------------------------------------------------------------------

@dataclass
class Mutation:
    """
    One structure-aware mutation: one section in one message set to one value.
    Everything else in the message remains nominal (CRC recalculated if present).
    """
    message_name: str
    section_name: str
    section_type: str        # class name of the section (Sync, Integer, …)
    strategy: str            # label describing WHY this value was chosen
    description: str         # human-readable summary
    value: Any               # the new value for this section (type varies by section)

    def label(self) -> str:
        return f"{self.message_name} · [{self.section_name}] · {self.strategy}"

    def __repr__(self) -> str:
        return f"Mutation({self.label()!r})"


# ---------------------------------------------------------------------------
# Strategy labels
# ---------------------------------------------------------------------------

BOUNDARY      = "BOUNDARY"       # min / max / ±1 edge values
BIT_FLIP      = "BIT_FLIP"       # each bit toggled individually
ENUM_VALID    = "ENUM_VALID"     # every named enum value
ENUM_INVALID  = "ENUM_INVALID"   # values outside the enum set
ZERO          = "ZERO"           # all-zeros payload / value
ALL_FF        = "ALL_FF"         # all-0xFF payload / value
FILL_PATTERN  = "FILL_PATTERN"   # alternating bit patterns (0x55, 0xAA)
STUFFING      = "STUFFING"       # byte-stuffing trigger sequences
SIZE_OVERFLOW = "SIZE_OVERFLOW"  # length field or payload exceeding max
SIZE_ZERO     = "SIZE_ZERO"      # empty / zero-length payload
SIZE_ONE      = "SIZE_ONE"       # minimal (1-byte) payload
SYNC_CORRUPT  = "SYNC_CORRUPT"   # individual sync bytes replaced
CRC_CORRUPT   = "CRC_CORRUPT"    # bad checksum values
FLAG_SET      = "FLAG_SET"       # each flag bit set independently
FLAG_CLEAR    = "FLAG_CLEAR"     # each flag bit cleared independently
FLAG_RESERVED = "FLAG_RESERVED"  # reserved (unnamed) bits set
FLOAT_SPECIAL = "FLOAT_SPECIAL"  # NaN, Inf, -Inf, -0, denormal
FLOAT_BOUNDARY= "FLOAT_BOUNDARY" # physically meaningful boundary values
RAW_PATTERN   = "RAW_PATTERN"    # fixed raw-byte block variants
MAGIC_BYTES   = "MAGIC_BYTES"    # protocol magic values (0x7E, 0xAA, …)


# ---------------------------------------------------------------------------
# Per-section mutation generators
# ---------------------------------------------------------------------------

def _mutations_sync(msg: str, s: Sync) -> Iterator[Mutation]:
    for byte_idx in range(len(s.value)):
        nominal = s.value[byte_idx]
        for bad in [0x00, 0xFF, nominal ^ 0xFF, nominal + 1, nominal - 1,
                    0x7E, 0xAA, 0x55]:
            bad &= 0xFF
            if bad == nominal:
                continue
            corrupted = bytearray(s.value)
            corrupted[byte_idx] = bad
            yield Mutation(
                msg, s.name, "Sync", SYNC_CORRUPT,
                f"byte[{byte_idx}] 0x{nominal:02X}→0x{bad:02X}",
                bytes(corrupted),
            )
    # Partial match: only first byte correct
    if len(s.value) > 1:
        partial = bytearray(s.value)
        partial[1] ^= 0xFF
        yield Mutation(msg, s.name, "Sync", SYNC_CORRUPT,
                       "partial match (only byte[0] correct)", bytes(partial))
    # All-zeros, all-0xFF
    yield Mutation(msg, s.name, "Sync", SYNC_CORRUPT,
                   "all zeros", bytes(len(s.value)))
    yield Mutation(msg, s.name, "Sync", SYNC_CORRUPT,
                   "all 0xFF", bytes([0xFF] * len(s.value)))


def _mutations_integer(msg: str, s: Integer) -> Iterator[Mutation]:
    max_unsigned = (1 << s.bits) - 1
    if s.signed:
        lo, hi = -(1 << (s.bits - 1)), (1 << (s.bits - 1)) - 1
    else:
        lo, hi = 0, max_unsigned

    boundaries = {lo, lo + 1, 0, 1, hi - 1, hi,
                  max_unsigned >> 1, (max_unsigned >> 1) + 1}
    for v in sorted(boundaries):
        if lo <= v <= hi:
            yield Mutation(msg, s.name, "Integer", BOUNDARY,
                           f"value={v} (0x{v & max_unsigned:X})", v)

    # Bit-flip: each bit individually
    for bit in range(s.bits):
        v = 1 << bit
        if lo <= v <= hi:
            yield Mutation(msg, s.name, "Integer", BIT_FLIP,
                           f"single-bit 2^{bit}=0x{v:X}", v)

    # Protocol magic values
    for magic in [0x7E, 0x7D, 0xAA, 0x55, 0xDE, 0xAD, 0xBE, 0xEF]:
        if lo <= magic <= hi:
            yield Mutation(msg, s.name, "Integer", MAGIC_BYTES,
                           f"magic value 0x{magic:02X}", magic)


def _mutations_enum(msg: str, s: Enum) -> Iterator[Mutation]:
    max_val = (1 << s.bits) - 1
    valid = set(s.values.values())

    # All named values (corpus seeds)
    for label, v in s.values.items():
        yield Mutation(msg, s.name, "Enum", ENUM_VALID,
                       f"{label}={v}", v)

    # Boundary: one above max valid, one below min valid
    min_v = min(valid)
    max_v = max(valid)
    for v in [min_v - 1, max_v + 1, max_val]:
        if 0 <= v <= max_val and v not in valid:
            yield Mutation(msg, s.name, "Enum", ENUM_INVALID,
                           f"out-of-enum value={v}", v)

    # Every out-of-range value (exhaustive for small enums with bits ≤ 8)
    if s.bits <= 8:
        for v in range(max_val + 1):
            if v not in valid:
                yield Mutation(msg, s.name, "Enum", ENUM_INVALID,
                               f"unknown enum value={v}", v)


def _mutations_length(msg: str, s: Length) -> Iterator[Mutation]:
    max_field = (1 << s.bits) - 1

    cases = [
        (SIZE_ZERO,     0,                  "zero-length (empty payload)"),
        (SIZE_ONE,      1,                  "minimal length = 1"),
        (BOUNDARY,      s.max_valid - 1,    f"max_valid−1 = {s.max_valid - 1}"),
        (BOUNDARY,      s.max_valid,        f"max_valid = {s.max_valid}"),
        (SIZE_OVERFLOW, s.max_valid + 1,    f"max_valid+1 = {s.max_valid + 1}  (overflow)"),
        (SIZE_OVERFLOW, s.max_valid * 2,    f"max_valid×2 = {s.max_valid * 2}"),
        (SIZE_OVERFLOW, max_field,          f"field max = {max_field}  (full overflow)"),
    ]
    for strategy, v, desc in cases:
        if 0 <= v <= max_field:
            yield Mutation(msg, s.name, "Length", strategy, desc, v)

    # Bit-flip on the length value
    for bit in range(s.bits):
        v = 1 << bit
        if v <= max_field:
            yield Mutation(msg, s.name, "Length", BIT_FLIP,
                           f"single-bit flip 2^{bit}=0x{v:X}", v)


def _mutations_payload(msg: str, s: Payload) -> Iterator[Mutation]:
    # Size-based mutations
    sizes = {0, 1, 2, s.max_valid - 1, s.max_valid, s.max_valid + 1,
             s.max_valid * 2, 65535}
    for size in sorted(sizes):
        if size < 0:
            continue
        if size == 0:
            yield Mutation(msg, s.name, "Payload", SIZE_ZERO,
                           "empty payload (0 bytes)", b"")
            continue

        cap = min(size, 4096)  # cap generation at 4KiB for sanity

        if size <= s.max_valid:
            strategy = BOUNDARY if size in {1, s.max_valid} else FILL_PATTERN
        else:
            strategy = SIZE_OVERFLOW

        yield Mutation(msg, s.name, "Payload", strategy,
                       f"size={size} fill=0x00", bytes(cap))
        yield Mutation(msg, s.name, "Payload", strategy,
                       f"size={size} fill=0xFF", bytes([0xFF] * cap))

    # Fill patterns (nominal size = max_valid)
    n = min(s.max_valid, 256)
    for fill, name in [(0x55, "0x55"), (0xAA, "0xAA")]:
        yield Mutation(msg, s.name, "Payload", FILL_PATTERN,
                       f"fill={name}", bytes([fill] * n))

    # Byte-stuffing triggers
    for pattern, label in [
        (b"\x7E",           "single SYNC byte 0x7E"),
        (b"\x7D",           "single ESC byte 0x7D"),
        (b"\x7E\x7D",       "SYNC then ESC"),
        (b"\x7D\x5E",       "stuffed-SYNC sequence"),
        (b"\x7D\x5D",       "stuffed-ESC sequence"),
        (b"\x7E" * 8,       "8× SYNC bytes"),
        (b"\xAA\x55" * 4,   "repeated frame-start pattern"),
    ]:
        yield Mutation(msg, s.name, "Payload", STUFFING, label, pattern)


def _mutations_crc(msg: str, s: Crc) -> Iterator[Mutation]:
    max_val = (1 << s.bits) - 1

    yield Mutation(msg, s.name, "Crc", CRC_CORRUPT,
                   "all-bits inverted (0x…FF XOR valid)", "INVERT")
    yield Mutation(msg, s.name, "Crc", CRC_CORRUPT,
                   f"zero (0x{'00' * (s.bits // 8)})", 0)
    yield Mutation(msg, s.name, "Crc", CRC_CORRUPT,
                   f"all-ones (0x{max_val:X})", max_val)
    yield Mutation(msg, s.name, "Crc", CRC_CORRUPT,
                   "valid+1 (off-by-one)", "VALID_PLUS_ONE")

    for bit in range(s.bits):
        yield Mutation(msg, s.name, "Crc", BIT_FLIP,
                       f"valid XOR 2^{bit} (single-bit error)", f"FLIP_{bit}")


def _mutations_flags(msg: str, s: Flags) -> Iterator[Mutation]:
    named_bits: set[int] = set()
    for f in s.fields:
        for offset in range(f.bit_offset, f.bit_offset + f.bit_width):
            named_bits.add(offset)

    # Each named flag field independently
    for f in s.fields:
        mask = ((1 << f.bit_width) - 1) << f.bit_offset
        yield Mutation(msg, s.name, "Flags", FLAG_SET,
                       f"{f.name} all bits set", mask)
        yield Mutation(msg, s.name, "Flags", FLAG_CLEAR,
                       f"{f.name} all bits cleared", 0)
        if f.bit_width > 1:
            for bit in range(f.bit_width):
                v = (1 << bit) << f.bit_offset
                yield Mutation(msg, s.name, "Flags", BIT_FLIP,
                               f"{f.name} bit {bit} only", v)

    # All flags set / all cleared
    all_named_mask = sum(
        ((1 << f.bit_width) - 1) << f.bit_offset for f in s.fields
    )
    yield Mutation(msg, s.name, "Flags", FLAG_SET,   "all named flags set",     all_named_mask)
    yield Mutation(msg, s.name, "Flags", FLAG_CLEAR, "all named flags cleared",  0)

    # Reserved bits (bits not covered by any named field)
    reserved = [b for b in range(s.bits) if b not in named_bits]
    if reserved:
        reserved_mask = sum(1 << b for b in reserved)
        yield Mutation(msg, s.name, "Flags", FLAG_RESERVED,
                       f"reserved bits set: {reserved}", reserved_mask)


def _mutations_float(msg: str, s: Float) -> Iterator[Mutation]:
    pack_fmt = ">f" if s.bits == 32 else ">d"

    specials = [
        (FLOAT_SPECIAL,  b"\x00\x00\x00\x00",            "+0.0"),
        (FLOAT_SPECIAL,  b"\x80\x00\x00\x00",            "-0.0"),
        (FLOAT_SPECIAL,  b"\x7F\x80\x00\x00",            "+Inf"),
        (FLOAT_SPECIAL,  b"\xFF\x80\x00\x00",            "-Inf"),
        (FLOAT_SPECIAL,  b"\x7F\xC0\x00\x00",            "quiet NaN"),
        (FLOAT_SPECIAL,  b"\xFF\xC0\x00\x00",            "quiet -NaN"),
        (FLOAT_SPECIAL,  b"\x7F\x80\x00\x01",            "signalling NaN"),
        (FLOAT_SPECIAL,  b"\x00\x00\x00\x01",            "min positive subnormal"),
        (FLOAT_SPECIAL,  b"\x7F\x7F\xFF\xFF",            "max finite +"),
        (FLOAT_SPECIAL,  b"\xFF\x7F\xFF\xFF",            "max finite −"),
    ] if s.bits == 32 else [
        (FLOAT_SPECIAL,  b"\x00" * 8,                    "+0.0"),
        (FLOAT_SPECIAL,  b"\x80" + b"\x00" * 7,         "-0.0"),
        (FLOAT_SPECIAL,  b"\x7F\xF0" + b"\x00" * 6,    "+Inf"),
        (FLOAT_SPECIAL,  b"\xFF\xF0" + b"\x00" * 6,    "-Inf"),
        (FLOAT_SPECIAL,  b"\x7F\xF8" + b"\x00" * 6,    "quiet NaN"),
    ]

    for strategy, raw, label in specials:
        if s.bits == 32:
            yield Mutation(msg, s.name, "Float", strategy, label, raw)
        else:
            yield Mutation(msg, s.name, "Float", strategy, label, raw)

    # Domain-specific boundaries encoded as struct floats
    boundaries = [-273.15, -55.0, 0.0, 25.0, 85.0, 125.0, 1000.0, -1000.0]
    for val in boundaries:
        raw = struct.pack(pack_fmt, val)
        if s.endian == "little":
            raw = raw[::-1]
        yield Mutation(msg, s.name, "Float", FLOAT_BOUNDARY,
                       f"physical value {val}", raw)


def _mutations_raw_bytes(msg: str, s: RawBytes) -> Iterator[Mutation]:
    n = s.length
    patterns = [
        (RAW_PATTERN, bytes(n),                 "all zeros"),
        (RAW_PATTERN, bytes([0xFF] * n),        "all 0xFF"),
        (RAW_PATTERN, bytes([0x55] * n),        "pattern 0x55"),
        (RAW_PATTERN, bytes([0xAA] * n),        "pattern 0xAA"),
        (RAW_PATTERN, (bytes(range(n % 256)) * (n // 256 + 1))[:n], "sequential"),
    ]
    for strategy, data, label in patterns:
        yield Mutation(msg, s.name, "RawBytes", strategy, label, data)


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

_GENERATORS = {
    Sync:      _mutations_sync,
    Integer:   _mutations_integer,
    Enum:      _mutations_enum,
    Length:    _mutations_length,
    Payload:   _mutations_payload,
    Crc:       _mutations_crc,
    Flags:     _mutations_flags,
    Float:     _mutations_float,
    RawBytes:  _mutations_raw_bytes,
}


class MutationEngine:
    """
    Derives all structure-aware mutation cases from a MessageFormat.

    For each section the engine applies the mutation strategies appropriate
    to that section's type.  The caller controls which sections to include.
    """

    def mutations(
        self,
        fmt: MessageFormat,
        *,
        only: list[str] | None = None,   # restrict to these section names
        exclude: list[str] | None = None,
    ) -> list[Mutation]:
        """
        Return all mutations for *fmt*.

        Parameters
        ----------
        only    : if given, only mutate sections whose name is in this list
        exclude : if given, skip sections whose name is in this list
        """
        result: list[Mutation] = []
        for section in fmt.sections:
            name = section.name
            if only    is not None and name not in only:
                continue
            if exclude is not None and name in exclude:
                continue
            gen = _GENERATORS.get(type(section))
            if gen is None:
                continue
            result.extend(gen(fmt.name, section))
        return result

    def mutations_by_section(
        self, fmt: MessageFormat, **kwargs
    ) -> dict[str, list[Mutation]]:
        """Return mutations grouped by section name."""
        groups: dict[str, list[Mutation]] = {}
        for mut in self.mutations(fmt, **kwargs):
            groups.setdefault(mut.section_name, []).append(mut)
        return groups

    def summary(self, fmt: MessageFormat) -> str:
        """Return a human-readable table of section → mutation count."""
        groups = self.mutations_by_section(fmt)
        lines = [f"  {fmt.name}  ({fmt.transport})"]
        total = 0
        for section in fmt.sections:
            n = len(groups.get(section.name, []))
            total += n
            stype = type(section).__name__
            lines.append(f"    [{stype:<10}] {section.name:<25} {n:4} mutations")
        lines.append(f"    {'─' * 45}")
        lines.append(f"    {'TOTAL':<36} {total:4} mutations")
        return "\n".join(lines)
