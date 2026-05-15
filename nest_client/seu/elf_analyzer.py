#!/usr/bin/env python3
"""
elf_analyzer.py Extract fault-injection targets from the CHESS ARM ELF binary.

Usage
-----
    python3 elf_analyzer.py [OPTIONS] <elf_binary>

Options
-------
    --filter <regex>   Only show symbols whose demangled name matches the regex
                       (default: show everything)
    --section <name>   Only show symbols in <name> section (e.g. .bss, .data)
    --json             Emit JSON instead of the human-readable table
    --candidates       Shortcut: emit only "good" SEU candidates (data/BSS,
                       FPrime component state, health-related names)
    --out <file>       Write output to file instead of stdout

What it finds
-------------
  • Every global symbol in .data / .bss / .rodata the variables that an
    SEU can flip.
  • Symbols whose demangled name contains FPrime component identifiers
    (Svc::, Fw::, health, state, mode, count, timer …) are flagged as
    high-value injection targets.
  • For each symbol we emit: name, demangled name, virtual address, size,
    section exactly what fault_injector.py needs to schedule an injection.

Requirements
------------
    pip install pyelftools
    arm-linux-gnueabihf-objdump  (or system objdump with --target=elf32-littlearm)
    c++filt                      (usually in binutils)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.descriptions import describe_symbol_type, describe_symbol_bind
except ImportError:
    print("WARNING: pyelftools not installed. DWARF analysis disabled.")

# DWARF field-expansion helpers

def _build_die_index(dwarf_info) -> dict:
    """Build {absolute_offset: DIE} index across all CUs."""
    index = {}
    for cu in dwarf_info.iter_CUs():
        for die in cu.iter_DIEs():
            index[die.offset] = die
    return index


def _ref_abs(attr, cu) -> int:
    """Convert DW_AT_type reference attribute to absolute .debug_info offset."""
    if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4',
                     'DW_FORM_ref8', 'DW_FORM_ref_udata'):
        return cu.cu_offset + attr.value
    return attr.value  # DW_FORM_ref_addr is already absolute


def _follow(die, die_index):
    """Return the DIE pointed to by DW_AT_type, or None."""
    attr = die.attributes.get('DW_AT_type')
    return die_index.get(_ref_abs(attr, die.cu)) if attr else None


def _deref(die, die_index):
    """Strip typedefs / const / volatile to reach a struct, class, or base type."""
    transparent = {'DW_TAG_typedef', 'DW_TAG_const_type',
                   'DW_TAG_volatile_type', 'DW_TAG_restrict_type'}
    seen: set = set()
    while die and die.tag in transparent and die.offset not in seen:
        seen.add(die.offset)
        die = _follow(die, die_index)
    return die


def _attr_str(die, attr_name) -> str | None:
    attr = die.attributes.get(attr_name)
    if attr is None:
        return None
    v = attr.value
    return v.decode('utf-8', errors='replace') if isinstance(v, bytes) else str(v)


def _type_str(die, die_index, depth: int = 0) -> str:
    if die is None or depth > 4:
        return '?'
    name = _attr_str(die, 'DW_AT_name')
    if name:
        return name
    tag = die.tag
    inner = _follow(die, die_index)
    if tag == 'DW_TAG_pointer_type':
        return _type_str(inner, die_index, depth + 1) + '*'
    if tag == 'DW_TAG_reference_type':
        return _type_str(inner, die_index, depth + 1) + '&'
    if tag == 'DW_TAG_array_type':
        return _type_str(inner, die_index, depth + 1) + '[]'
    if tag in ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type'):
        return _type_str(inner, die_index, depth + 1)
    return tag.replace('DW_TAG_', '')


def _die_byte_size(die, die_index) -> int:
    if die is None:
        return 0
    attr = die.attributes.get('DW_AT_byte_size')
    if attr:
        return int(attr.value)
    resolved = _deref(die, die_index)
    if resolved and resolved is not die:
        attr2 = resolved.attributes.get('DW_AT_byte_size')
        if attr2:
            return int(attr2.value)
    return 0


def _member_byte_offset(child) -> int | None:
    """Extract byte offset from DW_AT_data_member_location (int or block form)."""
    attr = child.attributes.get('DW_AT_data_member_location')
    if attr is None:
        return None
    v = attr.value
    if isinstance(v, int):
        return v
    # Block form: DW_OP_plus_uconst (0x23) <uleb128>
    b = list(v)
    if b and b[0] == 0x23 and len(b) > 1:
        # Simplified ULEB128 decode (correct for offsets < 16384)
        result, shift = 0, 0
        for byte in b[1:]:
            result |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80):
                break
        return result
    if len(b) == 1:
        return b[0]
    return None


@dataclass
class FieldInfo:
    offset: int       # byte offset from object base
    size: int         # byte size of this field
    type_name: str    # human-readable type
    field_name: str   # member name (or "<base: ClassName>")
    is_base: bool = False


def _collect_fields(type_die, die_index, base_off: int = 0,
                    depth: int = 0, fwd_map: dict | None = None) -> list[FieldInfo]:
    """Recursively collect members of a class/struct DIE.

    fwd_map: optional {declaration_die_offset: full_definition_die} built by
    expand_symbol_fields to resolve forward-declaration type references.
    """
    if depth > 4 or type_die is None:
        return []
    resolved = _deref(type_die, die_index)
    if resolved is None or resolved.tag not in (
            'DW_TAG_class_type', 'DW_TAG_structure_type', 'DW_TAG_union_type'):
        return []
    # If this is a forward declaration (no members), look for the full definition
    if resolved.attributes.get('DW_AT_declaration') and fwd_map:
        full = fwd_map.get(resolved.offset)
        if full is not None:
            resolved = full

    fields: list[FieldInfo] = []
    for child in resolved.iter_children():
        if child.tag == 'DW_TAG_inheritance':
            inh_off = _member_byte_offset(child) or 0
            base_type = _follow(child, die_index)
            base_name = _type_str(base_type, die_index) if base_type else '?'
            base_sz = _die_byte_size(_deref(base_type, die_index)
                                     if base_type else None, die_index)
            fields.append(FieldInfo(
                offset=base_off + inh_off, size=base_sz,
                type_name=base_name, field_name=f'<base: {base_name}>',
                is_base=True))

        elif child.tag == 'DW_TAG_member':
            # Skip static members (external flag set, no data location)
            if child.attributes.get('DW_AT_external'):
                continue
            moff = _member_byte_offset(child)
            if moff is None:
                continue
            mname = _attr_str(child, 'DW_AT_name') or '<anon>'
            mtype = _follow(child, die_index)
            msz = _die_byte_size(_deref(mtype, die_index)
                                 if mtype else None, die_index)
            fields.append(FieldInfo(
                offset=base_off + moff, size=msz,
                type_name=_type_str(mtype, die_index) if mtype else '?',
                field_name=mname))

    fields.sort(key=lambda f: f.offset)
    return fields


def _addr_from_location(attr) -> int | None:
    """Extract a simple DW_OP_addr address from a DW_AT_location attribute."""
    v = attr.value
    b = list(v) if isinstance(v, (bytes, bytearray)) else (v if isinstance(v, list) else [])
    if len(b) >= 5 and b[0] == 0x03:  # DW_OP_addr, 32-bit LE
        return b[1] | (b[2] << 8) | (b[3] << 16) | (b[4] << 24)
    return None


def expand_symbol_fields(elf_path: Path,
                          symbols: list[SymbolInfo]) -> dict[str, list[FieldInfo]]:
    """
    For each SymbolInfo, parse DWARF to get member field layout.
    Matches by DW_AT_linkage_name (mangled name) first, then falls back to address.
    Returns {symbol.name: [FieldInfo, ...]}.
    """
    results: dict[str, list[FieldInfo]] = {}
    with elf_path.open('rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("WARNING: No DWARF debug info. Rebuild with -g (use the -debug binary).",
                  file=sys.stderr)
            return results

        dwarf = elf.get_dwarf_info()
        print("Building DWARF index (may take a few seconds)…", file=sys.stderr)
        die_index = _build_die_index(dwarf)

        # Build forward-declaration -> full-definition map.
        # A forward declaration has DW_AT_declaration=True and no member children.
        # The full definition has the same DW_AT_name and no DW_AT_declaration.
        _tags = ('DW_TAG_class_type', 'DW_TAG_structure_type', 'DW_TAG_union_type')
        decls: dict[str, int] = {}   # name -> declaration offset
        fwd_map: dict[int, object] = {}  # decl_offset -> full def DIE
        for _die in die_index.values():
            if _die.tag not in _tags:
                continue
            _name = _attr_str(_die, 'DW_AT_name') or ''
            if not _name:
                continue
            if _die.attributes.get('DW_AT_declaration'):
                decls.setdefault(_name, _die.offset)
            else:
                decl_off = decls.get(_name)
                if decl_off is not None and decl_off not in fwd_map:
                    fwd_map[decl_off] = _die

        by_name = {s.name: s for s in symbols}
        by_addr = {s.address: s for s in symbols}

        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != 'DW_TAG_variable':
                    continue
                type_attr = die.attributes.get('DW_AT_type')
                if type_attr is None:
                    continue

                sym = None
                # Primary match: mangled linkage name
                linkage = (_attr_str(die, 'DW_AT_linkage_name') or
                           _attr_str(die, 'DW_AT_MIPS_linkage_name'))
                if linkage and linkage in by_name:
                    sym = by_name[linkage]
                # Fallback: match by DW_OP_addr address
                if sym is None:
                    loc_attr = die.attributes.get('DW_AT_location')
                    if loc_attr:
                        addr = _addr_from_location(loc_attr)
                        if addr is not None:
                            sym = by_addr.get(addr)

                if sym and sym.name not in results:
                    type_die = die_index.get(_ref_abs(type_attr, cu))
                    results[sym.name] = _collect_fields(type_die, die_index, fwd_map=fwd_map)

        # Fallback: match variable DIE by DW_AT_name when location was a list
        # RelWithDebInfo may use location lists (not simple DW_OP_addr), making
        # the address-based match above fail.  Match the variable DIE by its
        # unqualified DW_AT_name instead, then follow DW_AT_type for fields.
        unresolved = [s for s in symbols if s.name not in results]
        if unresolved:
            def _tail(demangled: str) -> str:
                base = demangled.split('<')[0].rstrip()
                part = base.split('::')[-1]
                # If demangling failed (name still starts with _Z), extract the
                # last C++ identifier via the length-prefixed encoding: e.g.
                # '_ZN5CHESS17obcSensorsManagerE' -> 'obcSensorsManager'
                if part.startswith('_Z'):
                    import re as _re
                    ids = _re.findall(r'\d+([A-Za-z_]\w*)', part)
                    if ids:
                        return ids[-1]
                return part
            by_tail = {_tail(s.demangled): s for s in unresolved}

            for cu in dwarf.iter_CUs():
                for die in cu.iter_DIEs():
                    if die.tag != 'DW_TAG_variable':
                        continue
                    var_name = _attr_str(die, 'DW_AT_name') or ''
                    sym = by_tail.get(var_name)
                    if sym is None or sym.name in results:
                        continue
                    type_attr = die.attributes.get('DW_AT_type')
                    if type_attr is None:
                        continue
                    type_die = die_index.get(_ref_abs(type_attr, cu))
                    fields = _collect_fields(type_die, die_index, fwd_map=fwd_map)
                    if fields:
                        results[sym.name] = fields

    return results


def print_expansion(sym: SymbolInfo, fields: list[FieldInfo]) -> None:
    print(f"\n{sym.demangled}")
    print(f"  base addr : 0x{sym.address:010x}")
    print(f"  total size: {sym.size} bytes")
    if not fields:
        print("  (no DWARF member info is this the debug binary?)")
        return
    hdr = f"  {'OFFSET':>8}  {'ABS ADDR':>12}  {'SIZE':>5}  {'TYPE':<32}  FIELD"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for fi in fields:
        abs_addr = sym.address + fi.offset
        note = " (base class)" if fi.is_base else ""
        print(f"  +{fi.offset:<7d}  0x{abs_addr:010x}  {fi.size:>5}  "
              f"{fi.type_name:<32}  {fi.field_name}{note}")
    # Show any fields that look like SEU targets (non-pointer, non-base, small types)
    targets = [fi for fi in fields
               if not fi.is_base and not fi.type_name.endswith('*')
               and 0 < fi.size <= 8]
    print(f"\n  {len(fields)} fields total, {len(targets)} potential SEU targets "
          f"(non-ptr, ≤8 bytes)")

# Constants

# FPrime / CHESS-specific patterns that make a symbol a high-value SEU target
_FPRIME_PATTERNS = re.compile(
    r"(Svc::|Fw::|CHESS::|OBCSensors|EventAction|Pathfinder"
    r"|health|Health|mode|Mode|state|State|count|Count"
    r"|timer|Timer|rate|Rate|cmd|Cmd|tlm|Tlm|port|Port)",
    re.IGNORECASE,
)

# Sections that hold writable data (SEU targets in RAM)
_WRITABLE_SECTIONS = {".data", ".bss", ".sbss", ".sdata", ".noinit"}

# Symbol types that represent data objects (not code)
# Note: describe_symbol_type() returns "OBJECT" not "STT_OBJECT"
_DATA_TYPES = {"OBJECT", "COMMON", "TLS"}


# Data class

@dataclass
class SymbolInfo:
    name: str            # raw (mangled) name from ELF
    demangled: str       # c++filt output
    address: int         # guest virtual address (load address)
    size: int            # size in bytes (0 if unknown)
    section: str         # ELF section name
    sym_type: str        # OBJECT, FUNC, …
    binding: str         # GLOBAL, LOCAL, WEAK
    is_candidate: bool   # True if high-value SEU injection candidate

    def bit_targets(self, skip_bytes: int = 0, bits: list[int] | None = None) -> list[dict]:
        """
        Return a list of {addr, bit} dicts covering every bit in this symbol.

        skip_bytes : skip the first N bytes (use to avoid vtable pointer region
                     in C++ objects typically 32-64 bytes for FPrime components)
        bits       : list of bit positions to test per byte (default: all 8)
        """
        targets = []
        bit_list = bits if bits is not None else list(range(8))
        byte_count = max(self.size, 1)
        for byte_off in range(skip_bytes, byte_count):
            for bit in bit_list:
                targets.append({
                    "addr": self.address + byte_off,
                    "bit": bit,
                    "symbol": self.demangled,
                    "byte_offset": byte_off,
                })
        return targets

    def smart_targets(self, vtable_skip: int = 64) -> list[dict]:
        """
        Return a reduced set of high-value targets by sampling the object at
        strategic offsets rather than exhaustively covering every bit.

        Strategy:
          - Skip the first `vtable_skip` bytes (vtable pointers -> always CRASH,
            not interesting for DETECTED/MASKED analysis)
          - Sample every 4 bytes (word-aligned) past the vtable region
          - Test only bits 0, 3, 7 per byte (LSB, middle, MSB representative)
        """
        if self.size <= vtable_skip:
            return []
        targets = []
        for byte_off in range(vtable_skip, self.size, 4):
            for bit in (0, 3, 7):
                targets.append({
                    "addr": self.address + byte_off,
                    "bit": bit,
                    "symbol": self.demangled,
                    "byte_offset": byte_off,
                })
        return targets


# Helpers

def _demangle(names: list[str]) -> list[str]:
    """Run c++filt on a batch of names for efficiency."""
    if not names:
        return []
    try:
        result = subprocess.run(
            ["c++filt"] + names,
            capture_output=True, text=True, check=True
        )
        return result.stdout.splitlines()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return names  # fall back to raw names


def _section_name(elf: ELFFile, sym) -> str:
    """Return the section name for a symbol, or '' if not applicable."""
    shndx = sym["st_shndx"]
    if isinstance(shndx, int):
        section = elf.get_section(shndx)
        return section.name if section else ""
    return str(shndx)  # e.g. 'SHN_ABS', 'SHN_UNDEF'


# Symbol cache

def _elf_sha256(elf_path: Path) -> str:
    h = hashlib.sha256()
    with elf_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _default_cache_path(elf_path: Path) -> Path:
    import os
    cache_dir = Path(os.environ.get("SEU_CACHE_DIR", "/tmp"))
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"seu_elf_{elf_path.stem}.json"


def _load_cache(cache_path: Path, elf_sha: str) -> list[SymbolInfo] | None:
    """Return cached symbols if the cache file exists and hash matches."""
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text())
        if data.get("elf_sha256") != elf_sha:
            return None
        return [SymbolInfo(**s) for s in data["symbols"]]
    except Exception:
        return None


def _save_cache(cache_path: Path, elf_sha: str, symbols: list[SymbolInfo]) -> None:
    try:
        cache_path.write_text(json.dumps({
            "elf_sha256": elf_sha,
            "created":    time.strftime("%Y-%m-%dT%H:%M:%S"),
            "symbols":    [asdict(s) for s in symbols],
        }, indent=2))
    except Exception as e:
        print(f"WARNING: could not write ELF cache to {cache_path}: {e}", file=sys.stderr)


def analyze_cached(elf_path: Path,
                   filter_re: re.Pattern | None = None,
                   cache_path: Path | None = None) -> list[SymbolInfo]:
    """
    Like analyze(), but caches results keyed by the ELF's SHA-256 hash.
    Subsequent calls with the same (unchanged) binary return instantly.

    cache_path defaults to /tmp/seu_elf_<stem>.json.
    Pass cache_path=False to disable caching.
    """
    cp = None if cache_path is False else (cache_path or _default_cache_path(elf_path))

    if cp is not None:
        sha = _elf_sha256(elf_path)
        cached = _load_cache(cp, sha)
        if cached is not None:
            # Apply filter_re post-load so we can reuse the same cache for
            # different filter patterns without re-parsing the ELF.
            if filter_re:
                cached = [s for s in cached if filter_re.search(s.demangled)]
            print(f"ELF analysis: loaded {len(cached)} symbols from cache "
                  f"({cp.name})", file=sys.stderr)
            return cached

    symbols = analyze(elf_path, filter_re=None)  # always store full set in cache

    if cp is not None:
        _save_cache(cp, sha, symbols)
        print(f"ELF analysis: cached {len(symbols)} symbols -> {cp}", file=sys.stderr)

    if filter_re:
        symbols = [s for s in symbols if filter_re.search(s.demangled)]
    return symbols


# Core analysis

def analyze(elf_path: Path, filter_re: re.Pattern | None = None) -> list[SymbolInfo]:
    """
    Parse the ELF and return one SymbolInfo per relevant global symbol.
    """
    symbols: list[SymbolInfo] = []

    with elf_path.open("rb") as f:
        elf = ELFFile(f)

        # Prefer .symtab (full), fall back to .dynsym
        symtab: SymbolTableSection | None = (
            elf.get_section_by_name(".symtab")
            or elf.get_section_by_name(".dynsym")
        )
        if symtab is None:
            print("WARNING: No symbol table found. Was the binary stripped?",
                  file=sys.stderr)
            return symbols

        raw_names: list[str] = []
        raw_syms = []

        for sym in symtab.iter_symbols():
            if sym.name == "":
                continue
            sym_type = describe_symbol_type(sym["st_info"]["type"])
            binding  = describe_symbol_bind(sym["st_info"]["bind"])
            # Strip ARM Thumb bit (bit 0 set = Thumb indicator, not a real byte addr)
            addr     = sym["st_value"] & ~1
            size     = sym["st_size"]
            section  = _section_name(elf, sym)

            # Skip undefined and absolute symbols
            if sym["st_shndx"] in ("SHN_UNDEF", "SHN_ABS"):
                continue
            # Skip zero-address symbols (linker artifacts)
            if addr == 0:
                continue

            raw_names.append(sym.name)
            raw_syms.append((sym.name, addr, size, section, sym_type, binding))

        # Batch demangle
        demangled = _demangle(raw_names)

        for (name, addr, size, section, sym_type, binding), dem in zip(raw_syms, demangled):
            # Apply user filter
            if filter_re and not filter_re.search(dem):
                continue

            is_candidate = (
                section in _WRITABLE_SECTIONS
                and sym_type in _DATA_TYPES
                and bool(_FPRIME_PATTERNS.search(dem))
            )

            symbols.append(SymbolInfo(
                name=name,
                demangled=dem,
                address=addr,
                size=size,
                section=section,
                sym_type=sym_type,
                binding=binding,
                is_candidate=is_candidate,
            ))

    symbols.sort(key=lambda s: s.address)
    return symbols


# Output formatters

def print_table(symbols: list[SymbolInfo], candidates_only: bool = False) -> None:
    data = [s for s in symbols if (not candidates_only or s.is_candidate)]
    if not data:
        print("(no symbols match)")
        return

    header = f"{'ADDRESS':>12}  {'SIZE':>6}  {'SECTION':<10}  {'TYPE':<10}  {'C':1}  DEMANGLED"
    print(header)
    print("-" * (len(header) + 20))

    for s in data:
        flag = "*" if s.is_candidate else " "
        print(f"0x{s.address:010x}  {s.size:>6}  {s.section:<10}  "
              f"{s.sym_type:<10}  {flag}  {s.demangled}")

    n_cand = sum(1 for s in data if s.is_candidate)
    print(f"\n{len(data)} symbols shown  ({n_cand} marked as SEU candidates  [*])")


def print_json(symbols: list[SymbolInfo], candidates_only: bool = False) -> str:
    data = [asdict(s) for s in symbols if (not candidates_only or s.is_candidate)]
    return json.dumps(data, indent=2)


# Candidate export (used by fault_injector.py)

def get_bituniform_sample(elf_path: Path,
                          n: int,
                          rng,
                          candidates_only: bool = True,
                          vtable_skip: int = 64,
                          ) -> list[dict]:
    """
    Return n targets sampled uniformly per bit — probability proportional to
    injectable bytes (size - vtable_skip).

    This matches the physical radiation model: a cosmic ray is equally likely
    to strike any bit in RAM, so larger structures are proportionally more
    likely to be hit.  Use this for statistical sweep campaigns.
    """
    symbols = [s for s in analyze_cached(elf_path)
               if (not candidates_only or s.is_candidate) and s.size > vtable_skip]
    if not symbols:
        return []

    weights = [s.size - vtable_skip for s in symbols]
    targets = []
    for _ in range(n):
        sym = rng.choices(symbols, weights=weights, k=1)[0]
        byte_off = rng.randint(vtable_skip, sym.size - 1)
        bit = rng.randint(0, 7)
        targets.append({
            "addr":        sym.address + byte_off,
            "bit":         bit,
            "symbol":      sym.demangled,
            "byte_offset": byte_off,
        })
    return targets


def get_stable_component_sample(
    elf_path: Path,
    total_quota: int,
    seed: int = 42,
    filter_prefix: str = "CHESS::",
    vtable_skip: int = 64,
    min_per_component: int = 1,
    exclude_re: str | None = None,
) -> tuple[list[dict], dict[str, int]]:
    """
    Physically proportional, version-stable CI sample.

    total_quota injections are distributed across components proportionally by
    injectable bytes (larger components get more samples, matching the radiation
    model within each component's footprint).  Every component gets at least
    min_per_component injections.

    Targets are keyed by (symbol_name, field_name, bit_within_field) — the same
    stable key that SEUResultDB uses for cross-version comparison.  If BSS
    addresses shift between FS versions, the same logical target resolves to the
    correct new address automatically.  New fields added in a newer version
    produce new targets; removed fields simply disappear.

    Randomisation uses SHA-256(seed:symbol:field:slot) so results are fully
    reproducible without relying on Python's PRNG state or address layout.

    Returns:
        targets    : list of injection dicts, each carrying "stable_key", "field",
                     "component", "byte_offset" in addition to "addr", "bit", "symbol"
        comp_quotas: {comp_name: quota} for display / auditing
    """
    import hashlib as _hl

    def _pick(salt: str, n: int) -> int:
        """Deterministic pick in [0, n) keyed by salt."""
        return int(_hl.sha256(salt.encode()).hexdigest(), 16) % n

    # All CHESS:: data symbols
    symbols = [
        s for s in analyze_cached(elf_path)
        if s.demangled.startswith(filter_prefix)
        and s.size > 0
        and s.section in (".bss", ".data")
    ]
    if not symbols:
        return [], {}

    # Group by component (first identifier after filter_prefix)
    comp_syms: dict[str, list] = {}
    for sym in symbols:
        remainder = sym.demangled[len(filter_prefix):]
        comp = re.split(r"[<:]", remainder)[0]
        if comp:
            comp_syms.setdefault(comp, []).append(sym)

    # Resolve DWARF fields for all symbols at once (one DWARF parse)
    all_fields = expand_symbol_fields(elf_path, symbols)  # sym.name -> [FieldInfo]

    # Build per-component list of injectable "units":
    # (sym, field_name_or_None, field_byte_offset, field_size_bytes)
    # field_byte_offset is relative to sym.address.
    comp_units: dict[str, list[tuple]] = {}
    for comp, syms in comp_syms.items():
        units: list[tuple] = []
        for sym in syms:
            fields = all_fields.get(sym.name, [])
            inject_start = min(vtable_skip, sym.size)
            if fields:
                for fi in fields:
                    if fi.is_base or fi.size == 0:
                        continue
                    if fi.offset + fi.size <= inject_start:
                        continue
                    units.append((sym, fi.field_name, fi.offset, fi.size))
            else:
                # No DWARF: whole injectable range is one anonymous unit
                injectable = sym.size - inject_start
                if injectable > 0:
                    units.append((sym, None, inject_start, injectable))
        if units:
            comp_units[comp] = units

    if not comp_units:
        return [], {}

    # Apply component exclusion filter
    if exclude_re:
        _excl = re.compile(exclude_re, re.IGNORECASE)
        comp_units = {c: u for c, u in comp_units.items()
                      if not _excl.search(c)}
    if not comp_units:
        return [], {}

    # Injectable bytes per component (for quota distribution)
    comp_bytes = {c: sum(u[3] for u in us) for c, us in comp_units.items()}
    total_bytes = sum(comp_bytes.values())
    n_comps = len(comp_units)

    # Distribute total_quota proportionally; guaranteed floor per component
    guaranteed = n_comps * min_per_component
    extra_pool = max(0, total_quota - guaranteed)
    comp_quotas: dict[str, int] = {}
    for comp in sorted(comp_units):
        frac = comp_bytes[comp] / total_bytes if total_bytes else 1 / n_comps
        comp_quotas[comp] = min_per_component + round(extra_pool * frac)

    # Correct rounding drift so sum == total_quota
    delta = total_quota - sum(comp_quotas.values())
    if delta != 0:
        anchor = max(comp_quotas, key=lambda c: comp_bytes[c])
        comp_quotas[anchor] = max(min_per_component, comp_quotas[anchor] + delta)

    # Generate stable targets
    targets: list[dict] = []
    for comp in sorted(comp_units):
        units = sorted(comp_units[comp],
                       key=lambda u: (u[0].name, u[1] or ""))  # stable order
        unit_weights = [u[3] for u in units]
        cum_weights = []
        acc = 0
        for w in unit_weights:
            acc += w
            cum_weights.append(acc)
        total_w = cum_weights[-1]

        for slot in range(comp_quotas[comp]):
            # Pick unit proportionally by size using stable hash
            unit_pick = _pick(f"{seed}:{comp}:unit:{slot}", total_w)
            unit = next(u for u, c in zip(units, cum_weights) if unit_pick < c)
            sym, field_name, field_offset, field_size = unit

            # Pick bit within field using stable hash
            bit_in_field = _pick(f"{seed}:{sym.demangled}:{field_name or ''}:{slot}",
                                 field_size * 8)
            byte_in_field = bit_in_field // 8
            bit = bit_in_field % 8
            addr = sym.address + field_offset + byte_in_field

            targets.append({
                "addr":        addr,
                "bit":         bit,
                "symbol":      sym.demangled,
                "field":       field_name,
                "byte_offset": field_offset + byte_in_field,
                "component":   comp,
                "stable_key":  f"{sym.demangled}::{field_name or ''}::{bit_in_field}",
            })

    return targets, comp_quotas


def summarise_candidates(elf_path: Path, candidates_only: bool = True) -> list[dict]:
    """
    Return a sorted list of candidate symbols with their size for display.
    """
    symbols = [s for s in analyze_cached(elf_path)
               if (not candidates_only or s.is_candidate) and s.size > 0]
    return sorted(
        [{"name": s.demangled, "size": s.size, "addr": s.address,
          "section": s.section} for s in symbols],
        key=lambda x: x["size"], reverse=True,
    )


def get_injection_targets(elf_path: Path,
                          candidates_only: bool = True,
                          filter_re: re.Pattern | None = None,
                          max_symbol_bytes: int = 8192,
                          ) -> list[dict]:
    """
    High-level function: return a flat list of {addr, bit, symbol, byte_offset}
    dicts ready for injection scheduling.  Called by fault_injector.py.

    Symbols larger than max_symbol_bytes are sampled with smart_targets()
    (every 4 bytes, 3 bits) instead of the exhaustive bit_targets() (every
    byte, every bit).  This prevents huge buffers like CdhCore::tlmSend
    (593 KB, 4.75 M targets) from dominating random-sweep samples.
    """
    symbols = analyze_cached(elf_path, filter_re=filter_re)
    targets = []
    for s in symbols:
        if candidates_only and not s.is_candidate:
            continue
        if s.size > max_symbol_bytes:
            # Huge buffers (telemetry rings, log stores) are mostly unallocated
            # demand-paged BSS reads fail and they contribute nothing interesting
            # to an SEU campaign. Skip them entirely.
            continue
        targets.extend(s.bit_targets())
    return targets


# CLI entry point

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract SEU injection targets from a CHESS ARM ELF binary."
    )
    parser.add_argument("elf", help="Path to the ARM ELF binary")
    parser.add_argument("--filter", metavar="REGEX",
                        help="Only show symbols matching this regex")
    parser.add_argument("--section", metavar="NAME",
                        help="Only show symbols in this ELF section")
    parser.add_argument("--candidates", action="store_true",
                        help="Only show high-value SEU candidate symbols")
    parser.add_argument("--smart", action="store_true",
                        help="Emit smart injection targets as JSON (skip vtable, "
                             "sample every 4B past it, bits 0/3/7 per byte)")
    parser.add_argument("--skip-vtable", metavar="N", type=int, default=64,
                        help="Bytes to skip at object start (vtable region, default: 64)")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON output")
    parser.add_argument("--out", metavar="FILE",
                        help="Write output to file")
    parser.add_argument("--expand", action="store_true",
                        help="Walk DWARF debug info to show per-field layout of matching "
                             "OBJECT symbols. Requires a -g (debug) binary.")
    args = parser.parse_args()

    elf_path = Path(args.elf)
    if not elf_path.exists():
        sys.exit(f"ERROR: ELF file not found: {elf_path}")

    # Build combined filter regex
    filter_parts = []
    if args.filter:
        filter_parts.append(args.filter)
    if args.section:
        # We'll post-filter by section below since analyze() doesn't take section
        pass

    filter_re = re.compile("|".join(filter_parts)) if filter_parts else None

    symbols = analyze(elf_path, filter_re=filter_re)

    # Section post-filter
    if args.section:
        symbols = [s for s in symbols if s.section == args.section]

    if args.expand:
        obj_symbols = [s for s in symbols if s.sym_type in _DATA_TYPES]
        if not obj_symbols:
            print("(no OBJECT symbols match try adjusting --filter)")
            return
        field_map = expand_symbol_fields(elf_path, obj_symbols)
        for s in obj_symbols:
            print_expansion(s, field_map.get(s.name, []))
        return

    if args.smart:
        targets = []
        for s in symbols:
            if not s.is_candidate:
                continue
            targets.extend(s.smart_targets(vtable_skip=args.skip_vtable))
        out_str = json.dumps(targets, indent=2)
        print(f"# {len(targets)} smart targets from {sum(1 for s in symbols if s.is_candidate)} candidates "
              f"(vtable_skip={args.skip_vtable})", file=sys.stderr)
    elif args.json:
        out_str = print_json(symbols, candidates_only=args.candidates)
    else:
        # Capture table output as string
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_table(symbols, candidates_only=args.candidates)
        out_str = buf.getvalue()

    if args.out:
        Path(args.out).write_text(out_str)
        print(f"Written to {args.out}")
    else:
        print(out_str, end="")


if __name__ == "__main__":
    main()
