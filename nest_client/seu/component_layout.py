#!/usr/bin/env python3
"""
component_layout.py — Generalized field-level address map for CHESS FPrime components.

Pipeline
--------
  1. Read production ELF symbol table  → {symbol_name: (address, size)}
  2. For each matched symbol, infer the source .cpp path from the symbol name
  3. Compile that .cpp with -g3 -O0 → /tmp/<Name>_layout.o
  4. Walk DWARF in the debug .o      → [(offset, field_name, type)]
  5. Output: base_addr + offset → abs_addr, field_name, type

Usage
-----
  python3 component_layout.py <production_elf> [options]

Options
-------
  --build-dir <path>   FPrime build directory (default: auto-detect sibling of binary)
  --src-dir   <path>   CHESS source root (default: auto-detect from build-dir)
  --filter    <regex>  Only process symbols matching this pattern (default: CHESS::)
  --json               Output JSON instead of human-readable table
  --compiler  <path>   ARM cross-compiler (default: arm-none-linux-gnueabihf-g++)
  --out       <file>   Write output to file

Examples
--------
  # All CHESS components
  python3 component_layout.py CHESS_Pathfinder0FS

  # Just OBCSensorsManager
  python3 component_layout.py CHESS_Pathfinder0FS --filter obcSensors

  # Any Svc component too
  python3 component_layout.py CHESS_Pathfinder0FS --filter "CHESS::|Svc::"
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict, field
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    sys.exit("ERROR: pyelftools not installed — pip install pyelftools")

# ── Types ─────────────────────────────────────────────────────────────────────

@dataclass
class FieldInfo:
    offset: int
    abs_addr: int
    size: int
    type_name: str
    field_name: str
    is_base: bool = False

@dataclass
class SymbolLayout:
    symbol_name: str      # mangled
    demangled: str
    address: int
    total_size: int
    fields: list[FieldInfo] = field(default_factory=list)

# ── DWARF helpers ──────────────────────────────────────────────────────────────

def _build_die_index(dwarf_info) -> dict:
    index = {}
    for cu in dwarf_info.iter_CUs():
        for die in cu.iter_DIEs():
            index[die.offset] = die
    return index

def _ref_abs(attr, cu) -> int:
    if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4',
                     'DW_FORM_ref8', 'DW_FORM_ref_udata'):
        return cu.cu_offset + attr.value
    return attr.value

def _follow(die, die_index):
    attr = die.attributes.get('DW_AT_type')
    return die_index.get(_ref_abs(attr, die.cu)) if attr else None

def _deref(die, die_index):
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
    if die is None or depth > 6:
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
        # Try to find array bounds
        for child in die.iter_children():
            if child.tag == 'DW_TAG_subrange_type':
                ub = child.attributes.get('DW_AT_upper_bound')
                if ub:
                    return _type_str(inner, die_index, depth + 1) + f'[{ub.value + 1}]'
        return _type_str(inner, die_index, depth + 1) + '[]'
    if tag in ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type'):
        return _type_str(inner, die_index, depth + 1)
    return tag.replace('DW_TAG_', '')

def _byte_size(die, die_index) -> int:
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
    attr = child.attributes.get('DW_AT_data_member_location')
    if attr is None:
        return None
    v = attr.value
    if isinstance(v, int):
        return v
    b = list(v)
    if b and b[0] in (0x23, 0x10) and len(b) > 1:  # DW_OP_plus_uconst / DW_OP_constu
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

def _collect_fields(type_die, die_index, base_off: int = 0,
                    depth: int = 0) -> list[tuple[int, int, str, str, bool]]:
    """Collect (offset, size, type_str, field_name, is_base) for all members."""
    if depth > 6 or type_die is None:
        return []
    resolved = _deref(type_die, die_index)
    if resolved is None or resolved.tag not in (
            'DW_TAG_class_type', 'DW_TAG_structure_type', 'DW_TAG_union_type'):
        return []

    results = []
    for child in resolved.iter_children():
        if child.tag == 'DW_TAG_inheritance':
            off = _member_byte_offset(child) or 0
            base_type = _follow(child, die_index)
            base_name = _type_str(base_type, die_index) if base_type else '?'
            base_sz = _byte_size(_deref(base_type, die_index) if base_type else None, die_index)
            results.append((base_off + off, base_sz, base_name, f'<base: {base_name}>', True))

        elif child.tag == 'DW_TAG_member':
            if child.attributes.get('DW_AT_external'):
                continue  # static member
            moff = _member_byte_offset(child)
            if moff is None:
                continue
            mname = _attr_str(child, 'DW_AT_name') or '<anon>'
            mtype = _follow(child, die_index)
            msz = _byte_size(_deref(mtype, die_index) if mtype else None, die_index)
            results.append((base_off + moff, msz,
                            _type_str(mtype, die_index) if mtype else '?',
                            mname, False))

    results.sort(key=lambda r: r[0])
    return results

# ── Source location inference ──────────────────────────────────────────────────

def _demangle(mangled: str) -> str:
    try:
        r = subprocess.run(['c++filt', mangled], capture_output=True, text=True)
        return r.stdout.strip()
    except FileNotFoundError:
        return mangled

def _instance_to_class(instance_name: str) -> str:
    """
    Convert FPrime instance name to class name.
    FPrime convention: instance is lowerCamelCase, class is PascalCase of same root.
    e.g. 'obcSensorsManager' -> 'OBCSensorsManager'
         'eventAction'       -> 'EventAction'
         'linuxTime'         -> 'LinuxTime'
    Strategy: just capitalise the first letter, the rest is already correct.
    """
    if not instance_name:
        return instance_name
    return instance_name[0].upper() + instance_name[1:]

def _find_source_file(class_name: str, src_root: Path) -> tuple[Path | None, str]:
    """
    Find <ClassName>.cpp under src_root. Returns (path, resolved_class_name).
    Searches by case-insensitive directory name match to handle acronyms
    (e.g. instance 'obcSensorsManager' → class dir 'OBCSensorsManager').
    """
    components_dirs = [
        src_root / 'CHESS' / 'Components',
        src_root / 'Components',
    ]
    class_lower = class_name.lower()

    for comp_dir in components_dirs:
        if not comp_dir.exists():
            continue
        for subdir in comp_dir.iterdir():
            if subdir.is_dir() and subdir.name.lower() == class_lower:
                candidate = subdir / f'{subdir.name}.cpp'
                if candidate.exists():
                    return candidate, subdir.name

    # Recursive fallback: find any matching .cpp (case-insensitive)
    for cpp in src_root.rglob('*.cpp'):
        if cpp.stem.lower() == class_lower and 'test' not in cpp.parent.name.lower():
            return cpp, cpp.stem

    return None, class_name

def _find_generated_include_dir(class_name: str, build_dir: Path) -> Path | None:
    """Find the FPrime-generated header directory for a component."""
    # Main build tree
    p = build_dir / 'CHESS' / 'Components' / class_name
    if p.exists():
        return p
    # Sub-build-info-cache
    p2 = build_dir / 'sub-build-info-cache' / 'CHESS' / 'Components' / class_name
    if p2.exists():
        return p2
    return None

# ── Compiler invocation ────────────────────────────────────────────────────────

def _build_include_list(build_dir: Path, src_root: Path, class_name: str) -> list[str]:
    """
    Reconstruct the include paths that FPrime cmake would pass to the compiler.
    Derived from the INCLUDES variable in the build.ninja for CHESS components.
    """
    bd = build_dir  # e.g. .../CHESS-FS/build-fprime-automatic-arm-hf-linux
    includes = []

    def add(p: Path) -> None:
        # Resolve symlinks / '..' so the compiler sees a real path
        resolved = p.resolve()
        if resolved.exists():
            includes.append(str(resolved))

    add(src_root / 'lib' / 'fprime')          # fprime framework headers
    add(src_root)                              # project root
    add(bd)                                   # build root (generated headers)
    add(bd / 'F-Prime')                       # F-Prime subtree in build
    add(bd / 'cmake' / 'platform' / 'unix')   # Platform/.. resolved
    add(bd / 'F-Prime' / 'default')           # config/.. resolved → config/ accessible
    add(bd / 'sub-build-info-cache')
    add(bd / 'sub-build-info-cache' / 'F-Prime')
    add(bd / 'sub-build-info-cache' / 'F-Prime' / 'default')

    # Component-specific generated include dir (auto-generated .hpp files)
    gen_dir = _find_generated_include_dir(class_name, build_dir)
    if gen_dir:
        add(gen_dir)

    # CHESS source roots
    chess_src = src_root / 'CHESS'
    if chess_src.exists():
        add(chess_src)
        add(chess_src / 'Components')

    return includes


def _compile_debug_object(source: Path, build_dir: Path, src_root: Path,
                           class_name: str, compiler: str,
                           out_path: Path) -> bool:
    """Compile source with -g3 -O0. Returns True on success."""
    includes = _build_include_list(build_dir, src_root, class_name)

    cmd = [compiler, '-std=c++14', '-g3', '-O0', '-DTGT_OS_TYPE_LINUX']
    for inc in includes:
        cmd += ['-I', inc]
    cmd += ['-c', str(source), '-o', str(out_path)]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  COMPILE ERROR for {source.name}:", file=sys.stderr)
        print(result.stderr[:1000], file=sys.stderr)
        return False
    return True

# ── DWARF extraction from debug .o ────────────────────────────────────────────

def _extract_layout_from_object(obj_path: Path, class_name: str,
                                 base_addr: int) -> list[FieldInfo]:
    """Open the debug .o, find <class_name> DIE, return FieldInfo list."""
    with obj_path.open('rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return []
        dwarf = elf.get_dwarf_info()
        die_index = _build_die_index(dwarf)

    target_die = None
    for off, die in die_index.items():
        if die.tag in ('DW_TAG_class_type', 'DW_TAG_structure_type'):
            name = _attr_str(die, 'DW_AT_name')
            if name == class_name:
                target_die = die
                break

    if target_die is None:
        return []

    raw = _collect_fields(target_die, die_index)
    return [
        FieldInfo(
            offset=off,
            abs_addr=base_addr + off,
            size=sz,
            type_name=tname,
            field_name=fname,
            is_base=is_base,
        )
        for off, sz, tname, fname, is_base in raw
    ]

# ── Symbol table reading ───────────────────────────────────────────────────────

_DATA_TAGS = {'STT_OBJECT', 'STT_COMMON'}

def _read_symbols(elf_path: Path, filter_re: re.Pattern) -> list[tuple[str, str, int, int]]:
    """Return [(mangled, demangled, address, size)] matching filter."""
    results = []
    with elf_path.open('rb') as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                if sym['st_info']['type'] not in _DATA_TAGS:
                    continue
                if sym['st_size'] == 0:
                    continue
                mangled = sym.name
                demangled = _demangle(mangled)
                if filter_re.search(demangled) or filter_re.search(mangled):
                    results.append((mangled, demangled, sym['st_value'], sym['st_size']))
    results.sort(key=lambda r: r[2])
    return results

# ── Inference: symbol → class name ────────────────────────────────────────────

def _infer_class_name(demangled: str) -> str | None:
    """
    Extract class name from demangled symbol.
    'CHESS::obcSensorsManager'  -> 'OBCSensorsManager'
    'Svc::linuxTime'            -> 'LinuxTime'
    Falls back to last :: segment, capitalised.
    """
    # Strip namespace qualifiers
    parts = demangled.split('::')
    if len(parts) >= 2:
        instance = parts[-1]
        return _instance_to_class(instance)
    return _instance_to_class(demangled)

# ── Auto-detection ─────────────────────────────────────────────────────────────

def _autodetect_build_dir(elf_path: Path) -> Path | None:
    """Walk up from ELF to find build-fprime-automatic-*."""
    # ELF is typically at build-dir/bin/arch/CHESS_Pathfinder0FS
    for parent in elf_path.parents:
        candidates = list(parent.glob('build-fprime-automatic-arm-hf-linux'))
        if candidates:
            return candidates[0]
    return None

def _autodetect_src_root(build_dir: Path) -> Path | None:
    """build_dir is typically inside CHESS-FS/, src root is its parent."""
    # build-dir is CHESS-FS/build-fprime-automatic-...
    # CHESS-FS/ is its parent
    chess_fs = build_dir.parent
    if (chess_fs / 'CHESS').exists():
        return chess_fs
    return None

# ── Output ─────────────────────────────────────────────────────────────────────

def _print_layout(layout: SymbolLayout) -> None:
    print(f"\n{'━'*72}")
    print(f"  {layout.demangled}")
    print(f"  base  : 0x{layout.address:010x}   size: {layout.total_size} bytes")
    if not layout.fields:
        print("  (no field info — source file not found or compile failed)")
        return

    print(f"\n  {'OFFSET':>8}  {'ABS ADDR':>12}  {'SIZE':>5}  {'TYPE':<28}  FIELD")
    print(f"  {'-'*72}")
    for fi in layout.fields:
        marker = ' ← SEU' if (not fi.is_base and not fi.type_name.endswith('*')
                               and 0 < fi.size <= 8) else ''
        tag = ' (base)' if fi.is_base else ''
        print(f"  +{fi.offset:<7d}  0x{fi.abs_addr:010x}  {fi.size:>5}  "
              f"{fi.type_name:<28}  {fi.field_name}{tag}{marker}")

    targets = [fi for fi in layout.fields
               if not fi.is_base and not fi.type_name.endswith('*') and 0 < fi.size <= 8]
    print(f"\n  {len(layout.fields)} fields, {len(targets)} SEU-injectable (non-ptr ≤8B)")

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('elf', help='Production ARM ELF binary')
    ap.add_argument('--build-dir', help='FPrime build directory (auto-detected if omitted)')
    ap.add_argument('--src-dir', help='CHESS-FS source root (auto-detected if omitted)')
    ap.add_argument('--filter', default=r'CHESS::',
                    help='Regex to match demangled symbol names (default: CHESS::)')
    ap.add_argument('--json', action='store_true', help='Output JSON')
    ap.add_argument('--compiler', default='/opt/toolchains/bin/arm-none-linux-gnueabihf-g++',
                    help='ARM cross-compiler binary')
    ap.add_argument('--out', help='Write output to file')
    args = ap.parse_args()

    elf_path = Path(args.elf).resolve()
    if not elf_path.exists():
        sys.exit(f"ERROR: ELF not found: {elf_path}")

    # Auto-detect paths
    build_dir = Path(args.build_dir).resolve() if args.build_dir else None
    if build_dir is None:
        build_dir = _autodetect_build_dir(elf_path)
    if build_dir is None:
        sys.exit("ERROR: Cannot auto-detect build dir. Use --build-dir.")

    src_root = Path(args.src_dir).resolve() if args.src_dir else None
    if src_root is None:
        src_root = _autodetect_src_root(build_dir)
    if src_root is None:
        sys.exit("ERROR: Cannot auto-detect source root. Use --src-dir.")

    print(f"Binary   : {elf_path}", file=sys.stderr)
    print(f"Build dir: {build_dir}", file=sys.stderr)
    print(f"Src root : {src_root}", file=sys.stderr)

    filter_re = re.compile(args.filter)
    symbols = _read_symbols(elf_path, filter_re)
    if not symbols:
        sys.exit(f"No symbols matched filter '{args.filter}'")
    print(f"Matched {len(symbols)} symbol(s)", file=sys.stderr)

    layouts: list[SymbolLayout] = []

    with tempfile.TemporaryDirectory(prefix='chess_layout_') as tmpdir:
        tmpdir = Path(tmpdir)

        for mangled, demangled, addr, size in symbols:
            print(f"\nProcessing: {demangled} @ 0x{addr:x} ({size}B)", file=sys.stderr)

            inferred_name = _infer_class_name(demangled)
            src_file, class_name = _find_source_file(inferred_name, src_root)

            layout = SymbolLayout(symbol_name=mangled, demangled=demangled,
                                  address=addr, total_size=size)

            if src_file is None:
                print(f"  WARNING: source not found for class '{inferred_name}'", file=sys.stderr)
                layouts.append(layout)
                continue

            print(f"  Source   : {src_file.relative_to(src_root)}", file=sys.stderr)
            obj_path = tmpdir / f'{class_name}_layout.o'

            ok = _compile_debug_object(src_file, build_dir, src_root,
                                        class_name, args.compiler, obj_path)
            if not ok:
                layouts.append(layout)
                continue

            layout.fields = _extract_layout_from_object(obj_path, class_name, addr)
            if not layout.fields:
                print(f"  WARNING: no DWARF class DIE for '{class_name}' in compiled object",
                      file=sys.stderr)
            else:
                print(f"  Found {len(layout.fields)} fields", file=sys.stderr)

            layouts.append(layout)

    # Output
    import io
    buf = io.StringIO()
    if args.json:
        out = json.dumps([asdict(l) for l in layouts], indent=2)
        buf.write(out + '\n')
    else:
        for layout in layouts:
            old_stdout = sys.stdout
            sys.stdout = buf
            _print_layout(layout)
            sys.stdout = old_stdout

    output = buf.getvalue()
    if args.out:
        Path(args.out).write_text(output)
        print(f"\nOutput written to {args.out}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
