"""
nest_client.seu.result_db
─────────────────────────
Persistent SQLite store for SEU fault-injection results.

Purpose
-------
Raw addresses shift whenever a global variable is added before the target in
BSS/data.  This module keys results by (symbol_demangled, field_name,
bit_within_field) — a label that stays stable as long as the C++ class and
field name don't change — so outcomes from different FS versions can be
compared automatically.

Schema (two tables)
-------------------
  runs    — one row per test campaign (FS version, binary hash, timestamp)
  results — one row per injection, FK to runs, enriched key columns

Typical usage (from a scenario)
--------------------------------
    from nest_client.seu.result_db import SEUResultDB

    db = SEUResultDB(Path("~/.seu_history.db").expanduser())
    run_id = db.start_run(elf_path, topology="topology_seu.yaml")

    # after each injection:
    db.record(run_id, addr, bit, original, flipped, write_ok,
              outcome, evidence, insn_count, elf_path)

    # at end of run — print what changed vs. the previous run on any version:
    db.print_review_queue(db.compare(run_id))

Address enrichment
------------------
  enrich_address(addr, elf_path) resolves an address to:
    symbol_name  — demangled C++ symbol (e.g. "CHESS::obcSensorsManager")
    field_name   — DWARF member name    (e.g. "magConsecutiveFailures")
    byte_offset  — addr - symbol.address
    field_offset — byte offset of field within symbol (from DWARF)
    field_bit_offset — (byte_offset - field_offset) * 8 + bit
                       stable bit-position within the field across builds
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ── Schema ───────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS runs (
    run_id       TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    fs_git_hash  TEXT,
    binary_hash  TEXT NOT NULL,
    binary_path  TEXT NOT NULL,
    topology     TEXT,
    notes        TEXT
);

CREATE TABLE IF NOT EXISTS results (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            TEXT    NOT NULL REFERENCES runs(run_id),
    addr              INTEGER NOT NULL,
    bit               INTEGER NOT NULL,
    byte_offset       INTEGER,
    symbol_name       TEXT,
    field_name        TEXT,
    field_offset      INTEGER,
    field_bit_offset  INTEGER,
    section           TEXT,
    original          INTEGER,
    flipped           INTEGER,
    write_ok          INTEGER,
    outcome           TEXT    NOT NULL,
    evidence          TEXT,
    insn_count        INTEGER,
    elapsed_s         REAL
);

CREATE INDEX IF NOT EXISTS idx_results_key
    ON results(symbol_name, field_name, field_bit_offset);
CREATE INDEX IF NOT EXISTS idx_results_run
    ON results(run_id);
"""

# ── Helpers ──────────────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]  # 16 hex chars is plenty for display


def _git_hash(elf_path: Path) -> str | None:
    """Try to get the HEAD commit of the CHESS-FS repo containing elf_path."""
    try:
        # Walk up until we find a .git directory
        repo = elf_path
        for _ in range(8):
            repo = repo.parent
            if (repo / ".git").exists():
                result = subprocess.run(
                    ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
                    capture_output=True, text=True, check=True,
                )
                return result.stdout.strip()
    except Exception:
        pass
    return None


# ── Address enrichment ────────────────────────────────────────────────────────

@dataclass
class AddrInfo:
    symbol_name: str
    field_name: str | None
    byte_offset: int          # addr − symbol.address
    field_offset: int | None  # field's byte offset within symbol (from DWARF)
    section: str

    @property
    def field_bit_offset(self) -> int | None:
        """Stable bit position within the field (cross-version comparison key)."""
        if self.field_offset is None:
            return None
        return (self.byte_offset - self.field_offset) * 8  # bit added at record time


class AddressEnricher:
    """
    Lazily builds symbol and DWARF indices from an ELF binary.
    Cache one instance per (run, elf_path) to avoid repeated parsing.
    """

    def __init__(self, elf_path: Path):
        self._elf = elf_path
        self._symbols: list | None = None      # list[SymbolInfo], sorted by address
        self._field_cache: dict = {}           # sym.name → list[FieldInfo]

    def _ensure_symbols(self) -> list:
        if self._symbols is None:
            from nest_client.seu.elf_analyzer import analyze
            syms = analyze(self._elf)
            # All symbols with a known size — data objects AND functions (.text)
            self._symbols = sorted(
                [s for s in syms if s.size > 0],
                key=lambda s: s.address,
            )
        return self._symbols

    def _fields_for(self, sym) -> list:
        if sym.name not in self._field_cache:
            try:
                from nest_client.seu.elf_analyzer import expand_symbol_fields
                result = expand_symbol_fields(self._elf, [sym])
                self._field_cache[sym.name] = result.get(sym.name, [])
            except Exception:
                self._field_cache[sym.name] = []
        return self._field_cache[sym.name]

    def lookup(self, addr: int) -> AddrInfo | None:
        syms = self._ensure_symbols()
        # Binary search for the symbol containing addr
        lo, hi = 0, len(syms) - 1
        sym = None
        while lo <= hi:
            mid = (lo + hi) // 2
            s = syms[mid]
            if addr < s.address:
                hi = mid - 1
            elif addr >= s.address + max(s.size, 1):
                lo = mid + 1
            else:
                sym = s
                break

        if sym is None:
            return None

        byte_off = addr - sym.address
        fields = self._fields_for(sym)

        # Find the field that contains byte_off
        field_name = None
        field_offset = None
        for fi in fields:
            if fi.is_base:
                continue
            if fi.offset <= byte_off < fi.offset + max(fi.size, 1):
                field_name = fi.field_name
                field_offset = fi.offset
                break

        return AddrInfo(
            symbol_name=sym.demangled,
            field_name=field_name,
            byte_offset=byte_off,
            field_offset=field_offset,
            section=sym.section,
        )


# ── Review item ───────────────────────────────────────────────────────────────

@dataclass
class ReviewItem:
    symbol_name: str
    field_name: str | None
    field_bit_offset: int | None
    bit: int
    run_a_id: str
    run_b_id: str
    outcome_a: str
    outcome_b: str
    evidence_a: str | None
    evidence_b: str | None
    addr_a: int
    addr_b: int
    # metadata
    run_a_ts: str
    run_b_ts: str
    run_a_hash: str
    run_b_hash: str
    run_a_git: str | None
    run_b_git: str | None

    @property
    def is_regression(self) -> bool:
        """True if a previously-MASKED target now produces a worse outcome."""
        return self.outcome_a == "MASKED" and self.outcome_b != "MASKED"

    @property
    def is_improvement(self) -> bool:
        return self.outcome_a != "MASKED" and self.outcome_b == "MASKED"

    @property
    def severity(self) -> str:
        """For sorting: REGRESSION > NEW_CRASH > CHANGED > IMPROVEMENT."""
        if self.is_regression:
            return "REGRESSION"
        if self.outcome_b == "CRASH" and self.outcome_a != "CRASH":
            return "NEW_CRASH"
        if self.is_improvement:
            return "IMPROVEMENT"
        return "CHANGED"


# ── Database ──────────────────────────────────────────────────────────────────

# SP root = 4 levels up from this file (seu/result_db.py → seu/ → nest_client/ → nest-python-client/ → SP/)
_SP_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DEFAULT_DB = Path(os.environ.get("SEU_DB", str(_SP_ROOT / "seu_history.db")))


class SEUResultDB:
    """
    Persistent SQLite store for SEU fault-injection results.

    Example
    -------
        db = SEUResultDB()
        run_id = db.start_run(elf_path, topology="topology_seu.yaml")
        db.record(run_id, addr=0x..., bit=0, ..., elf_path=elf_path)
        db.print_review_queue(db.compare(run_id))
    """

    def __init__(self, db_path: Path = _DEFAULT_DB):
        self.db_path = Path(db_path)
        self._con = sqlite3.connect(str(self.db_path))
        self._con.row_factory = sqlite3.Row
        self._con.executescript(_DDL)
        self._con.commit()
        self._enrichers: dict[str, AddressEnricher] = {}

    def close(self):
        self._con.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ── Run management ────────────────────────────────────────────────────────

    def start_run(
        self,
        elf_path: Path,
        topology: str | None = None,
        notes: str | None = None,
    ) -> str:
        """
        Create a new run record.  Returns the run_id (UUID string).
        Prints version metadata to stdout so it appears in the scenario log.
        """
        run_id = str(uuid.uuid4())
        binary_hash = _sha256(elf_path)
        git_hash = _git_hash(elf_path)
        ts = datetime.now(timezone.utc).isoformat()

        self._con.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?)",
            (run_id, ts, git_hash, binary_hash, str(elf_path), topology, notes),
        )
        self._con.commit()

        print(f"[SEUResultDB] run_id   : {run_id}")
        print(f"[SEUResultDB] timestamp: {ts}")
        print(f"[SEUResultDB] binary   : {elf_path.name}  sha256={binary_hash}")
        if git_hash:
            print(f"[SEUResultDB] git HEAD : {git_hash}")
        print(f"[SEUResultDB] db       : {self.db_path}")

        return run_id

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        """Accept full UUID or any unambiguous prefix."""
        row = self._con.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is not None:
            return row
        # Prefix match
        rows = self._con.execute(
            "SELECT * FROM runs WHERE run_id LIKE ?", (run_id + "%",)
        ).fetchall()
        if len(rows) == 1:
            return rows[0]
        if len(rows) > 1:
            ids = ", ".join(r["run_id"] for r in rows)
            raise ValueError(f"Ambiguous prefix '{run_id}' matches: {ids}")
        return None

    def list_runs(self, limit: int = 20) -> list[sqlite3.Row]:
        return self._con.execute(
            "SELECT r.*, COUNT(res.id) AS n_results "
            "FROM runs r LEFT JOIN results res ON r.run_id = res.run_id "
            "GROUP BY r.run_id ORDER BY r.timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def delete_run(self, run_id: str) -> int:
        """
        Delete a run and all its results.  Accepts a prefix.
        Returns the number of result rows deleted.
        """
        meta = self.get_run(run_id)
        if meta is None:
            raise ValueError(f"Run not found: '{run_id}'")
        full_id = meta["run_id"]
        n = self._con.execute(
            "SELECT COUNT(*) FROM results WHERE run_id = ?", (full_id,)
        ).fetchone()[0]
        self._con.execute("DELETE FROM results WHERE run_id = ?", (full_id,))
        self._con.execute("DELETE FROM runs WHERE run_id = ?", (full_id,))
        self._con.commit()
        return n

    # ── Result recording ──────────────────────────────────────────────────────

    def _enricher(self, elf_path: Path) -> AddressEnricher:
        key = str(elf_path)
        if key not in self._enrichers:
            self._enrichers[key] = AddressEnricher(elf_path)
        return self._enrichers[key]

    def record(
        self,
        run_id: str,
        addr: int,
        bit: int,
        original: int,
        flipped: int,
        write_ok: bool,
        outcome: str,
        evidence: str | None = None,
        insn_count: int | None = None,
        elapsed_s: float | None = None,
        elf_path: Path | None = None,
    ) -> None:
        """
        Store one injection result.  If elf_path is provided the address is
        resolved to a (symbol, field, bit_within_field) stable key.
        """
        info: AddrInfo | None = None
        if elf_path is not None:
            try:
                info = self._enricher(elf_path).lookup(addr)
            except Exception:
                pass

        fbo = None
        if info is not None and info.field_bit_offset is not None:
            fbo = info.field_bit_offset + bit

        self._con.execute(
            """INSERT INTO results
               (run_id, addr, bit, byte_offset, symbol_name, field_name,
                field_offset, field_bit_offset, section,
                original, flipped, write_ok, outcome, evidence,
                insn_count, elapsed_s)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run_id, addr, bit,
                info.byte_offset if info else None,
                info.symbol_name if info else None,
                info.field_name if info else None,
                info.field_offset if info else None,
                fbo,
                info.section if info else None,
                original, flipped, int(write_ok), outcome,
                evidence or "", insn_count, elapsed_s,
            ),
        )
        self._con.commit()

    # ── Comparison ────────────────────────────────────────────────────────────

    def compare(
        self,
        run_id_a: str,
        run_id_b: str | None = None,
    ) -> list[ReviewItem]:
        """
        Compare run_id_a against run_id_b (defaults to the most recent
        *other* run in the DB).  Both IDs may be abbreviated prefixes.

        Returns ReviewItems where the outcome differs for the same
        (symbol_name, field_name, field_bit_offset) key.

        Results with no symbol info (e.g. .text injections) are keyed by
        (addr, bit) instead, which is fragile across builds but still useful
        within the same build.
        """
        # Resolve prefixes to full UUIDs
        meta_a = self.get_run(run_id_a)
        if meta_a is None:
            raise ValueError(f"Run not found: '{run_id_a}'")
        run_id_a = meta_a["run_id"]

        if run_id_b is None:
            row = self._con.execute(
                "SELECT run_id FROM runs WHERE run_id != ? "
                "ORDER BY timestamp DESC LIMIT 1",
                (run_id_a,),
            ).fetchone()
            if row is None:
                return []
            run_id_b = row["run_id"]

        meta_b = self.get_run(run_id_b)
        if meta_b is None:
            raise ValueError(f"Run not found: '{run_id_b}'")
        if meta_a is None or meta_b is None:
            return []

        # Build a {key: row} map for each run
        def _rows(rid: str) -> dict[tuple, sqlite3.Row]:
            rows = self._con.execute(
                "SELECT * FROM results WHERE run_id = ?", (rid,)
            ).fetchall()
            out: dict[tuple, sqlite3.Row] = {}
            for r in rows:
                if r["symbol_name"] and r["field_bit_offset"] is not None:
                    key = (r["symbol_name"], r["field_name"], r["field_bit_offset"])
                else:
                    # Fall back to raw addr+bit for .text or unresolved symbols
                    key = ("__raw__", str(r["addr"]), r["bit"])
                out[key] = r
            return out

        rows_a = _rows(run_id_a)
        rows_b = _rows(run_id_b)

        items: list[ReviewItem] = []
        for key in set(rows_a) & set(rows_b):
            ra, rb = rows_a[key], rows_b[key]
            if ra["outcome"] == rb["outcome"]:
                continue
            items.append(ReviewItem(
                symbol_name      = ra["symbol_name"] or str(ra["addr"]),
                field_name       = ra["field_name"],
                field_bit_offset = ra["field_bit_offset"],
                bit              = ra["bit"],
                run_a_id         = run_id_a,
                run_b_id         = run_id_b,
                outcome_a        = ra["outcome"],
                outcome_b        = rb["outcome"],
                evidence_a       = ra["evidence"],
                evidence_b       = rb["evidence"],
                addr_a           = ra["addr"],
                addr_b           = rb["addr"],
                run_a_ts         = meta_a["timestamp"],
                run_b_ts         = meta_b["timestamp"],
                run_a_hash       = meta_a["binary_hash"],
                run_b_hash       = meta_b["binary_hash"],
                run_a_git        = meta_a["fs_git_hash"],
                run_b_git        = meta_b["fs_git_hash"],
            ))

        # Sort: REGRESSION first, then NEW_CRASH, CHANGED, IMPROVEMENT
        _order = {"REGRESSION": 0, "NEW_CRASH": 1, "CHANGED": 2, "IMPROVEMENT": 3}
        items.sort(key=lambda x: _order.get(x.severity, 9))
        return items

    def print_review_queue(self, items: list[ReviewItem]) -> None:
        if not items:
            print("\n[SEUResultDB] No outcome changes detected — runs are consistent.")
            return

        w = 78
        print("\n" + "═" * w)
        print("  SEU REVIEW QUEUE — outcome changed between runs")
        print("═" * w)

        _colour = {
            "REGRESSION":  "\033[91m",  # red
            "NEW_CRASH":   "\033[91m",
            "CHANGED":     "\033[93m",  # yellow
            "IMPROVEMENT": "\033[92m",  # green
        }
        _reset = "\033[0m"

        for item in items:
            c = _colour.get(item.severity, "")
            field = item.field_name or "(no DWARF field)"
            print(f"\n  {c}{item.severity}{_reset}")
            print(f"  Symbol  : {item.symbol_name}")
            print(f"  Field   : {field}  bit_pos={item.field_bit_offset}  bit={item.bit}")
            print(f"  Run A   : {item.run_a_ts[:19]}  git={item.run_a_git}  "
                  f"bin={item.run_a_hash}  addr=0x{item.addr_a:08x}")
            print(f"  Run B   : {item.run_b_ts[:19]}  git={item.run_b_git}  "
                  f"bin={item.run_b_hash}  addr=0x{item.addr_b:08x}")
            print(f"  Outcome : {item.outcome_a} (A) VS {item.outcome_b} (B)")
            if item.evidence_a:
                print(f"  Evid A  : {item.evidence_a[:100]}")
            if item.evidence_b:
                print(f"  Evid B  : {item.evidence_b[:100]}")

        regs  = sum(1 for i in items if i.severity == "REGRESSION")
        crash = sum(1 for i in items if i.severity == "NEW_CRASH")
        impr  = sum(1 for i in items if i.severity == "IMPROVEMENT")
        other = len(items) - regs - crash - impr
        print(f"\n{'─' * w}")
        print(f"  Total changed : {len(items)}  "
              f"regressions={regs}  new_crashes={crash}  "
              f"improvements={impr}  other={other}")
        if regs + crash > 0:
            print("  ⚠  Human review required for REGRESSION / NEW_CRASH items.")
        print("═" * w + "\n")

    # ── Reporting ─────────────────────────────────────────────────────────────

    def print_run_summary(self, run_id: str) -> None:
        """Print a per-injection table with DWARF field names, then outcome totals."""
        meta = self.get_run(run_id)
        if meta is None:
            print(f"Run not found: {run_id}")
            return
        run_id = meta["run_id"]  # resolve prefix to full UUID

        detail = self._con.execute(
            "SELECT addr, bit, section, symbol_name, field_name, "
            "       field_bit_offset, original, flipped, outcome, evidence "
            "FROM results WHERE run_id = ? "
            "ORDER BY section DESC, addr, bit",   # .text first (DESC), then bss
            (run_id,),
        ).fetchall()

        _c = {"MASKED": "\033[92m", "DETECTED": "\033[93m", "CRASH": "\033[91m"}
        _r = "\033[0m"

        print(f"\n  Run: {run_id}")
        print(f"  FS : {meta['binary_path']}  sha={meta['binary_hash']}")
        if meta["fs_git_hash"]:
            print(f"  Git: {meta['fs_git_hash']}")
        print(f"  At : {meta['timestamp'][:19]}")
        print()
        print(f"  {'ADDR':>10}  {'B':>1}  {'BEFORE→AFTER':^19}  {'SECTION':<6}  {'SYMBOL / FIELD':<44}  {'OUTCOME':<10}  EVIDENCE")
        print(f"  {'─'*10}  {'─':>1}  {'─'*19}  {'─'*6}  {'─'*44}  {'─'*10}  {'─'*40}")

        for r in detail:
            sym  = r["symbol_name"] or ""
            fld  = r["field_name"]  or ""
            sec  = r["section"]     or ""
            ev   = r["evidence"]    or ""
            orig = r["original"]
            flip = r["flipped"]
            if orig is not None and flip is not None:
                bits = f"{orig:08b}→{flip:08b}"
            else:
                bits = "?" * 19
            # Compact the evidence to its essential content:
            # "[EVR] EVENT: (...) WARNING_HI: (comQueue) QueueOverflow : ..."
            # → "QueueOverflow (comQueue)"
            # "[OS] Segmentation fault (core dumped)"
            # → "Segmentation fault"
            import re as _re
            ev_short = ev
            if "[EVR]" in ev:
                m = _re.search(
                    r'(?:WARNING_HI|FATAL|ACTIVITY_HI|ACTIVITY_LO|COMMAND_HI|COMMAND_LO)'
                    r':\s+\(([^)]+)\)\s+(\S+)',
                    ev
                )
                if m:
                    ev_short = f"{m.group(2)} ({m.group(1)})"
                else:
                    # Fallback: everything after last ") "
                    parts = ev.rsplit(") ", 1)
                    ev_short = parts[-1] if len(parts) > 1 else ev
            elif "[OS]" in ev:
                ev_short = ev.replace("[OS] ", "").split(" (core")[0]
            ev_short = ev_short[:70]

            if fld:
                sym_short = sym.split("::")[-1] if "::" in sym else sym
                label = f"{sym_short} :: {fld}"
            elif sym:
                label = sym.split("::")[-1] if "::" in sym else sym
            else:
                label = "(unknown)"
            label = label[:44]
            c = _c.get(r["outcome"], "")
            print(f"  0x{r['addr']:08x}  {r['bit']}  {bits:^19}  {sec:<6}  {label:<44}  "
                  f"{c}{r['outcome']:<10}{_r}  {ev_short}")

        # Totals
        total = len(detail)
        from collections import Counter
        counts = Counter(r["outcome"] for r in detail)
        print(f"  {'─'*10}  {'─':>1}  {'─'*19}  {'─'*6}  {'─'*44}  {'─'*10}  {'─'*40}")
        print(f"  {'OUTCOME':<12}  {'N':>5}  {'%':>6}")
        print(f"  {'─'*12}  {'─'*5}  {'─'*6}")
        for outcome, n in sorted(counts.items(), key=lambda x: -x[1]):
            c = _c.get(outcome, "")
            pct = 100 * n / total if total else 0
            print(f"  {c}{outcome:<12}{_r}  {n:>5}  {pct:>5.1f}%")
        print(f"  {'─'*12}  {'─'*5}  {'─'*6}")
        print(f"  {'TOTAL':<12}  {total:>5}")

    def export_jsonl(self, run_id: str, out_path: Path) -> int:
        """Export one run's results to a JSONL file. Returns record count."""
        meta = self.get_run(run_id)
        if meta is None:
            raise ValueError(f"Run not found: '{run_id}'")
        run_id = meta["run_id"]
        rows = self._con.execute(
            "SELECT r.*, ru.fs_git_hash, ru.binary_hash, ru.timestamp AS run_ts "
            "FROM results r JOIN runs ru ON r.run_id = ru.run_id "
            "WHERE r.run_id = ?",
            (run_id,),
        ).fetchall()
        with out_path.open("w") as f:
            for row in rows:
                f.write(json.dumps(dict(row)) + "\n")
        return len(rows)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli():
    import argparse, sys

    parser = argparse.ArgumentParser(
        prog="python -m nest_client.seu.result_db",
        description="Inspect and compare SEU campaign results",
    )
    parser.add_argument("--db", default=str(_DEFAULT_DB), metavar="PATH",
                        help=f"SQLite DB path (default: {_DEFAULT_DB})")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("runs", help="List all runs")

    p_sum = sub.add_parser("summary", help="Summarise one run")
    p_sum.add_argument("run_id")

    p_cmp = sub.add_parser("compare", help="Compare two runs")
    p_cmp.add_argument("run_a")
    p_cmp.add_argument("run_b", nargs="?", default=None,
                       help="Defaults to the most recent other run")

    p_exp = sub.add_parser("export", help="Export run to JSONL")
    p_exp.add_argument("run_id")
    p_exp.add_argument("out", help="Output file path")

    p_del = sub.add_parser("delete", help="Delete a run and all its results")
    p_del.add_argument("run_id", help="Full UUID or unambiguous prefix")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help(); sys.exit(0)

    with SEUResultDB(Path(args.db)) as db:
        if args.cmd == "runs":
            runs = db.list_runs(50)
            if not runs:
                print("No runs found.")
                return
            print(f"\n  {'RUN_ID':<8}  {'TIMESTAMP':<20}  {'GIT':<8}  "
                  f"{'BIN':<16}  {'N':>5}  TOPOLOGY")
            print(f"  {'─'*8}  {'─'*20}  {'─'*8}  {'─'*16}  {'─'*5}  {'─'*20}")
            for r in runs:
                print(f"  {r['run_id'][:8]:<8}  {r['timestamp'][:19]:<20}  "
                      f"{(r['fs_git_hash'] or 'n/a')[:8]:<8}  "
                      f"{(r['binary_hash'] or ''):<16}  {r['n_results']:>5}  "
                      f"{r['topology'] or ''}")

        elif args.cmd == "summary":
            db.print_run_summary(args.run_id)

        elif args.cmd == "compare":
            items = db.compare(args.run_a, args.run_b)
            db.print_review_queue(items)

        elif args.cmd == "export":
            n = db.export_jsonl(args.run_id, Path(args.out))
            print(f"Exported {n} records to {args.out}")

        elif args.cmd == "delete":
            n = db.delete_run(args.run_id)
            print(f"Deleted run {args.run_id} ({n} results removed)")


if __name__ == "__main__":
    _cli()
