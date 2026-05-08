"""Interactive CLI for manual fault injection."""

from __future__ import annotations

import json

from nest_client.seu.injector import FaultInjectorClient

from ..config import SOCK_PATH
from ..helpers import print_banner


def run_interactive(_args) -> None:
    """Interactive mode: query the plugin and inject manually from the CLI."""
    print_banner("SEU Fault Injection Interactive Mode")

    with FaultInjectorClient(SOCK_PATH) as fi:
        cnt = fi.get_count()
        print(f"Plugin connected. insn_count = {cnt:,}")
        print("Commands:  count | inject <addr_hex> <bit> <delay> | result | clear | quit")
        print()

        while True:
            try:
                line = input("fi> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            parts = line.split()
            cmd   = parts[0].lower()

            if cmd in ("q", "quit", "exit"):
                break
            elif cmd == "count":
                print(f"insn_count = {fi.get_count():,}  pending = {fi.is_pending()}")
            elif cmd == "result":
                r = fi.last_result()
                print(json.dumps(r, indent=2) if r else "No result yet.")
            elif cmd == "clear":
                fi.clear()
                print("Cleared.")
            elif cmd == "inject":
                if len(parts) < 4:
                    print("Usage: inject <addr_hex> <bit 0-7> <delay_insns>")
                    continue
                try:
                    addr  = int(parts[1], 0)
                    bit   = int(parts[2])
                    delay = int(parts[3])
                except ValueError as e:
                    print(f"Parse error: {e}")
                    continue
                trigger = fi.inject_mem(addr=addr, bit=bit, delay=delay)
                print(f"Scheduled at insn {trigger:,}. Waiting…")
                r = fi.wait_for_result(timeout=60.0)
                print(json.dumps(r, indent=2) if r else "Timed out.")
            else:
                print(f"Unknown command: {cmd}")
