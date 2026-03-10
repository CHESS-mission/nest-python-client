import asyncio
import contextlib
import re
import sys
from enum import Enum
from typing import List


class FuzzResult(Enum):
    SUCCESS_CLEAN = "Success: Clean (No Warnings)"
    SUCCESS_HANDLED = "Success: Handled Gracefully (With Warnings)"
    CRASH_REBOOT = "Failure: Crashed and Rebooted / Recovered"
    CRASH_SILENT = "Failure: Binary Crashed / Frozen (No Heartbeat)"
    UNKNOWN = "Unknown State"


class FuzzOracle:
    """
    Listens to the F' standard output (or QEMU UART log) to determine
    the result of a fuzzing injection sequence.
    """

    def __init__(self, timeout_secs: float = 10.0):
        self.timeout_secs = timeout_secs
        self.re_rejected = re.compile(
            r"(Fuzz pkt bad header_id|Fuzz pkt bad len|Frame bad sync|Frame bad len|Failed to read (.*) sensor)"
        )
        self.re_safe_mode = re.compile(r"OBC transitioned to (CONFIG|SAFE)")
        self.re_heartbeat = re.compile(r"Sensor poll cycle started")

        self.logs = []
        self._payload_rejected = False
        self._safe_mode_triggered = False
        self._heartbeat_count = 0

    def feed_log_line(self, line: str):
        self.logs.append(line)
        if self.re_rejected.search(line):
            self._payload_rejected = True
        if self.re_safe_mode.search(line):
            self._safe_mode_triggered = True
        if self.re_heartbeat.search(line):
            self._heartbeat_count += 1

    def evaluate(self) -> FuzzResult:
        if self._safe_mode_triggered:
            return FuzzResult.CRASH_REBOOT
        if self._payload_rejected:
            return FuzzResult.SUCCESS_HANDLED
        if self._heartbeat_count == 0:
            return FuzzResult.CRASH_SILENT
        return FuzzResult.SUCCESS_CLEAN

    def reset(self):
        self.logs.clear()
        self._payload_rejected = False
        self._safe_mode_triggered = False
        self._heartbeat_count = 0


async def _close_process_streams(process: asyncio.subprocess.Process) -> None:
    for name in ("stdout", "stderr", "stdin"):
        stream = getattr(process, name, None)
        if stream is None:
            continue

        close_fn = getattr(stream, "close", None)
        if callable(close_fn):
            with contextlib.suppress(Exception):
                close_fn()

        wait_closed_fn = getattr(stream, "wait_closed", None)
        if callable(wait_closed_fn):
            with contextlib.suppress(Exception):
                await wait_closed_fn()


async def monitor_qemu_process(process: asyncio.subprocess.Process, oracle: FuzzOracle, duration: float):
    if process.stdout is None:
        raise ValueError("monitor_qemu_process requires process.stdout=PIPE")

    loop = asyncio.get_running_loop()
    end_time = loop.time() + duration

    try:
        while loop.time() < end_time:
            try:
                line_bytes = await asyncio.wait_for(process.stdout.readline(), timeout=0.5)
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").strip()
                if line:
                    oracle.feed_log_line(line)
            except asyncio.TimeoutError:
                continue
    finally:
        await _close_process_streams(process)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(process.wait(), timeout=2.0)

async def test_oracle_standalone():
    """Simple test to verify the regex logic."""
    print("Testing Oracle Logic...")
    oracle = FuzzOracle()

    # Test 1: Graceful rejection.
    oracle.feed_log_line("Activity High: Sensor poll cycle started")
    oracle.feed_log_line("Activity High: Frame parsed: type 0x1, len 10")
    oracle.feed_log_line("Warning High: Frame bad sync: 0xFF 0xFF")
    assert oracle.evaluate() == FuzzResult.SUCCESS_HANDLED
    print("Test 1 (Rejection) passed.")
    oracle.reset()

    # Test 2: Autonomous recovery -> CONFIG (sensor health check triggers state change).
    oracle.feed_log_line("Activity High: Sensor poll cycle started")
    oracle.feed_log_line("Warning High: Failed to read Temperature sensor 0")
    oracle.feed_log_line("Activity High: OBC transitioned to CONFIG")
    assert oracle.evaluate() == FuzzResult.CRASH_REBOOT
    print("Test 2 (Config/Recovery) passed.")
    oracle.reset()

    # Test 3: Nominal heartbeat with no failure markers.
    oracle.feed_log_line("Activity High: Sensor poll cycle started")
    oracle.feed_log_line("Activity Low: Temp Sensor 0 value: 25.5")
    assert oracle.evaluate() == FuzzResult.SUCCESS_CLEAN
    print("Test 3 (Success) passed.")
    oracle.reset()

    # Test 4: No heartbeat at all => silent crash/freeze.
    oracle.feed_log_line("Activity Low: Temp Sensor 0 value: 25.5")
    assert oracle.evaluate() == FuzzResult.CRASH_SILENT
    print("Test 4 (Silent crash) passed.")


if __name__ == "__main__":
    asyncio.run(test_oracle_standalone())