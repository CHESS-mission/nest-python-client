"""Runtime configuration — all values derived from environment variables."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Union

# SP root: config.py -> seu/ -> scenarios/ -> nest-python-client/ -> SP/
_SP = Path(__file__).resolve().parent.parent.parent.parent

_elf_env = os.environ.get("CHESS_ELF_PATH", "")
ELF_PATH: Path = (Path(_elf_env) if _elf_env else
                  _SP / "CHESS-FS" / "build-fprime-automatic-arm-hf-linux"
                  / "bin" / "arm-hf-linux" / "CHESS_Pathfinder0FS")

SOCK_PATH: Path = Path(os.environ.get("FAULT_INJECT_SOCK", "/tmp/fi.sock"))
RESULTS:   Path = Path(os.environ.get("SEU_RESULTS",       "/tmp/seu_results.jsonl"))
SEU_DB:    Path = Path(os.environ.get("SEU_DB", str(_SP / "seu_history.db")))

# Docker mode: QEMU serial console is a TCP socket, not a local PTY file.
_docker_mode: bool = os.environ.get("NEST_DOCKER", "0") == "1"

_pty_env = os.environ.get("NEST_PTY_LOG", "")
PTY_LOG: Union[Path, tuple] = Path(_pty_env) if _pty_env else Path("/tmp/qemu-serial-pty")

_pty_env_b = os.environ.get("NEST_PTY_LOG_B", "")
PTY_LOG_B: Union[Path, tuple, None] = Path(_pty_env_b) if _pty_env_b else None

GDB_HOST: str  = os.environ.get("NEST_GDB_HOST", "localhost")
NEST_URL: str  = os.environ.get("NEST_URL", "ws://localhost:3000/ws")

_console_log_env = os.environ.get("NEST_CONSOLE_LOG", "")
CONSOLE_LOG:  Union[Path, None] = Path(_console_log_env) if _console_log_env else None
CONSOLE_HOST: str               = os.environ.get("NEST_CONSOLE_HOST", "localhost")
CONSOLE_PORT: int               = int(os.environ.get("NEST_CONSOLE_PORT", "3003"))
