"""Small helpers shared by the collectors."""

from __future__ import annotations

import re
import subprocess


class CollectorError(RuntimeError):
    """A collector could not read its data source (missing tool, permissions, timeout...)."""


def run_cmd(cmd: list[str], timeout: int = 30) -> str:
    """Run a command and return stdout. Collectors receive this as an injectable `runner`."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise CollectorError(f"{cmd[0]}: command not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise CollectorError(f"{cmd[0]}: timed out after {timeout}s") from exc
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        raise CollectorError(f"{cmd[0]} exited {proc.returncode}: {err[-1] if err else 'no error output'}")
    return proc.stdout


_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_DURATION = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")


def parse_duration(text: str | int | float) -> int:
    """'90s', '10m', '2h', '7d' -> seconds. A bare number is taken as seconds."""
    if isinstance(text, (int, float)):
        return int(text)
    match = _DURATION.match(text)
    if not match:
        raise ValueError(f"invalid duration: {text!r} (use e.g. 30s, 10m, 2h, 7d)")
    return int(match.group(1)) * _UNITS[match.group(2)]
