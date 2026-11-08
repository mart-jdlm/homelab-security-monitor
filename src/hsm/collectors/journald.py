"""journald collector: SSH, sudo and kernel firewall (UFW) messages.

Reads incrementally: the journal cursor of the last entry seen is kept in the collector
state and passed back with `--after-cursor`, so each run only sees new entries.
The user running it needs read access to the journal (group `systemd-journal`).
"""

from __future__ import annotations

import json
import re

from ..events import Event
from ..util import CollectorError, run_cmd

_FAILED = re.compile(r"^Failed (\S+) for (invalid user )?(\S+) from (\S+) port (\d+)")
_INVALID = re.compile(r"^Invalid user (\S*) from (\S+) port (\d+)")
_ACCEPTED = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)")
_SUDO_CMD = re.compile(r"^\s*(\S+) : .*?USER=(\S+) ; COMMAND=(.*)$")
_SUDO_AUTH_FAIL = re.compile(r"authentication failure;.*?\buser=(\S+)")
_SUDO_NOT_ALLOWED = re.compile(r"^\s*(\S+) : user NOT in sudoers")
_UFW = re.compile(r"\[UFW BLOCK\].*?SRC=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?")

MATCHES = ["SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session",
           "SYSLOG_IDENTIFIER=sudo", "+", "_TRANSPORT=kernel"]


def parse_message(identifier: str, message: str) -> tuple[str, dict] | None:
    """Map one journal line to (kind, fields), or None if it is not interesting."""
    if identifier.startswith("sshd"):
        if m := _FAILED.match(message):
            return "ssh.failed_login", {"method": m[1], "user": m[3], "src_ip": m[4],
                                        "invalid_user": "true" if m[2] else "false"}
        if m := _INVALID.match(message):
            return "ssh.invalid_user", {"user": m[1], "src_ip": m[2]}
        if m := _ACCEPTED.match(message):
            return "ssh.accepted", {"method": m[1], "user": m[2], "src_ip": m[3]}
    elif identifier == "sudo":
        if m := _SUDO_NOT_ALLOWED.match(message):
            return "sudo.not_in_sudoers", {"user": m[1]}
        if m := _SUDO_AUTH_FAIL.search(message):
            return "sudo.auth_failure", {"user": m[1]}
        if m := _SUDO_CMD.match(message):
            return "sudo.command", {"user": m[1], "target": m[2], "command": m[3]}
    elif identifier == "kernel" and "[UFW BLOCK]" in message:
        if m := _UFW.search(message):
            return "net.ufw_block", {"src_ip": m[1], "proto": m[2], "dst_port": m[3] or ""}
    return None


def _text(value) -> str:
    if isinstance(value, list):  # journald encodes non-UTF8 messages as byte arrays
        return bytes(value).decode("utf-8", "replace")
    return str(value or "")


class JournaldCollector:
    name = "journald"

    def __init__(self, cfg: dict, runner=run_cmd):
        self.lookback = cfg.get("first_run_lookback", "1h")
        self.runner = runner

    def collect(self, state: dict, now: float) -> list[Event]:
        cmd = ["journalctl", "-o", "json", "--no-pager", "-q"]
        if state.get("cursor"):
            cmd.append(f"--after-cursor={state['cursor']}")
        else:  # first run: bounded lookback (journalctl forbids combining --since with a cursor)
            cmd.append(f"--since=-{self.lookback}")
        output = self.runner(cmd + MATCHES, 60)
        events: list[Event] = []
        for line in output.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CollectorError(f"unreadable journalctl output: {line[:80]!r}") from exc
            if entry.get("__CURSOR"):
                state["cursor"] = entry["__CURSOR"]
            message = _text(entry.get("MESSAGE"))
            parsed = parse_message(entry.get("SYSLOG_IDENTIFIER", ""), message)
            if parsed is None:
                continue
            kind, fields = parsed
            ts = int(entry.get("__REALTIME_TIMESTAMP", 0)) / 1e6
            events.append(Event(ts=ts, source=self.name, kind=kind, fields=fields, message=message))
        return events
