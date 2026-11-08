"""File integrity monitoring for a configurable list of paths (globs allowed).

Records sha256, mode and owner. Files the user cannot read are reported once in the
logs and skipped: run hsm as a user that can read what you want to watch.
"""

from __future__ import annotations

import glob
import hashlib
import logging
import os
import stat
from pathlib import Path

from ..events import Event

log = logging.getLogger("hsm.fim")


def snapshot(patterns: list[str]) -> dict[str, dict]:
    files: dict[str, dict] = {}
    for pattern in patterns:
        for path in sorted(glob.glob(os.path.expanduser(pattern), recursive=True)):
            p = Path(path)
            if not p.is_file():
                continue
            try:
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
                st = p.stat()
            except PermissionError:
                log.warning("cannot read %s (permission denied), skipping", path)
                continue
            files[str(p)] = {"sha256": digest, "mode": stat.filemode(st.st_mode), "uid": st.st_uid}
    return files


class FimCollector:
    name = "fim"

    def __init__(self, cfg: dict):
        self.patterns: list[str] = cfg.get("paths", [])

    def collect(self, state: dict, now: float) -> list[Event]:
        current = snapshot(self.patterns)
        if "files" not in state:  # first run: baseline
            state["files"] = current
            return []
        known: dict = state["files"]
        events: list[Event] = []

        def ev(kind: str, path: str, extra: dict, msg: str) -> None:
            events.append(Event(now, self.name, kind, {"path": path, **extra}, msg))

        for path, new in current.items():
            old = known.get(path)
            if old is None:
                ev("fim.added", path, {"sha256": new["sha256"][:12]}, f"new watched file: {path}")
                continue
            what = [label for key, label in (("sha256", "content"), ("mode", "permissions"), ("uid", "owner"))
                    if old[key] != new[key]]
            if what:
                ev("fim.changed", path, {"what": ",".join(what), "old": old["sha256"][:12], "new": new["sha256"][:12]},
                   f"{path} changed ({', '.join(what)})")
        for path in known:
            if path not in current and not Path(path).exists():
                ev("fim.removed", path, {}, f"watched file removed: {path}")
        state["files"] = current
        return events
