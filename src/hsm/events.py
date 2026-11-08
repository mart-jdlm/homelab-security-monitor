"""Core data types: a normalized Event produced by collectors, an Alert produced by rules."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Event:
    ts: float                      # unix seconds
    source: str                    # journald | docker | tailscale | fim | ports | hsm
    kind: str                      # normalized name, e.g. ssh.failed_login
    fields: dict = field(default_factory=dict)
    message: str = ""

    def digest(self) -> str:
        """Stable identity, so re-reading the same log line never creates a second event."""
        blob = f"{self.ts:.6f}|{self.source}|{self.kind}|{json.dumps(self.fields, sort_keys=True)}"
        return hashlib.sha1(blob.encode()).hexdigest()


@dataclass
class Alert:
    ts: float
    rule_id: str
    title: str
    severity: str
    attack: list[str]
    group_key: str
    count: int
    detail: list[str]
    id: int | None = None
