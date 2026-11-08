"""Detection rules: loading from TOML and matching against events.

A rule selects events by `kind` and field conditions, optionally requires `threshold`
occurrences within `window` (per `group_by` values), and is rate-limited by `cooldown`.

Field condition values (in `match` / `exclude`):
    "text"            exact match
    ["a", "b"]        any of
    "re:<regex>"      regular expression search
    "cidr:<list>"     IP is inside one of the comma-separated networks
    "notcidr:<list>"  IP is outside all of the comma-separated networks
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .events import SEVERITIES, Event
from .util import parse_duration


def _in_networks(value: str, spec: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    for net in spec.split(","):
        net = net.strip()
        if net and ip in ipaddress.ip_network(net, strict=False):
            return True
    return False


def value_matches(pattern, actual) -> bool:
    if isinstance(pattern, list):
        return any(value_matches(p, actual) for p in pattern)
    text = str(actual)
    pat = str(pattern)
    if pat.startswith("re:"):
        return re.search(pat[3:], text) is not None
    if pat.startswith("cidr:"):
        return _in_networks(text, pat[5:])
    if pat.startswith("notcidr:"):
        return not _in_networks(text, pat[8:])
    return text == pat


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    kinds: list[str]
    match: dict = field(default_factory=dict)
    exclude: dict = field(default_factory=dict)
    threshold: int = 1
    window: int = 0
    group_by: list[str] = field(default_factory=list)
    cooldown: int = 3600
    attack: list[str] = field(default_factory=list)
    description: str = ""

    def matches(self, ev: Event) -> bool:
        if ev.kind not in self.kinds:
            return False
        for key, pattern in self.match.items():
            if key not in ev.fields or not value_matches(pattern, ev.fields[key]):
                return False
        for key, pattern in self.exclude.items():
            if key in ev.fields and value_matches(pattern, ev.fields[key]):
                return False
        return True

    def group_key(self, ev: Event) -> str:
        if not self.group_by:
            return "-"
        return "|".join(f"{k}={ev.fields.get(k, '')}" for k in self.group_by)


def load_rules(paths: list[Path]) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in paths:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
        for raw in data.get("rule", []):
            rule = _build(raw, path)
            if rule.id in seen:
                raise ValueError(f"{path}: duplicate rule id {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
    return rules


def _build(raw: dict, path: Path) -> Rule:
    try:
        severity = raw["severity"]
        if severity not in SEVERITIES:
            raise ValueError(f"unknown severity {severity!r}")
        kind = raw["kind"]
        threshold = int(raw.get("threshold", 1))
        window = parse_duration(raw["window"]) if "window" in raw else 0
        if threshold > 1 and window <= 0:
            raise ValueError("threshold > 1 requires a window")
        return Rule(
            id=raw["id"], title=raw["title"], severity=severity,
            kinds=[kind] if isinstance(kind, str) else list(kind),
            match=dict(raw.get("match", {})), exclude=dict(raw.get("exclude", {})),
            threshold=threshold, window=window, group_by=list(raw.get("group_by", [])),
            cooldown=parse_duration(raw.get("cooldown", "1h")),
            attack=list(raw.get("attack", [])), description=raw.get("description", ""),
        )
    except KeyError as exc:
        raise ValueError(f"{path}: rule {raw.get('id', '?')} is missing field {exc}") from exc
    except ValueError as exc:
        raise ValueError(f"{path}: rule {raw.get('id', '?')}: {exc}") from exc
