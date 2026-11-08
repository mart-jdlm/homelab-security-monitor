"""Command line: run (collect + detect + notify), baseline, timeline, alerts."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .collectors.docker import DockerCollector
from .collectors.fim import FimCollector
from .collectors.journald import JournaldCollector
from .collectors.ports import PortsCollector
from .collectors.tailscale import TailscaleCollector
from .config import find_config, load_config
from .engine import Engine
from .events import Alert, Event
from .notify import deliver, filter_by_severity, format_digest
from .rules import load_rules
from .store import Store
from .util import parse_duration

log = logging.getLogger("hsm")


def build_collectors(cfg: dict, state_dir: Path) -> list:
    collectors = []
    if cfg["journald"]["enabled"]:
        collectors.append(JournaldCollector(cfg["journald"]))
    if cfg["docker"]["enabled"]:
        collectors.append(DockerCollector(cfg["docker"]))
    if cfg["tailscale"]["enabled"]:
        collectors.append(TailscaleCollector(cfg["tailscale"]))
    if cfg["ports"]["enabled"]:
        collectors.append(PortsCollector(cfg["ports"]))
    if cfg["fim"]["enabled"] and cfg["fim"]["paths"]:
        collectors.append(FimCollector(cfg["fim"]))
    return collectors


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    os.replace(tmp, path)


def gather(collectors: list, state: dict, now: float) -> list[Event]:
    """Run every collector. A failing collector becomes an event: silent monitoring is worse than none."""
    events: list[Event] = []
    for collector in collectors:
        try:
            events.extend(collector.collect(state.setdefault(collector.name, {}), now))
        except Exception as exc:  # noqa: BLE001 - any failure must surface as an alert
            log.error("collector %s failed: %s", collector.name, exc)
            events.append(Event(now, "hsm", "hsm.collector_error", {"collector": collector.name},
                                f"collector {collector.name} failed: {exc}"))
    return events


def _setup(args) -> tuple[dict, Path, Store, list]:
    cfg = load_config(find_config(args.config))
    state_dir: Path = cfg["general"]["state_dir"]
    state_dir.mkdir(parents=True, exist_ok=True)
    rule_files = [(cfg["_base_dir"] / p) for p in cfg["rules"]["files"]]
    return cfg, state_dir, Store(state_dir / "hsm.db"), load_rules(rule_files)


def cmd_run(args) -> int:
    cfg, state_dir, store, rules = _setup(args)
    now = time.time()
    state_file = state_dir / "state.json"
    state = load_state(state_file)
    events = gather(build_collectors(cfg, state_dir), state, now)
    save_state(state_file, state)
    new_alerts = Engine(store, rules).process(events)
    log.info("%d event(s) collected, %d new alert(s)", len(events), len(new_alerts))

    pending = store.unnotified_alerts()
    to_send = filter_by_severity(pending, cfg["mail"]["min_severity"])
    if to_send and not args.no_notify:
        try:
            subject, body = format_digest(to_send, cfg["general"]["host"])
            deliver(subject, body)
        except Exception as exc:  # noqa: BLE001 - leave alerts unnotified, retry next run
            log.error("could not deliver alerts, will retry: %s", exc)
            return 1
    if not args.no_notify:
        store.mark_notified([a.id for a in pending])
    store.prune(now - cfg["general"]["retention_days"] * 86400)
    store.close()
    return 0


def cmd_baseline(args) -> int:
    """Forget the stored state of the selected collectors and re-record the current situation."""
    cfg, state_dir, store, _ = _setup(args)
    state_file = state_dir / "state.json"
    state = load_state(state_file)
    selected = set(args.only.split(",")) if args.only else {"docker", "tailscale", "ports", "fim"}
    for name in selected:
        state.pop(name, None)
    collectors = [c for c in build_collectors(cfg, state_dir) if c.name in selected]
    gather(collectors, state, time.time())
    save_state(state_file, state)
    print(f"baseline recorded for: {', '.join(c.name for c in collectors) or 'nothing'}")
    store.close()
    return 0


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def cmd_timeline(args) -> int:
    _, _, store, _ = _setup(args)
    since = time.time() - parse_duration(args.since)
    rows: list[tuple[float, str]] = []
    for ev in store.timeline(since, args.source, args.kind, args.text, args.limit):
        fields = " ".join(f"{k}={v}" for k, v in ev.fields.items() if v != "")
        rows.append((ev.ts, f"{_fmt_ts(ev.ts)}  {ev.source:<9} {ev.kind:<22} {fields}"))
    if not (args.source or args.kind or args.text):
        for a in store.alerts_since(since):
            rows.append((a.ts + 1e-6, f"{_fmt_ts(a.ts)}  !! {a.severity.upper():<8} {a.rule_id} {a.title} [{a.group_key}]"))
    for _, line in sorted(rows):
        print(line)
    store.close()
    return 0


def cmd_alerts(args) -> int:
    _, _, store, _ = _setup(args)
    for a in store.alerts_since(time.time() - parse_duration(args.since)):
        attack = f" ({','.join(a.attack)})" if a.attack else ""
        print(f"{_fmt_ts(a.ts)}  {a.severity.upper():<8} {a.rule_id} {a.title}{attack} [{a.group_key}] x{a.count}")
    store.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hsm", description="Homelab security monitor")
    parser.add_argument("--config", help="path to config.toml (default: $HSM_CONFIG or ./config.toml)")
    parser.add_argument("--version", action="version", version=f"hsm {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="collect events, evaluate rules, send alerts")
    run.add_argument("--no-notify", action="store_true", help="do not send or mark alerts (dry run)")
    run.set_defaults(func=cmd_run)

    base = sub.add_parser("baseline", help="record the current state as normal (use after intended changes)")
    base.add_argument("--only", help="comma-separated collectors: docker,tailscale,ports,fim")
    base.set_defaults(func=cmd_baseline)

    tl = sub.add_parser("timeline", help="chronological view of events and alerts")
    tl.add_argument("--since", default="24h")
    tl.add_argument("--source")
    tl.add_argument("--kind", help="event kind, * allowed (e.g. 'ssh.*')")
    tl.add_argument("--text", help="substring to look for, e.g. an IP address")
    tl.add_argument("--limit", type=int, default=500)
    tl.set_defaults(func=cmd_timeline)

    al = sub.add_parser("alerts", help="list recent alerts")
    al.add_argument("--since", default="7d")
    al.set_defaults(func=cmd_alerts)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    args = parser.parse_args(argv)
    return args.func(args)
