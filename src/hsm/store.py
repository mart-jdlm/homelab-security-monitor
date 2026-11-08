"""SQLite storage for events and alerts (also the source for the timeline)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .events import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY,
    digest TEXT UNIQUE NOT NULL,
    ts REAL NOT NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    fields TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ev_kind_ts ON events(kind, ts);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts(
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    attack TEXT NOT NULL,
    group_key TEXT NOT NULL,
    count INTEGER NOT NULL,
    detail TEXT NOT NULL,
    notified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS al_rule ON alerts(rule_id, group_key, ts);
"""


def _event(row) -> Event:
    return Event(ts=row[0], source=row[1], kind=row[2], fields=json.loads(row[3]), message=row[4])


def _alert(row) -> Alert:
    return Alert(id=row[0], ts=row[1], rule_id=row[2], title=row[3], severity=row[4],
                 attack=json.loads(row[5]), group_key=row[6], count=row[7], detail=json.loads(row[8]))


class Store:
    def __init__(self, path: str | Path):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.commit()
        self.db.close()

    # events -----------------------------------------------------------------
    def add_event(self, ev: Event) -> bool:
        """Insert an event. Returns False if it was already stored."""
        cur = self.db.execute(
            "INSERT OR IGNORE INTO events(digest, ts, source, kind, fields, message) VALUES (?,?,?,?,?,?)",
            (ev.digest(), ev.ts, ev.source, ev.kind, json.dumps(ev.fields, sort_keys=True), ev.message),
        )
        return cur.rowcount == 1

    def events_in_window(self, kinds: list[str], start: float, end: float) -> list[Event]:
        marks = ",".join("?" for _ in kinds)
        rows = self.db.execute(
            f"SELECT ts, source, kind, fields, message FROM events "
            f"WHERE kind IN ({marks}) AND ts >= ? AND ts <= ? ORDER BY ts",
            (*kinds, start, end),
        ).fetchall()
        return [_event(r) for r in rows]

    def timeline(self, since: float, source: str | None = None, kind: str | None = None,
                 text: str | None = None, limit: int = 500) -> list[Event]:
        sql = "SELECT ts, source, kind, fields, message FROM events WHERE ts >= ?"
        args: list = [since]
        if source:
            sql += " AND source = ?"
            args.append(source)
        if kind:
            sql += " AND kind LIKE ?"
            args.append(kind.replace("*", "%"))
        if text:
            sql += " AND (fields LIKE ? OR message LIKE ?)"
            args += [f"%{text}%", f"%{text}%"]
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        return [_event(r) for r in reversed(self.db.execute(sql, args).fetchall())]

    # alerts -----------------------------------------------------------------
    def in_cooldown(self, rule_id: str, group_key: str, ts: float, cooldown: int) -> bool:
        row = self.db.execute(
            "SELECT 1 FROM alerts WHERE rule_id = ? AND group_key = ? AND ts >= ? LIMIT 1",
            (rule_id, group_key, ts - cooldown),
        ).fetchone()
        return row is not None

    def add_alert(self, alert: Alert) -> None:
        cur = self.db.execute(
            "INSERT INTO alerts(ts, rule_id, title, severity, attack, group_key, count, detail) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (alert.ts, alert.rule_id, alert.title, alert.severity, json.dumps(alert.attack),
             alert.group_key, alert.count, json.dumps(alert.detail)),
        )
        alert.id = cur.lastrowid

    def unnotified_alerts(self) -> list[Alert]:
        rows = self.db.execute(
            "SELECT id, ts, rule_id, title, severity, attack, group_key, count, detail "
            "FROM alerts WHERE notified = 0 ORDER BY ts"
        ).fetchall()
        return [_alert(r) for r in rows]

    def mark_notified(self, ids: list[int]) -> None:
        self.db.executemany("UPDATE alerts SET notified = 1 WHERE id = ?", [(i,) for i in ids])

    def alerts_since(self, since: float) -> list[Alert]:
        rows = self.db.execute(
            "SELECT id, ts, rule_id, title, severity, attack, group_key, count, detail "
            "FROM alerts WHERE ts >= ? ORDER BY ts", (since,)
        ).fetchall()
        return [_alert(r) for r in rows]

    # housekeeping -----------------------------------------------------------
    def prune(self, older_than: float) -> None:
        self.db.execute("DELETE FROM events WHERE ts < ?", (older_than,))
        self.db.execute("DELETE FROM alerts WHERE ts < ? AND notified = 1", (older_than,))

    def commit(self) -> None:
        self.db.commit()
