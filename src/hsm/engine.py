"""Rule engine: stores new events, evaluates rules, returns new alerts."""

from __future__ import annotations

from .events import Alert, Event
from .rules import Rule
from .store import Store


class Engine:
    def __init__(self, store: Store, rules: list[Rule]):
        self.store = store
        self.rules = rules

    def process(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        for ev in sorted(events, key=lambda e: e.ts):
            if not self.store.add_event(ev):
                continue  # already seen on a previous run
            for rule in self.rules:
                if not rule.matches(ev):
                    continue
                group = rule.group_key(ev)
                hits = [ev]
                if rule.threshold > 1:
                    hits = self._window_hits(rule, ev, group)
                    if len(hits) < rule.threshold:
                        continue
                if self.store.in_cooldown(rule.id, group, ev.ts, rule.cooldown):
                    continue
                alert = Alert(
                    ts=ev.ts, rule_id=rule.id, title=rule.title, severity=rule.severity,
                    attack=rule.attack, group_key=group, count=len(hits),
                    detail=[h.message for h in hits[-5:]],
                )
                self.store.add_alert(alert)
                alerts.append(alert)
        self.store.commit()
        return alerts

    def _window_hits(self, rule: Rule, ev: Event, group: str) -> list[Event]:
        candidates = self.store.events_in_window(rule.kinds, ev.ts - rule.window, ev.ts)
        return [c for c in candidates if rule.matches(c) and rule.group_key(c) == group]
