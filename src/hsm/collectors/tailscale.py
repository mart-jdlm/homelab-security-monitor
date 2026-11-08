"""Tailscale collector: detects devices that join or leave the tailnet.

Diffs `tailscale status --json` against the peers seen on previous runs.
"""

from __future__ import annotations

import json

from ..events import Event
from ..util import CollectorError, run_cmd


class TailscaleCollector:
    name = "tailscale"

    def __init__(self, cfg: dict, runner=run_cmd):
        self.runner = runner

    def collect(self, state: dict, now: float) -> list[Event]:
        try:
            data = json.loads(self.runner(["tailscale", "status", "--json"], 20))
        except json.JSONDecodeError as exc:
            raise CollectorError("tailscale status --json did not return JSON") from exc
        current = {}
        for key, peer in (data.get("Peer") or {}).items():
            current[key] = {
                "host": peer.get("HostName", "?"),
                "dns": (peer.get("DNSName") or "").rstrip("."),
                "os": peer.get("OS", ""),
                "ips": ",".join(peer.get("TailscaleIPs") or []),
            }
        if "peers" not in state:  # first run: baseline
            state["peers"] = current
            return []
        known: dict = state["peers"]
        events: list[Event] = []
        for key, info in current.items():
            if key not in known:
                events.append(Event(now, self.name, "tailscale.new_peer", dict(info),
                                    f"new device on the tailnet: {info['host']} ({info['os']}) {info['ips']}"))
        for key, info in known.items():
            if key not in current:
                events.append(Event(now, self.name, "tailscale.peer_removed", dict(info),
                                    f"device left the tailnet: {info['host']}"))
        state["peers"] = current
        return events
