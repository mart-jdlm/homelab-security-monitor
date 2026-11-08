"""Listening-socket collector: flags new listeners, and whether they are reachable beyond loopback.

This backs the server's core design rule (every service on 127.0.0.1, published only by
`tailscale serve`): a new listener on another address breaks that rule.
"""

from __future__ import annotations

import ipaddress

from ..events import Event
from ..util import CollectorError, run_cmd


def parse_ss(output: str) -> dict[str, dict]:
    """Parse `ss -H -tuln` into {key: {proto, addr, port, exposed}}."""
    sockets: dict[str, dict] = {}
    for line in output.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        proto, local = cols[0], cols[4]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%", 1)[0]
        if not port.isdigit():
            continue
        try:
            loopback = ipaddress.ip_address(addr).is_loopback
        except ValueError:
            loopback = addr == "localhost"
        key = f"{proto}/{addr}:{port}"
        sockets[key] = {"proto": proto, "addr": addr, "port": port,
                        "exposed": "false" if loopback else "true"}
    return sockets


class PortsCollector:
    name = "ports"

    def __init__(self, cfg: dict, runner=run_cmd):
        self.runner = runner

    def collect(self, state: dict, now: float) -> list[Event]:
        current = parse_ss(self.runner(["ss", "-H", "-tuln"], 20))
        if not current:
            raise CollectorError("ss returned no listening sockets (unexpected)")
        if "listeners" not in state:  # first run: baseline
            state["listeners"] = current
            return []
        known: dict = state["listeners"]
        events = [
            Event(now, self.name, "net.new_listener", dict(info),
                  f"new listener {key} ({'reachable beyond loopback' if info['exposed'] == 'true' else 'loopback only'})")
            for key, info in current.items() if key not in known
        ]
        state["listeners"] = {**known, **current}  # keep history so a restart does not re-alert
        return events
