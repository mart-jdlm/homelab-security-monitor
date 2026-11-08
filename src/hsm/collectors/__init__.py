"""Collectors turn a data source into normalized Events.

Contract: `collect(state, now) -> list[Event]`. `state` is this collector's persistent dict.
Stateful collectors (docker, tailscale, ports, fim) treat an empty state as a first run:
they record the current situation as the baseline and emit nothing.
"""
