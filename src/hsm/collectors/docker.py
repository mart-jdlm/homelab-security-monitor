"""Docker collector: container lifecycle events since the last run.

Needs access to the Docker socket. Note that membership of the `docker` group is
root-equivalent on the host: see the README before granting it.
"""

from __future__ import annotations

import json

from ..events import Event
from ..util import CollectorError, run_cmd


def image_repo(image: str) -> str:
    """'mariadb:11.8' -> 'mariadb'; 'ghcr.io/x/y:dev@sha256:..' -> 'ghcr.io/x/y'."""
    image = image.split("@", 1)[0]
    head, _, tail = image.rpartition("/")
    return (head + "/" if head else "") + tail.split(":", 1)[0]


class DockerCollector:
    name = "docker"

    def __init__(self, cfg: dict, runner=run_cmd):
        self.runner = runner

    def _known_repos(self) -> list[str]:
        out = self.runner(["docker", "images", "--format", "{{.Repository}}"], 30)
        return sorted({line.strip() for line in out.splitlines() if line.strip() and line.strip() != "<none>"})

    def collect(self, state: dict, now: float) -> list[Event]:
        if "last" not in state:  # first run: baseline
            state["last"] = int(now)
            state["repos"] = self._known_repos()
            return []
        since, until = int(state["last"]), int(now)
        out = self.runner(["docker", "events", "--since", str(since), "--until", str(until),
                           "--filter", "type=container", "--format", "{{json .}}"], 60)
        known = set(state.get("repos", []))
        events: list[Event] = []
        for line in out.splitlines():
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CollectorError(f"unreadable docker events output: {line[:80]!r}") from exc
            events.extend(self._convert(raw, known))
        state["last"] = until
        state["repos"] = sorted(known)
        return events

    def _convert(self, raw: dict, known: set[str]) -> list[Event]:
        action_full = raw.get("Action") or raw.get("status", "")
        action, _, arg = action_full.partition(":")
        arg = arg.strip()
        attrs = (raw.get("Actor") or {}).get("Attributes", {})
        name = attrs.get("name", (raw.get("Actor") or {}).get("ID", "")[:12])
        image = attrs.get("image", raw.get("from", ""))
        ts = raw["timeNano"] / 1e9 if "timeNano" in raw else float(raw.get("time", 0))
        base = {"container": name, "image": image}

        def event(kind: str, extra: dict, msg: str) -> Event:
            return Event(ts=ts, source=self.name, kind=kind, fields={**base, **extra}, message=msg)

        if action == "die":
            code = attrs.get("exitCode", "")
            return [event("docker.die", {"exit_code": code}, f"container {name} exited with code {code}")]
        if action == "oom":
            return [event("docker.oom", {}, f"container {name} was OOM-killed")]
        if action == "health_status" and arg == "unhealthy":
            return [event("docker.unhealthy", {}, f"container {name} became unhealthy")]
        if action == "exec_create":
            return [event("docker.exec", {"command": arg}, f"exec in {name}: {arg}")]
        if action == "create":
            out = [event("docker.create", {}, f"container {name} created from {image}")]
            repo = image_repo(image) if image else ""
            if repo and repo not in known:
                known.add(repo)
                out.append(event("docker.new_image", {"repo": repo},
                                 f"container {name} uses a never-seen image: {image}"))
            return out
        return []
