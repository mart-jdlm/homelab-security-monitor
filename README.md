# homelab-security-monitor

Detection rules over the logs and state of a self-hosted Linux server. Written for a Debian
box that runs Docker services behind Tailscale, with **no dependency beyond Python 3.11+**.

It answers a question that uptime monitoring does not: *has something changed on this machine
that I did not do?* Failed and unexpected SSH logins, sudo abuse, port-scan patterns, unknown
devices joining the tailnet, containers started from images never seen before, new listening
ports, and edits to files such as `authorized_keys` all become alerts, with a timeline to
investigate them afterwards.

## Why

The server's security model is simple: every service listens on `127.0.0.1`, `tailscale serve`
publishes it to the private tailnet, nothing is exposed to the Internet. That model can be
checked continuously instead of trusted. Each rule below either verifies one of its assumptions
or detects an attacker's likely first moves once one of them fails.

## How it works

```
 journald ─┐
 docker   ─┤                      ┌────────┐   ┌─────────┐   ┌──────────────┐
 tailscale─┼─► collectors ─► Event ─► engine ├─► alerts    ├─► digest mail   │
 ss (ports)┤   (normalize)        │ rules  │   │ (SQLite)│   └──────────────┘
 files    ─┘                      └────────┘   └────┬────┘
                                                    └─► hsm timeline / hsm alerts
```

- **Collectors** read one source each and emit normalized events (`ssh.failed_login`,
  `docker.die`, `net.new_listener`, `fim.changed`, ...).
- **Stateful collectors** (docker, tailscale, ports, file integrity) treat their first run as
  a *baseline*: they record what is normal and emit nothing.
- **The engine** stores events in SQLite (idempotently: re-reading a log line never duplicates
  it), evaluates the rules, applies per-group thresholds over a time window, and rate-limits
  repeated alerts with a cooldown.
- **A collector that fails is itself an alert** (`HSM-900`), because a monitor that silently
  stops seeing is worse than no monitor.
- One digest mail per run, only above a configurable severity. Alerts that could not be
  delivered are retried on the next run.

## Rules

Rules are TOML, in `rules/default.toml`. Techniques from MITRE ATT&CK are attached where a rule
maps cleanly to one; configuration-drift rules intentionally have none.

| ID | Detects | Severity | ATT&CK |
| --- | --- | --- | --- |
| HSM-001 | 5 failed SSH logins in 10 min from one IP | high | T1110 |
| HSM-002 | SSH probing of non-existent users | medium | T1110.001 |
| HSM-003 | SSH login from outside the tailnet and LAN | critical | T1078, T1021.004 |
| HSM-004 / 005 | Repeated sudo failures / user not in sudoers | medium / high | T1548.003 |
| HSM-006 | 20 firewall blocks in 5 min from one source (scan pattern) | medium | T1046 |
| HSM-010..012 | Container exits with an error, is OOM-killed, becomes unhealthy | medium | |
| HSM-013 | `docker exec` into a container (timeline only) | low | T1609 |
| HSM-014 | Container created from a never-seen image repository | high | T1610, T1525 |
| HSM-020 | New device on the tailnet | high | T1133 |
| HSM-030 / 031 | New listener reachable beyond loopback / on loopback | high / low | |
| HSM-040 | `authorized_keys` or `sshd_config` changed | critical | T1098.004 |
| HSM-041 | Any other watched file changed | medium | |
| HSM-900 | A collector failed | medium | |

A rule looks like this:

```toml
[[rule]]
id = "HSM-001"
title = "SSH brute force"
severity = "high"
attack = ["T1110"]
kind = "ssh.failed_login"
threshold = 5            # events ...
window = "10m"           # ... within this window ...
group_by = ["src_ip"]    # ... counted separately per source IP
cooldown = "1h"          # do not re-alert the same group for an hour

[rule.match]             # optional field conditions; [rule.exclude] works the same way
user = ["root", "admin"]
```

Condition values: exact text, a list (any of), `re:<regex>`, `cidr:<networks>` and
`notcidr:<networks>`.

## Install

```bash
git clone <this repo> ~/server/homelab-security-monitor && cd ~/server/homelab-security-monitor
cp config.example.toml config.toml          # edit the fim paths for your machine
export PYTHONPATH=src HSM_CONFIG=$PWD/config.toml

python3 -m hsm baseline                     # record the current state as normal
python3 -m hsm run --no-notify              # dry run: collect and evaluate, send nothing
```

Schedule it with the systemd user units in `systemd/`:

```bash
mkdir -p ~/.config/systemd/user ~/.config/hsm
cp systemd/hsm.service systemd/hsm.timer ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now hsm.timer
```

**Permissions.** The user running it must be able to read the journal (`systemd-journal`
group) and, for the Docker collector, the Docker socket. Membership of the `docker` group is
root-equivalent on the host; if that is unacceptable, disable the collector in `config.toml`
(`[docker] enabled = false`). For UFW rules, enable firewall logging with `ufw logging low`.

**Mail.** SMTP settings come from the environment, never from the repository. Put them in
`~/.config/hsm/env` (mode 600):

```
HSM_SMTP_HOST=smtp.example.org
HSM_SMTP_PORT=587
HSM_SMTP_USER=...
HSM_SMTP_PASSWORD=...
HSM_MAIL_FROM=...
HSM_MAIL_TO=...
```

Without `HSM_SMTP_HOST`, the digest is printed to stdout (visible in `journalctl --user -u hsm`).

## Investigating

```bash
hsm timeline --since 24h                    # events and alerts, chronologically
hsm timeline --text 203.0.113.9             # everything involving one address
hsm timeline --kind 'ssh.*' --since 7d
hsm alerts --since 7d
```

After an intended change (new container image, edited compose file, new device), accept the
new state so it stops alerting: `hsm baseline --only fim` (or `docker`, `tailscale`, `ports`).

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The suite covers log parsing against realistic OpenSSH/sudo/UFW lines, every collector with
fake data sources, the engine (thresholds, windows spanning several runs, cooldown, replay
protection, per-group counting), the shipped rules end to end, and the failure path of a
broken collector.

## Limitations

- It detects and reports; it does not block anything. It reads logs after the fact, so an
  attacker with root can tamper with both the journal and this tool's database. Ship alerts
  off the machine (the mail does) and keep an external heartbeat for the machine itself.
- The tests use fake data sources. The collectors read real `journalctl`, `docker events`,
  `tailscale status --json` and `ss` output formats, but differences between versions are
  possible: report them as issues.
- File integrity only covers files the monitoring user can read.
- The rule format is Sigma-inspired but not Sigma-compatible.

## Roadmap

- Network inventory of the local network (new devices, open ports) as a new collector.
- Prioritization of container CVEs by real-world exploitation (CVSS + EPSS + CISA KEV).
- Sigma rule import.

## License

MIT
