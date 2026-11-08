"""Alert delivery: one digest mail per run. SMTP settings come from the environment, never from the repo.

    HSM_SMTP_HOST, HSM_SMTP_PORT (default 587), HSM_SMTP_USER, HSM_SMTP_PASSWORD,
    HSM_MAIL_FROM, HSM_MAIL_TO, HSM_SMTP_SSL=1 for implicit TLS (port 465).
Without HSM_SMTP_HOST the digest is printed to stdout instead (handy for journald or a dry run).
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage

from .events import SEVERITIES, Alert


def format_digest(alerts: list[Alert], host: str) -> tuple[str, str]:
    worst = max(alerts, key=lambda a: SEVERITIES[a.severity]).severity
    subject = f"[hsm:{host}] {len(alerts)} alert(s), highest: {worst}"
    lines: list[str] = []
    for a in sorted(alerts, key=lambda a: (-SEVERITIES[a.severity], a.ts)):
        attack = f" ({', '.join(a.attack)})" if a.attack else ""
        group = "" if a.group_key == "-" else f"  [{a.group_key}]"
        lines.append(f"[{a.severity.upper()}] {a.rule_id} {a.title}{attack}{group}")
        if a.count > 1:
            lines.append(f"    {a.count} events in the rule window")
        lines.extend(f"    {d}" for d in a.detail)
        lines.append("")
    lines.append("Investigate: hsm timeline --since 24h")
    return subject, "\n".join(lines)


def filter_by_severity(alerts: list[Alert], minimum: str) -> list[Alert]:
    return [a for a in alerts if SEVERITIES[a.severity] >= SEVERITIES[minimum]]


def smtp_configured() -> bool:
    return bool(os.environ.get("HSM_SMTP_HOST"))


def deliver(subject: str, body: str) -> str:
    """Send or print the digest. Returns 'mail' or 'stdout'. Raises on SMTP failure."""
    if not smtp_configured():
        print(subject)
        print()
        print(body)
        return "stdout"
    env = os.environ
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = env.get("HSM_MAIL_FROM", env.get("HSM_SMTP_USER", "hsm@localhost"))
    msg["To"] = env["HSM_MAIL_TO"]
    msg.set_content(body)
    host, port = env["HSM_SMTP_HOST"], int(env.get("HSM_SMTP_PORT", "587"))
    context = ssl.create_default_context()
    if env.get("HSM_SMTP_SSL") == "1" or port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=30, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=30)
    with server:
        if not isinstance(server, smtplib.SMTP_SSL):
            server.starttls(context=context)
        if env.get("HSM_SMTP_USER"):
            server.login(env["HSM_SMTP_USER"], env.get("HSM_SMTP_PASSWORD", ""))
        server.send_message(msg)
    return "mail"
