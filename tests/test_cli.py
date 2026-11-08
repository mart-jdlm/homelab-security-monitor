"""End-to-end: collectors -> engine -> store -> digest, with fake data sources."""

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from hsm import cli
from hsm.collectors.ports import PortsCollector
from hsm.engine import Engine
from hsm.events import Event
from hsm.notify import filter_by_severity, format_digest
from hsm.rules import load_rules
from hsm.store import Store
from hsm.util import CollectorError

RULES = Path(__file__).resolve().parent.parent / "rules" / "default.toml"


class Boom:
    name = "boom"

    def collect(self, state, now):
        raise CollectorError("docker: permission denied")


class EndToEndTests(unittest.TestCase):
    def test_failing_collector_becomes_an_alert(self):
        events = cli.gather([Boom()], {}, 100.0)
        self.assertEqual(events[0].kind, "hsm.collector_error")
        alerts = Engine(Store(":memory:"), load_rules([RULES])).process(events)
        self.assertEqual([a.rule_id for a in alerts], ["HSM-900"])

    def test_brute_force_to_digest(self):
        store = Store(":memory:")
        engine = Engine(store, load_rules([RULES]))
        attack = [Event(t, "journald", "ssh.failed_login", {"src_ip": "203.0.113.9", "user": "root"},
                        "Failed password for root from 203.0.113.9") for t in range(6)]
        exec_ev = Event(7, "docker", "docker.exec", {"container": "db", "command": "sh"}, "exec in db: sh")
        engine.process(attack + [exec_ev])
        pending = store.unnotified_alerts()
        self.assertEqual({a.rule_id for a in pending}, {"HSM-001", "HSM-013"})
        to_send = filter_by_severity(pending, "medium")
        self.assertEqual([a.rule_id for a in to_send], ["HSM-001"])  # low-severity exec stays out of mail
        subject, body = format_digest(to_send, "serveur")
        self.assertIn("highest: high", subject)
        self.assertIn("T1110", body)
        self.assertIn("203.0.113.9", body)

    def test_cli_run_with_dry_run_and_timeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "config.toml"
            cfg.write_text(
                f'[general]\nstate_dir = "{tmp}/state"\nhost = "test"\n'
                f'[rules]\nfiles = ["{RULES}"]\n'
                '[journald]\nenabled = false\n[docker]\nenabled = false\n[tailscale]\nenabled = false\n'
                '[ports]\nenabled = false\n[fim]\nenabled = true\npaths = []\n'
            )
            self.assertEqual(cli.main(["--config", str(cfg), "run", "--no-notify"]), 0)
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(cli.main(["--config", str(cfg), "timeline", "--since", "1h"]), 0)
                self.assertEqual(cli.main(["--config", str(cfg), "alerts"]), 0)
            self.assertEqual(buf.getvalue(), "")  # nothing collected, nothing printed


if __name__ == "__main__":
    unittest.main()
