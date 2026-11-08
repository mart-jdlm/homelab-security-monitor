import unittest
from pathlib import Path

from hsm.engine import Engine
from hsm.events import Event
from hsm.rules import Rule, load_rules, value_matches
from hsm.store import Store

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "default.toml"


def failed(ts, ip="203.0.113.9", user="root"):
    return Event(ts, "journald", "ssh.failed_login", {"src_ip": ip, "user": user},
                 f"Failed password for {user} from {ip}")


class MatcherTests(unittest.TestCase):
    def test_value_matching_modes(self):
        self.assertTrue(value_matches("a", "a"))
        self.assertTrue(value_matches(["a", "b"], "b"))
        self.assertTrue(value_matches("re:^1\\d$", "12"))
        self.assertTrue(value_matches("cidr:10.0.0.0/8", "10.1.2.3"))
        self.assertFalse(value_matches("cidr:10.0.0.0/8", "11.1.2.3"))
        self.assertTrue(value_matches("notcidr:10.0.0.0/8,100.64.0.0/10", "8.8.8.8"))
        self.assertFalse(value_matches("notcidr:10.0.0.0/8,100.64.0.0/10", "100.100.1.1"))
        self.assertFalse(value_matches("cidr:10.0.0.0/8", "not-an-ip"))

    def test_shipped_rules_load_and_are_consistent(self):
        rules = load_rules([RULES_FILE])
        ids = [r.id for r in rules]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(rules), 15)
        for r in rules:
            self.assertTrue(r.title and r.kinds)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def engine(self, **kw):
        base = dict(id="T-1", title="brute force", severity="high", kinds=["ssh.failed_login"],
                    threshold=3, window=600, group_by=["src_ip"], cooldown=3600)
        base.update(kw)
        return Engine(self.store, [Rule(**base)])

    def test_threshold_fires_once_then_cooldown(self):
        eng = self.engine()
        alerts = eng.process([failed(t) for t in (0, 10, 20, 30, 40)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 3)
        self.assertEqual(alerts[0].group_key, "src_ip=203.0.113.9")

    def test_below_threshold_or_spread_over_time_does_not_fire(self):
        eng = self.engine()
        self.assertEqual(eng.process([failed(0), failed(10)]), [])
        self.assertEqual(eng.process([failed(5000), failed(10000)]), [])  # outside the window

    def test_counts_are_per_group(self):
        eng = self.engine()
        events = [failed(t, ip=f"203.0.113.{t}") for t in range(6)]
        self.assertEqual(eng.process(events), [])

    def test_window_spans_runs(self):
        eng = self.engine()
        self.assertEqual(eng.process([failed(0), failed(10)]), [])
        self.assertEqual(len(eng.process([failed(20)])), 1)  # third hit arrives in a later run

    def test_replayed_events_are_ignored(self):
        eng = self.engine(threshold=1, cooldown=0)
        self.assertEqual(len(eng.process([failed(0)])), 1)
        self.assertEqual(eng.process([failed(0)]), [])  # same line read twice

    def test_exclude_and_match(self):
        eng = self.engine(threshold=1, cooldown=0, exclude={"user": "backup"}, match={"src_ip": "cidr:203.0.113.0/24"})
        self.assertEqual(eng.process([failed(0, user="backup")]), [])
        self.assertEqual(eng.process([failed(1, ip="198.51.100.1")]), [])
        self.assertEqual(len(eng.process([failed(2)])), 1)

    def test_shipped_ssh_rules_end_to_end(self):
        eng = Engine(self.store, load_rules([RULES_FILE]))
        lan = Event(0, "journald", "ssh.accepted", {"src_ip": "192.168.1.20", "user": "martin"}, "ok")
        tailnet = Event(1, "journald", "ssh.accepted", {"src_ip": "100.101.102.103", "user": "martin"}, "ok")
        outside = Event(2, "journald", "ssh.accepted", {"src_ip": "203.0.113.77", "user": "martin"}, "bad")
        alerts = eng.process([lan, tailnet, outside])
        self.assertEqual([a.rule_id for a in alerts], ["HSM-003"])
        self.assertEqual(alerts[0].severity, "critical")

    def test_shipped_docker_die_ignores_clean_exits(self):
        eng = Engine(self.store, load_rules([RULES_FILE]))

        def die(ts, code):
            return Event(ts, "docker", "docker.die", {"container": "c", "exit_code": code}, "x")

        self.assertEqual(eng.process([die(0, "0"), die(1, "143")]), [])
        self.assertEqual([a.rule_id for a in eng.process([die(2, "137")])], ["HSM-010"])

    def test_fim_rules_split_by_path(self):
        eng = Engine(self.store, load_rules([RULES_FILE]))
        crit = Event(0, "fim", "fim.changed", {"path": "/home/m/.ssh/authorized_keys"}, "keys")
        other = Event(1, "fim", "fim.changed", {"path": "/home/m/server/x/docker-compose.yml"}, "compose")
        self.assertEqual([a.rule_id for a in eng.process([crit, other])], ["HSM-040", "HSM-041"])


if __name__ == "__main__":
    unittest.main()
