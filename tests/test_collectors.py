import json
import tempfile
import unittest
from pathlib import Path

from hsm.collectors.docker import DockerCollector, image_repo
from hsm.collectors.fim import FimCollector
from hsm.collectors.ports import PortsCollector, parse_ss
from hsm.collectors.tailscale import TailscaleCollector

SS_BASELINE = """\
tcp   LISTEN 0 4096     127.0.0.1:8080  0.0.0.0:*
tcp   LISTEN 0 128        0.0.0.0:22    0.0.0.0:*
tcp   LISTEN 0 128           [::]:22       [::]:*
udp   UNCONN 0 0     127.0.0.53%lo:53    0.0.0.0:*
"""


class PortsTests(unittest.TestCase):
    def test_parse(self):
        socks = parse_ss(SS_BASELINE)
        self.assertEqual(socks["tcp/127.0.0.1:8080"]["exposed"], "false")
        self.assertEqual(socks["tcp/0.0.0.0:22"]["exposed"], "true")
        self.assertEqual(socks["tcp/::0:22".replace("::0", "::")]["exposed"], "true")
        self.assertEqual(socks["udp/127.0.0.53:53"]["exposed"], "false")

    def test_first_run_is_baseline_then_new_listener_detected(self):
        outputs = [SS_BASELINE, SS_BASELINE + "tcp LISTEN 0 5 0.0.0.0:2375 0.0.0.0:*\n"]
        col = PortsCollector({}, runner=lambda cmd, t: outputs.pop(0))
        state: dict = {}
        self.assertEqual(col.collect(state, 1), [])
        events = col.collect(state, 2)
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0].kind, events[0].fields["port"], events[0].fields["exposed"]),
                         ("net.new_listener", "2375", "true"))


class TailscaleTests(unittest.TestCase):
    def status(self, *hosts):
        return json.dumps({"Peer": {f"nodekey:{h}": {"HostName": h, "DNSName": f"{h}.tail.ts.net.", "OS": "linux",
                                                      "TailscaleIPs": ["100.64.0.1"]} for h in hosts}})

    def test_new_and_removed_peer(self):
        outputs = [self.status("laptop"), self.status("laptop", "unknown-box"), self.status("unknown-box")]
        col = TailscaleCollector({}, runner=lambda cmd, t: outputs.pop(0))
        state: dict = {}
        self.assertEqual(col.collect(state, 1), [])
        new = col.collect(state, 2)
        self.assertEqual([(e.kind, e.fields["host"]) for e in new], [("tailscale.new_peer", "unknown-box")])
        gone = col.collect(state, 3)
        self.assertEqual([(e.kind, e.fields["host"]) for e in gone], [("tailscale.peer_removed", "laptop")])

    def test_no_peers_key(self):
        col = TailscaleCollector({}, runner=lambda cmd, t: json.dumps({"Self": {}, "Peer": None}))
        self.assertEqual(col.collect({}, 1), [])


class DockerTests(unittest.TestCase):
    def test_image_repo(self):
        self.assertEqual(image_repo("mariadb:11.8"), "mariadb")
        self.assertEqual(image_repo("cioraneanu/firefly-pico:dev@sha256:abc"), "cioraneanu/firefly-pico")
        self.assertEqual(image_repo("localhost:5000/team/app:1"), "localhost:5000/team/app")
        self.assertEqual(image_repo("firefly-iii-assistant-http"), "firefly-iii-assistant-http")

    def ev(self, action, name="web", image="nginx:1", ts=1_762_600_000, **attrs):
        return json.dumps({"Type": "container", "Action": action, "timeNano": ts * 10**9,
                           "Actor": {"ID": "abcdef1234567890", "Attributes": {"name": name, "image": image, **attrs}}})

    def test_events_and_new_image(self):
        calls = []

        def runner(cmd, timeout):
            calls.append(cmd)
            if cmd[1] == "images":
                return "mariadb\nnginx\n<none>\n"
            return "\n".join([
                self.ev("die", exitCode="137"),
                self.ev("exec_create: sh -c ls"),
                self.ev("health_status: unhealthy"),
                self.ev("health_status: healthy"),
                self.ev("create", image="nginx:2"),          # known repo, new tag: not suspicious
                self.ev("create", name="x", image="evil/miner:latest"),
                self.ev("start"),
            ])

        col = DockerCollector({}, runner=runner)
        state: dict = {}
        self.assertEqual(col.collect(state, 1_762_600_000), [])
        events = col.collect(state, 1_762_600_100)
        kinds = [e.kind for e in events]
        self.assertEqual(kinds, ["docker.die", "docker.exec", "docker.unhealthy", "docker.create",
                                 "docker.create", "docker.new_image"])
        self.assertEqual(events[0].fields["exit_code"], "137")
        self.assertEqual(events[1].fields["command"], "sh -c ls")
        self.assertEqual(events[-1].fields["repo"], "evil/miner")
        self.assertIn("evil/miner", state["repos"])
        events_cmd = calls[-1]
        self.assertIn("1762600000", events_cmd)  # resumes from the previous run


class FimTests(unittest.TestCase):
    def test_added_changed_removed_and_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            watched = Path(tmp) / "keys"
            watched.write_text("ssh-ed25519 AAA me")
            col = FimCollector({"paths": [str(Path(tmp) / "*")]})
            state: dict = {}
            self.assertEqual(col.collect(state, 1), [])          # baseline
            self.assertEqual(col.collect(state, 2), [])          # nothing changed
            watched.write_text("ssh-ed25519 AAA me\nssh-ed25519 BBB attacker")
            changed = col.collect(state, 3)
            self.assertEqual([(e.kind, e.fields["what"]) for e in changed], [("fim.changed", "content")])
            watched.chmod(0o666)
            self.assertEqual(col.collect(state, 4)[0].fields["what"], "permissions")
            extra = Path(tmp) / "new"
            extra.write_text("x")
            self.assertEqual([e.kind for e in col.collect(state, 5)], ["fim.added"])
            watched.unlink()
            self.assertEqual([e.kind for e in col.collect(state, 6)], ["fim.removed"])


if __name__ == "__main__":
    unittest.main()
