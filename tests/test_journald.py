import json
import unittest

from hsm.collectors.journald import JournaldCollector, parse_message


class ParseMessageTests(unittest.TestCase):
    def test_failed_password_valid_user(self):
        kind, f = parse_message("sshd-session", "Failed password for martin from 203.0.113.9 port 51234 ssh2")
        self.assertEqual(kind, "ssh.failed_login")
        self.assertEqual((f["user"], f["src_ip"], f["invalid_user"]), ("martin", "203.0.113.9", "false"))

    def test_failed_password_invalid_user(self):
        kind, f = parse_message("sshd", "Failed password for invalid user admin from 198.51.100.7 port 22 ssh2")
        self.assertEqual(kind, "ssh.failed_login")
        self.assertEqual((f["user"], f["invalid_user"]), ("admin", "true"))

    def test_invalid_user(self):
        kind, f = parse_message("sshd-session", "Invalid user oracle from 198.51.100.7 port 4000")
        self.assertEqual((kind, f["user"], f["src_ip"]), ("ssh.invalid_user", "oracle", "198.51.100.7"))

    def test_accepted_publickey(self):
        kind, f = parse_message("sshd-session", "Accepted publickey for martin from 100.64.1.2 port 40022 ssh2: ED25519 SHA256:abc")
        self.assertEqual((kind, f["method"], f["user"], f["src_ip"]), ("ssh.accepted", "publickey", "martin", "100.64.1.2"))

    def test_sudo_variants(self):
        kind, f = parse_message("sudo", "pam_unix(sudo:auth): authentication failure; logname=martin uid=1000 euid=0 tty=/dev/pts/0 ruser=martin rhost=  user=martin")
        self.assertEqual((kind, f["user"]), ("sudo.auth_failure", "martin"))
        kind, f = parse_message("sudo", "    martin : TTY=pts/0 ; PWD=/home/martin ; USER=root ; COMMAND=/usr/bin/apt update")
        self.assertEqual((kind, f["target"], f["command"]), ("sudo.command", "root", "/usr/bin/apt update"))
        kind, f = parse_message("sudo", "    bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls")
        self.assertEqual((kind, f["user"]), ("sudo.not_in_sudoers", "bob"))

    def test_ufw_block(self):
        msg = "[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=203.0.113.50 DST=192.168.1.10 LEN=44 PROTO=TCP SPT=4444 DPT=2375 WINDOW=1024"
        kind, f = parse_message("kernel", msg)
        self.assertEqual((kind, f["src_ip"], f["proto"], f["dst_port"]), ("net.ufw_block", "203.0.113.50", "TCP", "2375"))

    def test_uninteresting_lines_are_ignored(self):
        self.assertIsNone(parse_message("sshd-session", "Connection closed by 1.2.3.4 port 22"))
        self.assertIsNone(parse_message("cron", "Failed password for x from 1.1.1.1 port 1"))


class CollectorTests(unittest.TestCase):
    def test_collect_builds_events_and_resumes_from_cursor(self):
        lines = [
            {"SYSLOG_IDENTIFIER": "sshd-session", "__REALTIME_TIMESTAMP": "1762600000000000", "__CURSOR": "s=1",
             "MESSAGE": "Failed password for root from 203.0.113.9 port 22 ssh2"},
            {"SYSLOG_IDENTIFIER": "sshd", "__REALTIME_TIMESTAMP": "1762600001000000", "__CURSOR": "s=2",
             "MESSAGE": list(b"Invalid user x from 203.0.113.9 port 22")},  # byte-array encoding
            {"SYSLOG_IDENTIFIER": "sudo", "__REALTIME_TIMESTAMP": "1762600002000000", "__CURSOR": "s=3",
             "MESSAGE": "noise"},
        ]
        seen = []

        def runner(cmd, timeout):
            seen.append(cmd)
            return "\n".join(json.dumps(x) for x in lines)

        col = JournaldCollector({"first_run_lookback": "2h"}, runner)
        state: dict = {}
        events = col.collect(state, 0)
        self.assertIn("--since=-2h", seen[0])
        self.assertFalse(any("cursor" in a for a in seen[0]))  # never combined with --since
        self.assertEqual(state["cursor"], "s=3")
        col.collect(state, 0)
        self.assertIn("--after-cursor=s=3", seen[1])
        self.assertNotIn("--since=-2h", seen[1])
        self.assertEqual([e.kind for e in events], ["ssh.failed_login", "ssh.invalid_user"])
        self.assertEqual(events[0].ts, 1762600000.0)


if __name__ == "__main__":
    unittest.main()
