import unittest
from unittest.mock import call, patch

from payloads import _ufw


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TemporaryUfwTests(unittest.TestCase):
    @patch.object(_ufw, "_run")
    def test_generic_outbound_rule_uses_complete_ufw_syntax(self, run):
        run.return_value = Result()
        rules = _ufw.TemporaryUfwRules("payload-egress")
        rules.add("allow", "out", "to", "any")
        run.assert_called_once_with(
            "insert", "1", "allow", "out", "to", "any",
            "comment", rules.marker,
        )

    @patch.object(_ufw.subprocess, "run")
    def test_connected_context_matches_address_without_hardcoding_network(self, run):
        run.return_value = Result(stdout=(
            "2: eth0 inet 192.168.18.4/24 brd 192.168.18.255 scope global eth0\n"
            "3: tailscale0 inet 100.64.0.2/32 scope global tailscale0\n"
        ))
        self.assertEqual(
            _ufw.connected_context("192.168.18.4"),
            ("eth0", "192.168.18.0/24"),
        )

    @patch.object(_ufw.uuid, "uuid4")
    @patch.object(_ufw, "_run")
    def test_lan_service_rules_are_inserted_first_for_both_directions(
        self, run, uuid4,
    ):
        uuid4.return_value.hex = "1234567890abcdef"
        run.return_value = Result()
        rules = _ufw.TemporaryUfwRules("honeypot")
        with patch.object(
            _ufw, "connected_context", return_value=("eth0", "192.168.18.0/24"),
        ):
            rules.allow_lan_service("192.168.18.4", 8081)

        self.assertEqual(rules.marker, "city-pop-honeypot-1234567890")
        self.assertEqual(
            run.call_args_list,
            [
                call(
                    "insert", "1", "allow", "in", "on", "eth0", "proto", "tcp",
                    "from", "192.168.18.0/24", "to", "any", "port", "8081",
                    "comment", rules.marker,
                ),
                call(
                    "insert", "1", "allow", "out", "on", "eth0", "proto", "tcp",
                    "from", "any", "port", "8081", "to", "192.168.18.0/24",
                    "comment", rules.marker,
                ),
            ],
        )

    @patch.object(_ufw, "_run")
    def test_cleanup_removes_only_rules_with_its_marker(self, run):
        rules = _ufw.TemporaryUfwRules("test")
        run.side_effect = [
            Result(stdout=(
                "[ 1] 22/tcp ALLOW IN Anywhere # unrelated\n"
                f"[ 2] 8081/tcp ALLOW IN Anywhere # {rules.marker}\n"
                f"[ 3] 8081/tcp (v6) ALLOW IN Anywhere (v6) # {rules.marker}\n"
            )),
            Result(),
            Result(),
            Result(stdout="[ 1] 22/tcp ALLOW IN Anywhere # unrelated\n"),
        ]

        rules.close()

        self.assertEqual(
            run.call_args_list[1:3],
            [call("--force", "delete", "3"), call("--force", "delete", "2")],
        )

    @patch.object(_ufw, "_run")
    def test_forwarding_rule_is_run_scoped_and_interface_specific(self, run):
        run.return_value = Result()
        rules = _ufw.TemporaryUfwRules("usb")
        rules.allow_forwarding("usb0", "wlan0", "10.0.88.1/24")
        run.assert_called_once_with(
            "route", "insert", "1", "allow", "in", "on", "usb0",
            "out", "on", "wlan0", "from", "10.0.88.0/24",
            "comment", rules.marker,
        )

    @patch.object(_ufw, "_run")
    def test_client_service_is_scoped_to_route_peer_and_port(self, run):
        run.return_value = Result()
        rules = _ufw.TemporaryUfwRules("lan-speed-test")
        rules.allow_client_service(
            "wlan0", "192.168.18.4", "192.168.18.20", 5201,
        )
        self.assertEqual(run.call_args_list, [
            call(
                "insert", "1", "allow", "out", "on", "wlan0", "proto", "tcp",
                "from", "192.168.18.4", "to", "192.168.18.20", "port", "5201",
                "comment", rules.marker,
            ),
            call(
                "insert", "1", "allow", "in", "on", "wlan0", "proto", "tcp",
                "from", "192.168.18.20", "port", "5201", "to", "192.168.18.4",
                "comment", rules.marker,
            ),
        ])


if __name__ == "__main__":
    unittest.main()
