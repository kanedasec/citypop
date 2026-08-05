import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from payloads.utilities import LanTest


class LanSpeedTestTests(unittest.TestCase):
    @patch.object(LanTest.subprocess, "run")
    def test_route_lookup_returns_interface_and_source(self, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stdout="192.168.18.20 dev wlan0 src 192.168.18.4 uid 0\n",
            stderr="",
        )
        self.assertEqual(
            LanTest.route_to("192.168.18.20"),
            ("wlan0", "192.168.18.4"),
        )
        run.assert_called_once_with(
            ["ip", "-o", "-4", "route", "get", "192.168.18.20"],
            capture_output=True, text=True, timeout=5,
        )

    @patch.object(LanTest.subprocess, "run")
    def test_ipv6_route_lookup_uses_ipv6_route_table(self, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stdout="2001:db8::20 dev wlan0 src 2001:db8::4 metric 600\n",
            stderr="",
        )
        self.assertEqual(
            LanTest.route_to("2001:db8::20", LanTest.socket.AF_INET6),
            ("wlan0", "2001:db8::4"),
        )
        self.assertEqual(run.call_args.args[0][2], "-6")

    @patch.object(LanTest.subprocess, "run")
    def test_iperf_json_error_is_reported_concisely(self, run):
        run.return_value = SimpleNamespace(
            returncode=1,
            stdout=json.dumps({"error": "unable to connect to server"}),
            stderr="",
        )
        with self.assertRaisesRegex(RuntimeError, "unable to connect to server"):
            LanTest.measure("192.168.18.20", 5201, 5, True)


if __name__ == "__main__":
    unittest.main()
