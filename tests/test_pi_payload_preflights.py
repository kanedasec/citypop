import io
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from payloads.bluetooth import ble_mitm
from payloads.network import silent_bridge
from payloads.utilities import m5burner

_previous_numpy = sys.modules.get("numpy")
sys.modules["numpy"] = types.ModuleType("numpy")
try:
    from payloads.sdr import sdr_replay
finally:
    if _previous_numpy is None:
        sys.modules.pop("numpy", None)
    else:
        sys.modules["numpy"] = _previous_numpy


class PiPayloadPreflightTests(unittest.TestCase):
    def test_m5burner_uses_current_interpreter_module(self):
        command = m5burner._esptool_command("--port", "/dev/ttyUSB0", "chip-id")
        self.assertEqual(command[:3], [m5burner.sys.executable, "-m", "esptool"])
        self.assertNotIn("esptool.py", command)

    def test_bridge_command_failure_is_not_ignored(self):
        result = SimpleNamespace(returncode=1, stdout="", stderr="not supported")
        with patch.object(silent_bridge, "_run", return_value=result):
            with self.assertRaisesRegex(silent_bridge.BridgeError, "not supported"):
                silent_bridge._checked(["ip", "link", "set", "tailscale0", "master", "br0"])

    def test_unvalidated_sdr_replay_is_refused(self):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(sdr_replay._run_replay([]), 2)
        self.assertIn("Replay is disabled", output.getvalue())

    def test_ble_payload_no_longer_claims_transparent_proxy(self):
        self.assertIn("GATT Assessment", ble_mitm.__doc__ or "")


if __name__ == "__main__":
    unittest.main()
