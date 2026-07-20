import tempfile
import unittest
from pathlib import Path

from payloads.wifi.captive_portal import GATEWAY, write_configs


class CaptivePortalTests(unittest.TestCase):
    def test_dnsmasq_is_scoped_away_from_pitail_services(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, config_path = write_configs(root, "wlan-test0", "FreeWiFi", 6)
            config = config_path.read_text(encoding="utf-8")
        self.assertIn("interface=wlan-test0\n", config)
        self.assertIn("except-interface=lo\n", config)
        self.assertIn(f"listen-address={GATEWAY}\n", config)
        self.assertIn("bind-dynamic\n", config)
        self.assertNotIn("bind-interfaces\n", config)
        self.assertIn(f"dhcp-leasefile={root / 'dnsmasq.leases'}\n", config)


if __name__ == "__main__":
    unittest.main()
