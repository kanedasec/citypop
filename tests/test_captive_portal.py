import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.request import urlopen

from payloads.wifi.captive_portal import (
    GATEWAY, acquire_portal_lock, captive_template_handler, prepare_image_site,
    release_portal_lock, resolve_uploaded_image, write_configs,
)


class CaptivePortalTests(unittest.TestCase):
    def test_portal_lock_rejects_an_overlapping_instance(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "portal.lock"
            first = acquire_portal_lock(path)
            try:
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    acquire_portal_lock(path)
            finally:
                release_portal_lock(first)

            second = acquire_portal_lock(path)
            release_portal_lock(second)

    def test_dnsmasq_is_scoped_away_from_pitail_services(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hostapd_path, config_path = write_configs(root, "wlan-test0", "FreeWiFi", 6)
            config = config_path.read_text(encoding="utf-8")
            hostapd = hostapd_path.read_text(encoding="utf-8")
        self.assertIn("interface=wlan-test0\n", config)
        self.assertIn("except-interface=lo\n", config)
        self.assertIn(f"listen-address={GATEWAY}\n", config)
        self.assertIn("bind-dynamic\n", config)
        self.assertNotIn("bind-interfaces\n", config)
        self.assertIn(f"dhcp-leasefile={root / 'dnsmasq.leases'}\n", config)
        self.assertIn("wmm_enabled=1\n", hostapd)
        self.assertIn("ieee80211n=1\n", hostapd)

    def test_uploaded_image_token_is_contained_and_page_is_responsive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token = "a" * 32 + ".png"
            image = root / token
            image.write_bytes(b"\x89PNG\r\n\x1a\nimage")
            self.assertEqual(resolve_uploaded_image(token, root), image)
            with self.assertRaises(ValueError):
                resolve_uploaded_image("../outside.png", root)

            site = root / "site"
            site.mkdir()
            prepare_image_site(image, site)
            page = (site / "index.html").read_text(encoding="utf-8")
            self.assertIn('src="/portal-image.png"', page)
            self.assertIn("max-width: 100%", page)
            self.assertIn("max-height:", page)

    def test_connectivity_probe_receives_portal_page(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "index.html").write_text("portal notice", encoding="utf-8")
            event_log = root / "events.jsonl"
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                captive_template_handler(root, event_log, []),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                response = urlopen(
                    f"http://127.0.0.1:{server.server_port}/generate_204",
                    timeout=3,
                )
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b"portal notice")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

if __name__ == "__main__":
    unittest.main()
