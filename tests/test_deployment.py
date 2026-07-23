import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DeploymentTests(unittest.TestCase):
    def test_service_uses_single_threaded_gunicorn_worker_group(self):
        service = (ROOT / "city-pop.service").read_text(encoding="utf-8")
        self.assertIn("/gunicorn", service)
        self.assertIn("--workers 1", service)
        self.assertIn("--worker-class gthread", service)
        self.assertIn("--bind 127.0.0.1:18080", service)
        self.assertNotIn("app.py", service)

    def test_nginx_terminates_tls_and_proxies_websockets(self):
        nginx = (ROOT / "city-pop.nginx.conf").read_text(encoding="utf-8")
        self.assertIn("listen __CITYPOP_PORT__ ssl", nginx)
        self.assertNotIn("listen 80", nginx)
        self.assertIn("proxy_pass http://127.0.0.1:18080", nginx)
        self.assertIn("proxy_set_header Host $http_host", nginx)
        self.assertIn("proxy_set_header Upgrade $http_upgrade", nginx)
        self.assertIn("proxy_set_header Connection $citypop_connection_upgrade", nginx)
        self.assertIn("limit_req_zone", nginx)
        self.assertIn("Content-Security-Policy", nginx)
        self.assertIn("client_max_body_size 1m", nginx)

    def test_socketio_is_bundled_and_not_loaded_from_a_cdn(self):
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        asset = ROOT / "static" / "vendor" / "socket.io.min.js"
        self.assertIn('src="/vendor/socket.io.min.js"', html)
        self.assertNotIn("cdn.socket.io", html)
        self.assertGreater(asset.stat().st_size, 40_000)

    def test_installer_hardens_runtime_permissions_and_pairing(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('chmod 600 "$INSTALL_DIR/config.json"', installer)
        self.assertIn('chmod 700 "$INSTALL_DIR/state" "$INSTALL_DIR/loot"', installer)
        self.assertIn("ONE-TIME FIRST-ACCESS PAIRING CODE", installer)
        self.assertIn("SOCKETIO_SHA256=", installer)
        self.assertIn("--require-hashes", installer)


if __name__ == "__main__":
    unittest.main()
