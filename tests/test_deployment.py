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
        self.assertIn("proxy_pass http://127.0.0.1:18080", nginx)
        self.assertIn("proxy_set_header Upgrade $http_upgrade", nginx)
        self.assertIn("proxy_set_header Connection $citypop_connection_upgrade", nginx)


if __name__ == "__main__":
    unittest.main()
