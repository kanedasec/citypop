import unittest
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import patch

import app as citypop
from auth_store import AuthStore
from engagement_store import EngagementStore


class WebApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auth_dir = tempfile.TemporaryDirectory()
        citypop.auth_store = AuthStore(Path(cls.auth_dir.name) / "auth.json")
        citypop.auth_store.setup("test_admin", "correct horse battery staple")
        cls.client = citypop.app.test_client()
        response = cls.client.post(
            "/api/login",
            json={"username": "test_admin", "password": "correct horse battery staple"},
        )
        assert response.status_code == 200
        cls.headers = {}

    @classmethod
    def tearDownClass(cls):
        cls.auth_dir.cleanup()

    def test_protected_api_rejects_anonymous_request(self):
        self.assertEqual(citypop.app.test_client().get("/api/payloads").status_code, 401)

    def test_account_password_can_be_changed_without_storing_plaintext(self):
        response = self.client.put("/api/account", json={
            "username": "test_admin",
            "current_password": "correct horse battery staple",
            "new_password": "another long test passphrase",
            "new_password_confirm": "another long test passphrase",
        })
        self.assertEqual(response.status_code, 200)
        stored = (Path(self.auth_dir.name) / "auth.json").read_text()
        self.assertNotIn("another long test passphrase", stored)
        # Restore the shared fixture for tests that may run after this one.
        response = self.client.put("/api/account", json={
            "username": "test_admin",
            "current_password": "another long test passphrase",
            "new_password": "correct horse battery staple",
            "new_password_confirm": "correct horse battery staple",
        })
        self.assertEqual(response.status_code, 200)

    def test_payload_catalog_is_available_when_authenticated(self):
        response = self.client.get("/api/payloads", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        payloads = response.get_json()["payloads"]
        self.assertTrue(payloads)
        self.assertTrue(all(payload["web"] for payload in payloads))

    def test_protected_interface_cannot_change_mode(self):
        protected = {"name": "wlan0", "wireless": True, "default_route": True}
        with patch.object(citypop, "interface_inventory", return_value=[protected]):
            response = self.client.post(
                "/api/hardware/interface-mode", headers=self.headers,
                json={"interface": "wlan0", "mode": "monitor"},
            )
        self.assertEqual(response.status_code, 409)
        self.assertIn("protected", response.get_json()["detail"])

    def test_protected_interface_cannot_be_brought_down(self):
        protected = {"name": "wlan0", "wireless": True, "default_route": True}
        with patch.object(citypop, "interface_inventory", return_value=[protected]):
            response = self.client.post(
                "/api/hardware/interface-link", headers=self.headers,
                json={"interface": "wlan0", "state": "down"},
            )
        self.assertEqual(response.status_code, 409)
        self.assertIn("protected", response.get_json()["detail"])

    def test_non_protected_interface_can_be_brought_up(self):
        available = {"name": "wlan1", "wireless": True, "default_route": False}
        command = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(citypop, "interface_inventory", return_value=[available]), \
                patch.object(citypop.subprocess, "run", return_value=command) as run:
            response = self.client.post(
                "/api/hardware/interface-link", headers=self.headers,
                json={"interface": "wlan1", "state": "up"},
            )
        self.assertEqual(response.status_code, 200)
        run.assert_called_once_with(
            ["sudo", "-n", "ip", "link", "set", "dev", "wlan1", "up"],
            capture_output=True, text=True, timeout=10,
        )

    def test_poweroff_refuses_while_operation_is_running(self):
        with patch.object(citypop.runner, "snapshot", return_value={"running": {"name": "test"}}):
            response = self.client.post("/api/system/poweroff", headers=self.headers)
        self.assertEqual(response.status_code, 409)

    def test_runtime_and_history_shapes(self):
        runtime = self.client.get("/api/runtime", headers=self.headers)
        history = self.client.get("/api/executions", headers=self.headers)
        self.assertEqual(runtime.status_code, 200)
        self.assertIn("output", runtime.get_json())
        self.assertEqual(history.status_code, 200)
        self.assertIn("executions", history.get_json())

    def test_running_execution_history_cannot_be_deleted(self):
        run_id = "a" * 32
        with patch.object(citypop.runner, "snapshot", return_value={"running": {"run_id": run_id}}), \
                patch.object(citypop.runner, "delete_execution_history") as delete:
            response = self.client.delete(
                f"/api/executions/{run_id}", headers=self.headers,
                json={"confirm": f"DELETE {run_id}"},
            )
        self.assertEqual(response.status_code, 409)
        delete.assert_not_called()

    def test_delete_all_execution_history_is_scoped_to_engagement(self):
        with patch.object(citypop.runner, "snapshot", return_value={"running": None}), \
                patch.object(citypop.runner, "delete_engagement_history", return_value=3) as delete:
            response = self.client.delete(
                "/api/executions", headers=self.headers,
                json={"engagement": "test_lab", "confirm": "DELETE ALL RUNS"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["deleted"], 3)
        delete.assert_called_once_with("test_lab")

    def test_report_manager_shape(self):
        response = self.client.get("/api/reports", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("reports", response.get_json())

    def test_engagement_manager_shape(self):
        response = self.client.get("/api/engagements", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("engagements", response.get_json())

    def test_payload_loot_directories_are_not_engagements(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "loot" / "DeadDrop").mkdir(parents=True)
            (root / "loot" / "KarmaAP").mkdir()
            (root / "loot" / "logs").mkdir()
            store = EngagementStore(root / "state" / "engagements.json")
            with patch.object(citypop, "LOOT", root / "loot"), \
                    patch.object(citypop, "engagements", store), \
                    patch.object(citypop.runner, "execution_history", return_value=[]):
                response = self.client.get("/api/engagements", headers=self.headers)
            self.assertEqual(response.get_json()["engagements"], [])

    def test_every_payload_has_a_preflight_endpoint(self):
        payloads = self.client.get("/api/payloads", headers=self.headers).get_json()["payloads"]
        for payload in payloads:
            with self.subTest(payload=payload["id"]):
                response = self.client.get(f"/api/preflight/{payload['id']}", headers=self.headers)
                self.assertEqual(response.status_code, 200)
                data = response.get_json()
                self.assertEqual(data["payload"]["id"], payload["id"])
                self.assertIn("checks", data)
                self.assertIn("warnings", data)
                self.assertIn("capabilities", data)
                self.assertTrue(data["checks"])
                self.assertTrue(all("blocking" in check for check in data["checks"]))


if __name__ == "__main__":
    unittest.main()
