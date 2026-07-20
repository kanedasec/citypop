import unittest

import app as citypop


class WebApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = citypop.app.test_client()
        cls.headers = {"X-CityPop-Token": citypop.config["auth_token"]}

    def test_protected_api_rejects_anonymous_request(self):
        self.assertEqual(self.client.get("/api/payloads").status_code, 401)

    def test_payload_catalog_is_available_when_authenticated(self):
        response = self.client.get("/api/payloads", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        payloads = response.get_json()["payloads"]
        self.assertTrue(payloads)
        self.assertTrue(all(payload["web"] for payload in payloads))

    def test_runtime_and_history_shapes(self):
        runtime = self.client.get("/api/runtime", headers=self.headers)
        history = self.client.get("/api/executions", headers=self.headers)
        self.assertEqual(runtime.status_code, 200)
        self.assertIn("output", runtime.get_json())
        self.assertEqual(history.status_code, 200)
        self.assertIn("executions", history.get_json())

    def test_report_manager_shape(self):
        response = self.client.get("/api/reports", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("reports", response.get_json())

    def test_engagement_manager_shape(self):
        response = self.client.get("/api/engagements", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("engagements", response.get_json())

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
