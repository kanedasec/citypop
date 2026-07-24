import json
import http.client
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from scapy.all import DNS, DNSQR

from payloads.network.dns_spoofing import (
    allowed_submission_fields, build_spoof_response, discover_templates,
    domain_matches, normalize_domain, parse_query, redirect_handler, template_handler,
)


class DnsSpoofingTests(unittest.TestCase):
    def test_template_catalog_reads_static_sites_and_ignores_incomplete_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "lab-notice"
            valid.mkdir()
            (valid / "index.html").write_text("notice", encoding="utf-8")
            (valid / "template.json").write_text(json.dumps({
                "name": "Lab Notice", "description": "safe training page",
                "submission_fields": ["attendance_plan", "feedback"],
            }), encoding="utf-8")
            (root / "missing-index").mkdir()
            choices = discover_templates(root)

        self.assertEqual([choice["value"] for choice in choices], ["none", "lab-notice"])
        self.assertIn("safe training page", choices[1]["label"])
        self.assertEqual(choices[1]["submission_fields"], ["attendance_plan", "feedback"])

    def test_submission_allowlist_rejects_credential_like_fields(self):
        fields = allowed_submission_fields([
            "survey_choice", "feedback",
        ])
        self.assertEqual(fields, ["survey_choice", "feedback"])

    def test_template_server_records_only_declared_post_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "index.html").write_text("formulário de ação", encoding="utf-8")
            (root / "thanks.html").write_text("thanks", encoding="utf-8")
            event_log = root / "events.jsonl"
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                template_handler(root, event_log, ["survey_choice"]),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                page = urlopen(base + "/", timeout=3)
                self.assertEqual(page.headers.get_content_charset(), "utf-8")
                self.assertEqual(page.read().decode("utf-8"), "formulário de ação")

                request = Request(
                    base + "/submit", data=urlencode({"survey_choice": "report"}).encode(),
                )
                self.assertEqual(urlopen(request, timeout=3).read(), b"thanks")
                events = [
                    json.loads(line)
                    for line in event_log.read_text(encoding="utf-8").splitlines()
                ]
                submission = next(
                    event for event in events if event["event"] == "form_submission"
                )
                self.assertEqual(submission["fields"], {"survey_choice": "report"})
                self.assertTrue(any(event["event"] == "http_request" for event in events))

                prohibited = Request(
                    base + "/submit", data=urlencode({"sensitive": "never"}).encode(),
                )
                with self.assertRaises(HTTPError) as error:
                    urlopen(prohibited, timeout=3)
                self.assertEqual(error.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_http_redirect_preserves_host_path_and_query(self):
        with tempfile.TemporaryDirectory() as temporary:
            event_log = Path(temporary) / "events.jsonl"
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0), redirect_handler("fallback.test", event_log),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
                connection.request("GET", "/notice?id=7", headers={"Host": "portal.test"})
                response = connection.getresponse()
                self.assertEqual(response.status, 308)
                self.assertEqual(response.getheader("Location"), "https://portal.test/notice?id=7")
                response.read()
                connection.close()
                event = json.loads(event_log.read_text(encoding="utf-8"))
                self.assertEqual(event["event"], "https_redirect")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_domain_validation_and_wildcard_matching(self):
        self.assertEqual(normalize_domain("*.Example.Test."), "*.example.test")
        self.assertTrue(domain_matches("login.example.test", "*.example.test"))
        self.assertFalse(domain_matches("example.test", "*.example.test"))
        self.assertFalse(domain_matches("notexample.test", "*.example.test"))
        with self.assertRaises(ValueError):
            normalize_domain("*.*.example.test")

    def test_spoof_response_preserves_transaction_and_returns_address(self):
        query = DNS(id=1234, rd=1, qd=DNSQR(qname="portal.example.test", qtype="A"))
        parsed, domain, qtype = parse_query(bytes(query))
        self.assertEqual(domain, "portal.example.test")
        self.assertEqual(qtype, 1)
        response = DNS(build_spoof_response(parsed, domain, "10.0.0.9"))
        self.assertEqual(response.id, 1234)
        self.assertEqual(response.qr, 1)
        self.assertEqual(response.an[0].rdata, "10.0.0.9")


if __name__ == "__main__":
    unittest.main()
