import ast
import tempfile
import unittest
from pathlib import Path

from citypop.app import portal_image_extension, tls_context
from citypop.payload_runner import discover, parse_metadata


ROOT = Path(__file__).resolve().parents[1]
PAYLOADS = ROOT / "payloads"
SUPPORTED_INPUTS = {"text", "password", "number", "select", "file"}


class PayloadCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = discover(PAYLOADS)

    def test_catalog_is_not_empty_and_ids_are_unique(self):
        self.assertGreater(len(self.payloads), 0)
        ids = [payload["id"] for payload in self.payloads]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_payload_is_active_and_web_native(self):
        for payload in self.payloads:
            with self.subTest(payload=payload["id"]):
                self.assertTrue(payload["active"])
                self.assertTrue(payload["web"])
                capabilities = payload.get("capabilities", {})
                self.assertIn("static_inputs", capabilities)
                self.assertIn("runtime_inputs", capabilities)
                self.assertIn("commands", capabilities)
                self.assertIn("python_modules", capabilities)
                self.assertIn("hardware", capabilities)
                self.assertIn("kernel_capabilities", capabilities)
                self.assertIn("dashboard", capabilities)
                self.assertIn("produces_loot", capabilities)

    def test_whois_output_does_not_create_runtime_links(self):
        metadata = parse_metadata(PAYLOADS / "reconnaissance" / "whois_lookup.py")
        self.assertFalse(metadata["runtime_links"])
        self.assertTrue(parse_metadata(
            PAYLOADS / "reconnaissance" / "dns_lookup.py"
        )["runtime_links"])

    def test_category_matches_parent_directory(self):
        for payload in self.payloads:
            with self.subTest(payload=payload["id"]):
                self.assertEqual(payload["category"], Path(payload["id"]).parent.name)

    def test_descriptions_are_web_appropriate(self):
        forbidden = ("lcd", "raspyjack")
        for payload in self.payloads:
            with self.subTest(payload=payload["id"]):
                description = payload["desc"].strip().lower()
                self.assertTrue(description)
                self.assertFalse(any(word in description for word in forbidden))

    def test_static_inputs_use_supported_schema(self):
        for payload in self.payloads:
            names = set()
            for index, spec in enumerate(payload["inputs"]):
                with self.subTest(payload=payload["id"], input=index):
                    self.assertIsInstance(spec, dict)
                    self.assertTrue(spec.get("name"))
                    self.assertTrue(spec.get("label"))
                    self.assertIn(spec.get("type"), SUPPORTED_INPUTS)
                    self.assertNotIn(spec["name"], names)
                    names.add(spec["name"])
                    if spec["type"] == "select":
                        self.assertIsInstance(spec.get("choices"), list)
                        self.assertTrue(spec["choices"])
                        for choice in spec["choices"]:
                            self.assertIsInstance(choice, dict)
                            self.assertIn("value", choice)
                            self.assertTrue(choice.get("label"))
                            self.assertNotEqual(str(choice["value"]), choice["label"])
                    if spec["type"] == "file":
                        self.assertTrue(str(spec.get("accept", "")).startswith("image/"))

    def test_runtime_input_types_are_supported(self):
        for path in PAYLOADS.glob("*/*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                if name != "request_input":
                    continue
                keywords = {item.arg: item.value for item in node.keywords if item.arg}
                input_type = ast.literal_eval(keywords["input_type"]) if "input_type" in keywords else "text"
                with self.subTest(payload=str(path.relative_to(PAYLOADS)), line=node.lineno):
                    self.assertIn(input_type, SUPPORTED_INPUTS)
                    if input_type == "select":
                        self.assertIn("choices", keywords)

    def test_network_interface_prompts_describe_the_required_interface(self):
        requirement_terms = (
            "connected", "external", "managed", "management",
            "monitor-mode", "monitor mode", "default-route", "to inspect",
        )
        missing = []
        for path in PAYLOADS.glob("*/*.py"):
            if path.parent.name == "bluetooth" or path.name == "bt_scan_classic.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                function = node.func
                name = function.id if isinstance(function, ast.Name) else getattr(function, "attr", "")
                if name != "request_input" or not node.args:
                    continue
                label_node = node.args[0]
                if isinstance(label_node, ast.Constant) and isinstance(label_node.value, str):
                    label = label_node.value
                elif isinstance(label_node, ast.JoinedStr):
                    label = "".join(
                        part.value
                        for part in label_node.values
                        if isinstance(part, ast.Constant) and isinstance(part.value, str)
                    )
                else:
                    continue
                lowered = label.lower()
                if (
                    "select" in lowered
                    and ("interface" in lowered or "wi-fi adapter" in lowered)
                    and not any(term in lowered for term in requirement_terms)
                ):
                    missing.append(f"{path.relative_to(ROOT)}: {label}")
        self.assertEqual(
            missing, [],
            "Network-interface prompts must state whether they require a "
            f"connected, external, managed, or monitor-mode interface: {missing}",
        )

    def test_interface_prompt_requirements_match_payload_lifecycle(self):
        unused_external = {
            "network/goodportal.py",
            "wifi/captive_portal.py",
            "wifi/ciw_zeroclick.py",
            "wifi/dead_drop.py",
            "wifi/deauth.py",
            "wifi/espnow_evil_master.py",
            "wifi/evil_twin.py",
            "wifi/handshake_hunter.py",
            "wifi/karma_ap.py",
            "wifi/pmkid_grab.py",
            "wifi/raspygotchi.py",
            "wifi/ssid_pool.py",
            "wifi/wifi_alert.py",
            "wifi/wifi_handshake_auto.py",
            "wifi/wifi_probe_dump.py",
            "wifi/wifi_survey.py",
            "wifi/wpa_enterprise_evil.py",
            "wifi/wps_pixie.py",
        }
        connected = {
            "ai/network_anomaly.py",
            "credentials/default_creds_scanner.py",
            "evasion/timing_evasion.py",
            "evasion/traffic_shaper.py",
            "network/arp_dos.py",
            "network/arp_mitm.py",
            "network/dhcp_snoop.py",
            "network/dns_spoofing.py",
            "network/igmp_snoop.py",
            "network/lldp_recon.py",
            "network/mdns_poison.py",
            "network/nbns_spoof.py",
            "network/syn_flood.py",
            "network/tcp_rst_inject.py",
            "network/traffic_analyzer.py",
            "network/trunk_dump.py",
            "reconnaissance/mdns_scanner.py",
            "reconnaissance/passive_os_detect.py",
            "utilities/packet_replay.py",
        }
        monitor = {
            path for path in unused_external
            if path not in {
                "network/goodportal.py",
                "wifi/captive_portal.py",
                "wifi/ciw_zeroclick.py",
                "wifi/dead_drop.py",
            }
        }
        for relative in sorted(unused_external):
            source = (PAYLOADS / relative).read_text(encoding="utf-8", errors="replace")
            with self.subTest(payload=relative, requirement="unused external"):
                self.assertIn("unused/unconnected", source)
                self.assertIn("external Wi-Fi adapter", source)
        for relative in sorted(connected):
            source = (PAYLOADS / relative).read_text(encoding="utf-8", errors="replace")
            with self.subTest(payload=relative, requirement="connected"):
                self.assertIn("connected", source)
                self.assertIn("interface", source)
        for relative in sorted(monitor):
            source = (PAYLOADS / relative).read_text(encoding="utf-8", errors="replace")
            with self.subTest(payload=relative, requirement="monitor"):
                self.assertIn("monitor", source.lower())

    def test_all_discoverable_files_parse_directly(self):
        for payload in self.payloads:
            path = PAYLOADS / payload["id"]
            with self.subTest(payload=payload["id"]):
                self.assertEqual(parse_metadata(path)["name"], payload["name"])

    def test_maturity_is_optional_and_validated(self):
        base = "# @name: Test\n# @desc: Test payload\n# @category: test\n# @danger: false\n"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "payload.py"
            path.write_text(base, encoding="utf-8")
            self.assertEqual(parse_metadata(path)["maturity"], "not tested")

            path.write_text(base + "# @maturity: Functional\n", encoding="utf-8")
            self.assertEqual(parse_metadata(path)["maturity"], "functional")

            path.write_text(base + "# @maturity: experimental\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "@maturity"):
                parse_metadata(path)

    def test_tls_can_be_disabled_without_certificate_files(self):
        self.assertIsNone(tls_context({"tls": {"enabled": False}}))

    def test_portal_image_uploads_use_file_signatures(self):
        self.assertEqual(portal_image_extension(b"\x89PNG\r\n\x1a\npayload"), ".png")
        self.assertEqual(portal_image_extension(b"\xff\xd8\xffpayload"), ".jpg")
        self.assertEqual(portal_image_extension(b"GIF89apayload"), ".gif")
        self.assertEqual(portal_image_extension(b"RIFF1234WEBPpayload"), ".webp")
        self.assertIsNone(portal_image_extension(b"<html>not an image</html>"))


if __name__ == "__main__":
    unittest.main()
