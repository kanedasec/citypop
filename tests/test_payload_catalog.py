import ast
import tempfile
import unittest
from pathlib import Path

from payload_runner import discover, parse_metadata
from app import portal_image_extension, tls_context


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
