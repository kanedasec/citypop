import ast
import unittest
from pathlib import Path


PAYLOAD = Path(__file__).resolve().parents[1] / "payloads" / "wifi" / "deauth.py"


class DeauthWebConversionTests(unittest.TestCase):
    def test_preflight_contains_no_removed_lcd_status_calls(self):
        tree = ast.parse(PAYLOAD.read_text(encoding="utf-8"))
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("draw_status", called_names)
        self.assertIn("status", called_names)


if __name__ == "__main__":
    unittest.main()
