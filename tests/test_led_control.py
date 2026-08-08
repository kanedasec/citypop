import ast
import unittest
from pathlib import Path


PAYLOAD = Path(__file__).resolve().parents[1] / "payloads" / "hardware" / "led_control.py"


class LedControlWebInputTests(unittest.TestCase):
    def test_primary_runtime_prompt_is_an_explicit_select(self):
        tree = ast.parse(PAYLOAD.read_text(encoding="utf-8"))
        requests = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "request_input"
        ]
        select_requests = [
            node for node in requests
            if any(
                keyword.arg == "input_type"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value == "select"
                for keyword in node.keywords
            )
        ]
        self.assertEqual(len(select_requests), 1)
        self.assertTrue(any(keyword.arg == "choices" for keyword in select_requests[0].keywords))

    def test_custom_timing_uses_numeric_web_inputs(self):
        tree = ast.parse(PAYLOAD.read_text(encoding="utf-8"))
        numeric_requests = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "request_input"
            and any(
                keyword.arg == "input_type"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value == "number"
                for keyword in node.keywords
            )
        ]
        self.assertEqual(len(numeric_requests), 2)


if __name__ == "__main__":
    unittest.main()
