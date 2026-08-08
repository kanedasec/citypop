import ast
import unittest
from pathlib import Path


PAYLOAD = Path(__file__).resolve().parents[1] / "payloads" / "wifi" / "unitree_pwn.py"


class UnitreeWebConversionTests(unittest.TestCase):
    def test_payload_contains_no_legacy_lcd_execution_surface(self):
        source = PAYLOAD.read_text(encoding="utf-8")
        tree = ast.parse(source)
        function_names = {
            node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        }
        argument_names = {
            argument.arg
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        }
        self.assertFalse(any(name.startswith("draw_") for name in function_names))
        self.assertNotIn("lcd", argument_names)
        self.assertNotIn("LCD_ShowImage", source)
        self.assertNotIn("ScaledDraw", source)


if __name__ == "__main__":
    unittest.main()
