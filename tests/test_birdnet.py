import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_birdnet():
    fake_numpy = types.ModuleType("numpy")
    previous = sys.modules.get("numpy")
    sys.modules["numpy"] = fake_numpy
    try:
        spec = importlib.util.spec_from_file_location(
            "citypop_test_birdnet", ROOT / "payloads" / "ai" / "birdnet.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if previous is None:
            sys.modules.pop("numpy", None)
        else:
            sys.modules["numpy"] = previous


birdnet = load_birdnet()


class BirdnetModelTests(unittest.TestCase):
    def test_three_byte_partial_model_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            model = Path(temporary) / "model.tflite"
            model.write_bytes(b"404")
            self.assertFalse(birdnet._valid_model(str(model)))

    def test_tflite_validation_requires_expected_hash_and_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            model = Path(temporary) / "model.tflite"
            model.write_bytes(b"\x1c\x00\x00\x00TFL3payload")
            with patch.object(birdnet, "MODEL_SIZE", model.stat().st_size), \
                    patch.object(birdnet, "MODEL_SHA256", birdnet._sha256(model)):
                self.assertTrue(birdnet._valid_model(str(model)))

    def test_failed_bundle_install_is_not_treated_as_success(self):
        with patch.object(birdnet, "_valid_model_bundle", return_value=False), \
                patch.object(birdnet, "_install_model_bundle", return_value=False):
            self.assertFalse(birdnet._ensure_model())


if __name__ == "__main__":
    unittest.main()
