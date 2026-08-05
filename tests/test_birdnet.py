import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


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

    def test_bundle_download_stops_after_inactivity_limit(self):
        process = Mock()
        process.returncode = -15
        process.poll.side_effect = [None, None, None]
        process.wait.return_value = -15
        process.communicate.return_value = ("", "")
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(birdnet.subprocess, "Popen", return_value=process), \
                patch.object(birdnet.time, "monotonic", side_effect=[0, 0, 61]), \
                patch.object(birdnet.time, "sleep"):
            success, detail = birdnet._download_model_archive(
                str(Path(temporary) / "bundle.zip")
            )
        self.assertFalse(success)
        self.assertIn("no data received", detail)
        process.terminate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
