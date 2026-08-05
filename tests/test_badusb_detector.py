import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from payloads.usb import badusb_detector as detector


class FakeInput:
    name = "Test USB Keyboard"

    def capabilities(self):
        return {1: [28, 30, 44, 57]}


class BadUsbDetectorTests(unittest.TestCase):
    def test_usb_keyboard_requires_keyboard_and_usb_properties(self):
        fake_codes = SimpleNamespace(EV_KEY=1, KEY_A=30, KEY_Z=44, KEY_SPACE=57, KEY_ENTER=28)
        with mock.patch.object(detector, "ecodes", fake_codes):
            self.assertTrue(detector.is_usb_keyboard(
                {"ID_BUS": "usb", "ID_INPUT_KEYBOARD": "1"}, FakeInput()
            ))
            self.assertFalse(detector.is_usb_keyboard(
                {"ID_BUS": "usb", "ID_INPUT_MOUSE": "1"}, FakeInput()
            ))
            self.assertFalse(detector.is_usb_keyboard(
                {"ID_BUS": "bluetooth", "ID_INPUT_KEYBOARD": "1"}, FakeInput()
            ))

    def test_preexisting_inventory_accepts_non_usb_keyboard(self):
        fake_codes = SimpleNamespace(EV_KEY=1, KEY_A=30, KEY_Z=44, KEY_SPACE=57, KEY_ENTER=28)
        with mock.patch.object(detector, "ecodes", fake_codes):
            self.assertTrue(detector.is_keyboard(
                {"ID_BUS": "bluetooth", "ID_INPUT_KEYBOARD": "1"}, FakeInput()
            ))
            self.assertTrue(detector.is_keyboard(
                {"ID_BUS": "i8042", "ID_INPUT_KEYBOARD": "1"}, FakeInput()
            ))

    def test_mouse_like_key_device_is_not_a_typing_keyboard(self):
        fake_codes = SimpleNamespace(EV_KEY=1, KEY_A=30, KEY_Z=44, KEY_SPACE=57, KEY_ENTER=28)
        mouse = mock.Mock()
        mouse.capabilities.return_value = {1: [272, 273, 274]}
        with mock.patch.object(detector, "ecodes", fake_codes):
            self.assertFalse(detector.is_keyboard(
                {"ID_BUS": "usb", "ID_INPUT_KEYBOARD": "1"}, mouse
            ))

    def test_new_and_preexisting_identity_have_different_trace_policy(self):
        props = {
            "ID_MODEL": "Fixture",
            "ID_VENDOR_ID": "1234",
            "ID_MODEL_ID": "5678",
        }
        existing = detector.device_identity("/dev/input/event1", FakeInput(), props, "pre-existing")
        new = detector.device_identity("/dev/input/event2", FakeInput(), props, "new")
        self.assertFalse(existing["exact_trace"])
        self.assertEqual(existing["trace_status"], "disabled (pre-existing)")
        self.assertTrue(new["exact_trace"])
        self.assertEqual(new["trace_status"], "pending")

    def test_jsonl_trace_is_private_and_structured(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "BadUSB" / "trace.jsonl"
            journal = detector.SecureJsonl(path)
            journal.write("key_event", device="/dev/input/event2", key="KEY_A", action="press")
            journal.close()

            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(record["event"], "key_event")
            self.assertEqual(record["key"], "KEY_A")
            self.assertIn("timestamp", record)


if __name__ == "__main__":
    unittest.main()
