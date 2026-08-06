import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from citypop import app as citypop
from citypop.app import _configured_usb_role, _render_usb_role


class UsbRoleConfigTests(unittest.TestCase):
    def test_cm5_host_setting_does_not_override_zero_all_section(self):
        config = "[cm5]\ndtoverlay=dwc2,dr_mode=host\n\n[all]\ndtoverlay=dwc2\n"
        self.assertEqual(_configured_usb_role(config), "hid")

    def test_host_mode_preserves_other_dwc2_parameters(self):
        config = "[all]\ndtoverlay=dwc2,g-rx-fifo-size=558\n"
        rendered = _render_usb_role(config, "host")
        self.assertIn("dtoverlay=dwc2,g-rx-fifo-size=558,dr_mode=host", rendered)
        self.assertEqual(_configured_usb_role(rendered), "host")

    def test_hid_mode_removes_forced_host_parameter(self):
        config = "[all]\ndtoverlay=dwc2,g-rx-fifo-size=558,dr_mode=host\n"
        rendered = _render_usb_role(config, "hid")
        self.assertIn("dtoverlay=dwc2,g-rx-fifo-size=558\n", rendered)
        self.assertNotIn("dr_mode=host", rendered)
        self.assertEqual(_configured_usb_role(rendered), "hid")

    def test_missing_all_section_is_created_without_changing_model_section(self):
        config = "[cm5]\ndtoverlay=dwc2,dr_mode=host\n"
        rendered = _render_usb_role(config, "hid")
        self.assertIn("[cm5]\ndtoverlay=dwc2,dr_mode=host", rendered)
        self.assertTrue(rendered.endswith("[all]\ndtoverlay=dwc2\n"))

    def test_role_change_writes_config_and_preserves_one_time_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.txt"
            config.write_text("[all]\ndtoverlay=dwc2\n", encoding="utf-8")
            inventory = {
                "supported": True, "config_path": str(config),
                "configured": "hid", "active": "hid",
            }
            with patch.object(citypop, "usb_role_inventory", return_value=inventory):
                ok, detail = citypop.set_usb_role("host")
                self.assertTrue(ok, detail)
                self.assertEqual(_configured_usb_role(config.read_text()), "host")
                backup = config.with_name("config.txt.citypop.bak")
                self.assertEqual(backup.read_text(), "[all]\ndtoverlay=dwc2\n")

                ok, detail = citypop.set_usb_role("hid")
                self.assertTrue(ok, detail)
                self.assertEqual(backup.read_text(), "[all]\ndtoverlay=dwc2\n")


if __name__ == "__main__":
    unittest.main()
