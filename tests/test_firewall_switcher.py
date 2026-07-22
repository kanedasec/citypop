import unittest
from unittest.mock import patch

from payloads.network import firewall_switcher


class FirewallSwitcherTests(unittest.TestCase):
    def test_interactive_prompt_uses_descriptive_structured_choices(self):
        with patch.object(firewall_switcher.sys, "argv", ["firewall_switcher.py"]), \
                patch.object(firewall_switcher, "_detect_active_preset", return_value="OPEN"), \
                patch.object(firewall_switcher, "request_input", return_value="show") as prompt, \
                patch.object(firewall_switcher, "_get_current_rules", return_value=["rules"]):
            result = firewall_switcher.main()

        self.assertEqual(result, 0)
        choices = prompt.call_args.kwargs["choices"]
        self.assertEqual(prompt.call_args.kwargs["input_type"], "select")
        self.assertEqual(prompt.call_args.kwargs["default"], "show")
        self.assertTrue(all(isinstance(choice, dict) for choice in choices))
        labels = " ".join(choice["label"] for choice in choices)
        self.assertIn("without changing", labels)
        self.assertIn("apply immediately", prompt.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
