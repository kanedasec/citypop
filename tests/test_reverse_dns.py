import io
import socket
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from payloads.reconnaissance.reverse_dns import reverse_lookup


class ReverseDnsTests(unittest.TestCase):
    @patch(
        "payloads.reconnaissance.reverse_dns.socket.gethostbyaddr",
        side_effect=socket.herror(1, "Unknown host"),
    )
    def test_missing_ptr_has_an_explicit_message(self, _lookup):
        output = io.StringIO()
        with redirect_stdout(output):
            result = reverse_lookup("4.228.31.150")
        self.assertEqual(result, 1)
        self.assertEqual(
            output.getvalue().strip(),
            "No PTR record exists for 4.228.31.150",
        )

    def test_invalid_ip_is_rejected_before_lookup(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = reverse_lookup("example.com")
        self.assertEqual(result, 2)
        self.assertIn("Invalid IP address", output.getvalue())


if __name__ == "__main__":
    unittest.main()
