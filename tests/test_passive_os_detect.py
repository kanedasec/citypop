import unittest

from payloads.reconnaissance.passive_os_detect import (
    infer_os_family, parse_tshark_fields,
)


class PassiveOsDetectTests(unittest.TestCase):
    def test_parser_keeps_ipv4_and_ipv6_sources(self):
        records = parse_tshark_fields(
            "192.168.1.20\t\t117\t\t64240\t1460\n"
            "\t2001:db8::20\t\t61\t65320\t1420\n"
        )
        self.assertEqual(records[0]["address"], "192.168.1.20")
        self.assertEqual(records[0]["ip_version"], 4)
        self.assertEqual(records[1]["address"], "2001:db8::20")
        self.assertEqual(records[1]["ip_version"], 6)
        self.assertEqual(records[1]["ttl_or_hop_limit"], 61)

    def test_inference_is_explicitly_conservative(self):
        self.assertEqual(infer_os_family(117, 64240, 1460)[:2], (
            "Windows-family", "moderate",
        ))
        self.assertEqual(infer_os_family(61, 65320, 1420)[:2], (
            "Linux/Android-family", "low",
        ))
        self.assertEqual(infer_os_family(None, None, None)[:2], (
            "Unknown", "insufficient",
        ))


if __name__ == "__main__":
    unittest.main()
