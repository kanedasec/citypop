import unittest

from payloads.reconnaissance.mdns_scanner import interface_results


class MdnsScannerTests(unittest.TestCase):
    def test_results_are_filtered_to_the_selected_interface(self):
        output = (
            "+;wlp2s0;IPv4;Printer;_ipp._tcp;local\n"
            "+;eth0;IPv4;NAS;_smb._tcp;local\n"
            "=;wlp2s0;IPv4;Printer;_ipp._tcp;local;printer.local;192.0.2.4;631;\n"
        )
        self.assertEqual(interface_results(output, "wlp2s0"), [
            "+;wlp2s0;IPv4;Printer;_ipp._tcp;local",
            "=;wlp2s0;IPv4;Printer;_ipp._tcp;local;printer.local;192.0.2.4;631;",
        ])


if __name__ == "__main__":
    unittest.main()
