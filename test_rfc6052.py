import unittest

from rfc6052 import ipv4_to_ipv6, ipv6_to_ipv4


class TestRFC6052(unittest.TestCase):
    def test_ipv4_to_ipv6_success(self):
        ipv4_address: str = "192.168.1.1"
        expected_result: str = "64:ff9b::c0a8:0101"
        result = ipv4_to_ipv6(ipv4_address)
        self.assertEqual(result, expected_result)

    def test_ipv4_to_ipv6_invalid_ip_octet(self):
        ipv4_address: str = '999.999.999.999'
        with self.assertRaises(ValueError):
            ipv4_to_ipv6(ipv4_address)

    def test_ipv4_to_ipv6_invalid_ip_length_long(self):
        ipv4_address: str = "1.2.3.4.5.6.7.8"
        with self.assertRaises(ValueError):
            ipv4_to_ipv6(ipv4_address)

    def test_ipv4_to_ipv6_invalid_ip_length_short(self):
        ipv4_address: str = "1.2.3"
        with self.assertRaises(ValueError):
            ipv4_to_ipv6(ipv4_address)

    def test_ipv4_to_ipv6_invalid_ip_characters(self):
        ipv4_address: str = "%4.#2.0.$2"
        with self.assertRaises(ValueError):
            ipv4_to_ipv6(ipv4_address)

    def test_ipv4_to_ipv6_invalid_empty(self):
        ipv4_address: str = ""
        with self.assertRaises(ValueError):
            ipv4_to_ipv6(ipv4_address)

    def test_ipv6_to_ipv4_success(self):
        ipv6_address: str = '64:ff9b::ffff:ffff'
        expected_result: str = '255.255.255.255'
        result = ipv6_to_ipv4(ipv6_address)
        self.assertEqual(result, expected_result)

    def test_ipv6_to_ipv4_invalid_ip_octet(self):
        ipv6_address: str = 'fdf8:f53b:zzzz::53'
        with self.assertRaises(ValueError):
            ipv6_to_ipv4(ipv6_address)

    def test_ipv6_to_ipv4_invalid_ip_length_long(self):
        ipv6_address: str = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        with self.assertRaises(ValueError):
            ipv6_to_ipv4(ipv6_address)

    def test_ipv6_to_ipv4_invalid_ip_length_short(self):
        ipv6_address: str = 'ffff:'
        with self.assertRaises(ValueError):
            ipv6_to_ipv4(ipv6_address)

    def test_ipv6_top_ipv4_invalid_characters(self):
        ipv6_address: str = '$ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        with self.assertRaises(ValueError):
            ipv6_to_ipv4(ipv6_address)

    def test_ipv6_to_ipv4_invalid_empty(self):
        ipv6_address: str = ""
        with self.assertRaises(ValueError):
            ipv6_to_ipv4(ipv6_address)


if __name__ == '__main__':
    unittest.main()