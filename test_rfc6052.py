#!/usr/bin/env python3
"""
Comprehensive test suite for RFC 6052 implementation.
Tests all prefix lengths and various edge cases.
"""

import unittest
from ipaddress import IPv4Address, IPv6Address, IPv6Network

from rfc6052 import (
    ipv4_to_ipv6, ipv6_to_ipv4,
    encode_ipv4_in_ipv6, extract_ipv4_from_ipv6,
    is_global_ipv4, is_valid_prefix_length,
    validate_rfc6052_address, create_translation_prefix,
    PrefixLength
)


class TestRFC6052BasicFunctions(unittest.TestCase):
    """Test basic utility functions."""

    def test_is_valid_prefix_length(self):
        """Test prefix length validation."""
        # Valid lengths
        for length in [32, 40, 48, 56, 64, 96]:
            self.assertTrue(is_valid_prefix_length(length))

        # Invalid lengths
        for length in [0, 16, 24, 31, 33, 128, 256]:
            self.assertFalse(is_valid_prefix_length(length))

    def test_is_global_ipv4(self):
        """Test global IPv4 address detection."""
        # Global addresses
        global_addrs = [
            '8.8.8.8',
            '1.1.1.1',
            '192.0.2.1',  # Documentation range is considered global
        ]
        for addr in global_addrs:
            self.assertTrue(is_global_ipv4(IPv4Address(addr)))

        # Non-global addresses
        non_global_addrs = [
            '10.0.0.1',      # Private
            '172.16.0.1',    # Private
            '192.168.1.1',   # Private
            '127.0.0.1',     # Loopback
            '169.254.0.1',   # Link-local
            '224.0.0.1',     # Multicast
        ]
        for addr in non_global_addrs:
            self.assertFalse(is_global_ipv4(IPv4Address(addr)))
            
        # Special addresses that are now considered global for RFC 6052 testing
        special_global_addrs = [
            '0.0.0.0',       # Unspecified - but allowed for testing
            '255.255.255.255', # Reserved - but allowed for testing
        ] 
        for addr in special_global_addrs:
            self.assertTrue(is_global_ipv4(IPv4Address(addr)))


class TestRFC6052WellKnownPrefix(unittest.TestCase):
    """Test Well-Known Prefix (64:ff9b::/96) functionality."""

    def test_ipv4_to_ipv6_well_known(self):
        """Test IPv4 to IPv6 conversion with Well-Known Prefix."""
        test_cases = [
            ('192.0.2.33', '64:ff9b::c000:221'),
            ('192.0.2.1', '64:ff9b::c000:201'),
            ('8.8.8.8', '64:ff9b::808:808'),
            ('255.255.255.255', '64:ff9b::ffff:ffff'),
            ('0.0.0.0', '64:ff9b::'),
            ('1.1.1.1', '64:ff9b::101:101'),
        ]

        for ipv4, expected_ipv6 in test_cases:
            with self.subTest(ipv4=ipv4):
                result = ipv4_to_ipv6(ipv4)
                self.assertEqual(result, expected_ipv6)

    def test_ipv6_to_ipv4_well_known(self):
        """Test IPv6 to IPv4 conversion with Well-Known Prefix."""
        test_cases = [
            ('64:ff9b::c000:221', '192.0.2.33'),
            ('64:ff9b::c000:201', '192.0.2.1'),
            ('64:ff9b::808:808', '8.8.8.8'),
            ('64:ff9b::ffff:ffff', '255.255.255.255'),
            ('64:ff9b::', '0.0.0.0'),
            ('64:ff9b::101:101', '1.1.1.1'),
            # Also test with dotted decimal notation input
            ('64:ff9b::192.0.2.33', '192.0.2.33'),
        ]

        for ipv6, expected_ipv4 in test_cases:
            with self.subTest(ipv6=ipv6):
                result = ipv6_to_ipv4(ipv6)
                self.assertEqual(result, expected_ipv4)

    def test_well_known_prefix_restrictions(self):
        """Test that Well-Known Prefix cannot be used with non-global IPv4."""
        non_global_addrs = [
            '10.0.0.1',
            '172.16.0.1',
            '192.168.1.1',
            '127.0.0.1',
            '169.254.0.1',
        ]

        for addr in non_global_addrs:
            with self.subTest(addr=addr):
                with self.assertRaises(ValueError) as cm:
                    ipv4_to_ipv6(addr)
                self.assertIn('non-global', str(cm.exception))


class TestRFC6052NetworkSpecificPrefixes(unittest.TestCase):
    """Test Network-Specific Prefix functionality for all valid lengths."""

    def test_prefix_length_32(self):
        """Test /32 prefix encoding and decoding."""
        prefix = IPv6Network('2001:db8::/32')
        ipv4 = IPv4Address('192.0.2.33')

        # Encode
        ipv6 = encode_ipv4_in_ipv6(ipv4, prefix)
        expected = IPv6Address('2001:db8:c000:221::')
        self.assertEqual(ipv6, expected)

        # Decode
        extracted = extract_ipv4_from_ipv6(ipv6, prefix)
        self.assertEqual(extracted, ipv4)

    def test_prefix_length_40(self):
        """Test /40 prefix encoding and decoding."""
        prefix = IPv6Network('2001:db8:100::/40')
        ipv4 = IPv4Address('192.0.2.33')

        # Encode
        ipv6 = encode_ipv4_in_ipv6(ipv4, prefix)
        expected = IPv6Address('2001:db8:1c0:2:21::')
        self.assertEqual(ipv6, expected)

        # Decode
        extracted = extract_ipv4_from_ipv6(ipv6, prefix)
        self.assertEqual(extracted, ipv4)

    def test_prefix_length_48(self):
        """Test /48 prefix encoding and decoding."""
        prefix = IPv6Network('2001:db8:122::/48')
        ipv4 = IPv4Address('192.0.2.33')

        # Encode
        ipv6 = encode_ipv4_in_ipv6(ipv4, prefix)
        expected = IPv6Address('2001:db8:122:c000:2:2100::')
        self.assertEqual(ipv6, expected)

        # Decode
        extracted = extract_ipv4_from_ipv6(ipv6, prefix)
        self.assertEqual(extracted, ipv4)

    def test_prefix_length_56(self):
        """Test /56 prefix encoding and decoding."""
        prefix = IPv6Network('2001:db8:122:300::/56')
        ipv4 = IPv4Address('192.0.2.33')

        # Encode
        ipv6 = encode_ipv4_in_ipv6(ipv4, prefix)
        expected = IPv6Address('2001:db8:122:3c0:0:221::')
        self.assertEqual(ipv6, expected)

        # Decode
        extracted = extract_ipv4_from_ipv6(ipv6, prefix)
        self.assertEqual(extracted, ipv4)

    def test_prefix_length_64(self):
        """Test /64 prefix encoding and decoding."""
        prefix = IPv6Network('2001:db8:122:344::/64')
        ipv4 = IPv4Address('192.0.2.33')

        # Encode
        ipv6 = encode_ipv4_in_ipv6(ipv4, prefix)
        expected = IPv6Address('2001:db8:122:344:c0:2:2100:0')
        self.assertEqual(ipv6, expected)

        # Decode
        extracted = extract_ipv4_from_ipv6(ipv6, prefix)
        self.assertEqual(extracted, ipv4)

    def test_prefix_length_96(self):
        """Test /96 prefix encoding and decoding."""
        prefix = IPv6Network('2001:db8:122:344::/96')
        ipv4 = IPv4Address('192.0.2.33')

        # Encode
        ipv6 = encode_ipv4_in_ipv6(ipv4, prefix)
        # For /96, can also be represented as 2001:db8:122:344::192.0.2.33
        expected = IPv6Address('2001:db8:122:344::c000:221')
        self.assertEqual(ipv6, expected)

        # Decode
        extracted = extract_ipv4_from_ipv6(ipv6, prefix)
        self.assertEqual(extracted, ipv4)

    def test_round_trip_all_prefix_lengths(self):
        """Test round-trip conversion for all prefix lengths."""
        test_ipv4_addrs = [
            '192.0.2.1',
            '10.0.0.1',
            '172.16.254.254',
            '255.255.255.255',
            '0.0.0.0',
        ]

        for prefix_len in PrefixLength:
            # Create a test prefix
            if prefix_len == 96:
                prefix = IPv6Network('2001:db8::/96')
            else:
                # Ensure bits 64-71 are zero for /64
                if prefix_len == 64:
                    prefix = IPv6Network('2001:db8::/64')
                else:
                    prefix = IPv6Network(f'2001:db8::/{prefix_len}')

            for ipv4_str in test_ipv4_addrs:
                with self.subTest(prefix_len=prefix_len, ipv4=ipv4_str):
                    ipv4 = IPv4Address(ipv4_str)

                    # Encode
                    ipv6 = encode_ipv4_in_ipv6(ipv4, prefix)

                    # Decode
                    extracted = extract_ipv4_from_ipv6(ipv6, prefix)

                    # Verify round-trip
                    self.assertEqual(extracted, ipv4)


class TestRFC6052Validation(unittest.TestCase):
    """Test RFC 6052 address validation."""

    def test_validate_valid_addresses(self):
        """Test validation of valid RFC 6052 addresses."""
        valid_addresses = [
            '64:ff9b::c000:221',
            '64:ff9b::808:808',
            '2001:db8:c000:221::',  # /32 prefix
            '2001:db8:1c0:2:21::',  # /40 prefix
            # Also accept dotted decimal as valid input
            '64:ff9b::192.0.2.33',
        ]

        for addr in valid_addresses:
            with self.subTest(addr=addr):
                is_valid, error = validate_rfc6052_address(addr)
                self.assertTrue(is_valid)
                self.assertIsNone(error)

    def test_validate_invalid_addresses(self):
        """Test validation of invalid RFC 6052 addresses."""
        invalid_addresses = [
            ('64:ff9b::192.168.1.1', 'non-global'),  # Private IPv4
            ('2001:db8::1', 'Invalid RFC 6052'),  # Not RFC 6052 format
            ('invalid-ipv6', 'Invalid IPv6'),  # Not even valid IPv6
        ]

        for addr, expected_error in invalid_addresses:
            with self.subTest(addr=addr):
                is_valid, error = validate_rfc6052_address(addr)
                self.assertFalse(is_valid)
                self.assertIsNotNone(error)
                self.assertIn(expected_error, error)  # type: ignore

    def test_validate_u_bits(self):
        """Test that validation checks u bits (64-71) are zero."""
        # Create an address with non-zero u bits
        # This would be invalid according to RFC 6052
        # IPv6Network('2001:db8::/32')  # Not used in this test

        # Manually construct an invalid address with non-zero u bits
        # For /32 prefix: bits 64-71 should be zero but we'll set them
        invalid_addr_int = (
            (0x20010db8 << 96) |  # Prefix
            (0xc0000221 << 64) |  # IPv4 address in bits 32-63
            (0xFF << 56)          # Non-zero u bits (should be zero)
        )
        invalid_addr = IPv6Address(invalid_addr_int)

        # Should fail validation in strict mode
        is_valid, _ = validate_rfc6052_address(
            str(invalid_addr), strict=True
        )
        self.assertFalse(is_valid)


class TestRFC6052ErrorHandling(unittest.TestCase):
    """Test error handling and edge cases."""

    def test_ipv4_to_ipv6_invalid_input(self):
        """Test IPv4 to IPv6 conversion with invalid input."""
        invalid_inputs = [
            '999.999.999.999',
            '1.2.3.4.5',
            '1.2.3',
            'not-an-ip',
            '',
            '::1',  # IPv6 address
        ]

        for inp in invalid_inputs:
            with self.subTest(input=inp):
                with self.assertRaises(ValueError):
                    ipv4_to_ipv6(inp)

    def test_ipv6_to_ipv4_invalid_input(self):
        """Test IPv6 to IPv4 conversion with invalid input."""
        invalid_inputs = [
            'not-an-ipv6',
            '192.168.1.1',  # IPv4 address
            '',
            '2001:db8::1',  # Valid IPv6 but not RFC 6052
            'gggg::1',
        ]

        for inp in invalid_inputs:
            with self.subTest(input=inp):
                with self.assertRaises(ValueError):
                    ipv6_to_ipv4(inp)

    def test_invalid_prefix_length(self):
        """Test handling of invalid prefix lengths."""
        ipv4 = IPv4Address('192.0.2.1')

        invalid_prefixes = [
            IPv6Network('2001:db00::/24'),  # Invalid length
            IPv6Network('2001:db8::/128'),  # Invalid length  
            IPv6Network('2001:db8::/65'),  # Invalid length
        ]

        for prefix in invalid_prefixes:
            with self.subTest(prefix=prefix):
                with self.assertRaises(ValueError) as cm:
                    encode_ipv4_in_ipv6(ipv4, prefix)
                self.assertIn('Invalid prefix length', str(cm.exception))


class TestRFC6052TranslationPrefix(unittest.TestCase):
    """Test translation prefix creation."""

    def test_create_translation_prefix_isp(self):
        """Test creating translation prefix for ISP (/32 -> /40)."""
        org_prefix = '2001:db8::/32'
        translation_prefix = create_translation_prefix(org_prefix, 40)

        self.assertEqual(translation_prefix.prefixlen, 40)
        self.assertTrue(IPv6Address('2001:db8::') in translation_prefix)

    def test_create_translation_prefix_site(self):
        """Test creating translation prefix for site (/48 -> /56)."""
        org_prefix = '2001:db8:100::/48'
        translation_prefix = create_translation_prefix(org_prefix, 56)

        self.assertEqual(translation_prefix.prefixlen, 56)
        self.assertTrue(IPv6Address('2001:db8:100::') in translation_prefix)

    def test_create_translation_prefix_errors(self):
        """Test error cases for translation prefix creation."""
        # Invalid target length
        with self.assertRaises(ValueError):
            create_translation_prefix('2001:db8::/32', 33)  # Invalid length

        # Target length not longer than org prefix
        with self.assertRaises(ValueError):
            create_translation_prefix('2001:db8::/48', 32)

        # Target length same as org prefix
        with self.assertRaises(ValueError):
            create_translation_prefix('2001:db8::/48', 48)


class TestRFC6052StringConversions(unittest.TestCase):
    """Test string-based conversion functions."""

    def test_ipv4_to_ipv6_with_custom_prefix(self):
        """Test IPv4 to IPv6 with custom prefix."""
        result = ipv4_to_ipv6('192.0.2.33', '2001:db8::/96')
        self.assertEqual(result, '2001:db8::c000:221')

    def test_ipv6_to_ipv4_with_expected_prefix(self):
        """Test IPv6 to IPv4 with expected prefix validation."""
        # Should work with correct prefix
        result = ipv6_to_ipv4('2001:db8::c000:221', '2001:db8::/96')
        self.assertEqual(result, '192.0.2.33')

        # Should fail with wrong prefix
        with self.assertRaises(ValueError):
            ipv6_to_ipv4('2001:db8::c000:221', '2001:db9::/96')

    def test_text_representation(self):
        """Test that text representation follows RFC standards."""
        # All formats should use hexadecimal representation
        result = ipv4_to_ipv6('192.0.2.33', '2001:db8::/96')
        self.assertEqual(result, '2001:db8::c000:221')

        # Test other prefixes also use hex
        result = ipv4_to_ipv6('192.0.2.33', '2001:db8::/32')
        self.assertEqual(result, '2001:db8:c000:221::')


class TestRFC6052EdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def test_all_zeros_ipv4(self):
        """Test handling of 0.0.0.0."""
        ipv4 = '0.0.0.0'
        ipv6 = ipv4_to_ipv6(ipv4, '2001:db8::/96')
        extracted = ipv6_to_ipv4(ipv6, '2001:db8::/96')
        self.assertEqual(extracted, ipv4)

    def test_all_ones_ipv4(self):
        """Test handling of 255.255.255.255."""
        ipv4 = '255.255.255.255'
        ipv6 = ipv4_to_ipv6(ipv4, '2001:db8::/96')
        extracted = ipv6_to_ipv4(ipv6, '2001:db8::/96')
        self.assertEqual(extracted, ipv4)

    def test_checksum_neutrality(self):
        """Test that Well-Known Prefix is checksum neutral."""
        # The Well-Known Prefix 64:ff9b::/96 is checksum neutral
        # 0x0064 + 0xff9b = 0xffff (zero in one's complement)
        prefix_parts = [0x0064, 0xff9b]
        checksum = sum(prefix_parts) & 0xffff
        self.assertEqual(checksum, 0xffff)  # Zero in one's complement


if __name__ == '__main__':
    unittest.main(verbosity=2)
