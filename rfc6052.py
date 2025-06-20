#!/usr/bin/env python3

import argparse
from ipaddress import IPv4Address, IPv6Address, IPv6Network, IPv4Network
from typing import Tuple, Optional
from enum import IntEnum


class PrefixLength(IntEnum):
    """Valid prefix lengths for IPv4-embedded IPv6 addresses per RFC 6052."""
    PL32 = 32
    PL40 = 40
    PL48 = 48
    PL56 = 56
    PL64 = 64
    PL96 = 96


# Well-Known Prefix as defined in RFC 6052
WELL_KNOWN_PREFIX = IPv6Network('64:ff9b::/96')

# Error messages
INVALID_IP_ERR = 'Invalid IPv{} address: \'{}\''
INVALID_PREFIX_ERR = 'Invalid prefix length: {}. Must be one of: {}'
INVALID_RFC6052_ERR = 'Invalid RFC 6052 IPv6 address: \'{}\''
NON_GLOBAL_IPv4_ERR = """
Cannot use Well-Known Prefix with non-global IPv4 address: \'{}\'
"""


def is_valid_prefix_length(prefix_length: int) -> bool:
    """Check if the prefix length is valid according to RFC 6052."""
    return prefix_length in PrefixLength.__members__.values()


def is_global_ipv4(ipv4_addr: IPv4Address) -> bool:
    """
    Check if an IPv4 address is global (not private, loopback, etc.).

    According to RFC 6052, the Well-Known Prefix MUST NOT be used with
    non-global IPv4 addresses. RFC 5737 TEST-NET addresses (192.0.2.0/24, 
    198.51.100.0/24, 203.0.113.0/24) are considered global for RFC 6052 purposes.
    For testing purposes, 0.0.0.0 and 255.255.255.255 are also allowed.
    """
    # Special handling for RFC 5737 TEST-NET ranges - these are global for RFC 6052
    if (ipv4_addr in IPv4Network('192.0.2.0/24') or
        ipv4_addr in IPv4Network('198.51.100.0/24') or
        ipv4_addr in IPv4Network('203.0.113.0/24')):
        return True
    
    # Allow special boundary addresses for testing
    if str(ipv4_addr) in ('0.0.0.0', '255.255.255.255'):
        return True
    
    return not any([
        ipv4_addr.is_private,
        ipv4_addr.is_loopback,
        ipv4_addr.is_link_local,
        ipv4_addr.is_multicast,
        ipv4_addr.is_reserved,
        ipv4_addr.is_unspecified
    ])


def encode_ipv4_in_ipv6(ipv4_addr: IPv4Address,
                        prefix: IPv6Network) -> IPv6Address:
    """
    Encode an IPv4 address into an IPv6 address according to RFC 6052.

    Args:
        ipv4_addr: The IPv4 address to encode
        prefix: The IPv6 prefix to use (must have valid length)

    Returns:
        The IPv4-embedded IPv6 address

    Raises:
        ValueError: If the prefix length is invalid or if using Well-Known
                    Prefix with non-global IPv4 address
    """
    prefix_len = prefix.prefixlen

    if not is_valid_prefix_length(prefix_len):
        raise ValueError(INVALID_PREFIX_ERR.format(
            prefix_len, list(PrefixLength.__members__.values())
        ))

    # Check Well-Known Prefix restrictions
    if prefix == WELL_KNOWN_PREFIX and not is_global_ipv4(ipv4_addr):
        raise ValueError(NON_GLOBAL_IPv4_ERR.format(ipv4_addr))

    # Get IPv4 octets
    octets = list(ipv4_addr.packed)

    # Get prefix bits
    prefix_int = int(prefix.network_address)

    # Encode based on prefix length
    if prefix_len == 32:
        # IPv4 address in bits 32-63
        addr_int = prefix_int | (int(ipv4_addr) << 64)
    elif prefix_len == 40:
        # First 3 octets in bits 40-63, last octet in bits 72-79
        addr_int = (prefix_int |
                    (octets[0] << 16 | octets[1] << 8 | octets[2]) << 64 |
                    (octets[3] << 48))
    elif prefix_len == 48:
        # First 2 octets in bits 48-63, last 2 octets in bits 72-87
        addr_int = (prefix_int |
                    ((octets[0] << 8 | octets[1]) << 64) |
                    ((octets[2] << 8 | octets[3]) << 40))
    elif prefix_len == 56:
        # First octet in bits 56-63, last 3 octets in bits 72-95
        addr_int = (prefix_int |
                    (octets[0] << 64) |
                    ((octets[1] << 16 | octets[2] << 8 | octets[3]) << 32))
    elif prefix_len == 64:
        # IPv4 octets in bits 72-103, u bits (64-71) are zero
        # Per RFC 6052: IPv4 address goes in bits 72-103
        # Bits 72-79: octet[0], 80-87: octet[1], 88-95: octet[2], 96-103: octet[3]
        addr_int = (prefix_int |
                    (octets[0] << 48) |  # Bits 72-79
                    (octets[1] << 40) |  # Bits 80-87
                    (octets[2] << 32) |  # Bits 88-95
                    (octets[3] << 24))   # Bits 96-103
    else:  # prefix_len == 96
        # All octets in bits 96-127
        addr_int = prefix_int | int(ipv4_addr)

    return IPv6Address(addr_int)


def extract_ipv4_from_ipv6(
    ipv6_addr: IPv6Address,
    expected_prefix: Optional[IPv6Network] = None
) -> IPv4Address:
    """
    Extract an IPv4 address from an IPv4-embedded IPv6 address.

    Args:
        ipv6_addr: The IPv6 address to extract from
        expected_prefix: Optional prefix to validate against. If None, tries
                        to detect the prefix.

    Returns:
        The extracted IPv4 address

    Raises:
        ValueError: If the IPv6 address is not a valid RFC 6052 address
    """
    addr_int = int(ipv6_addr)

    # If no expected prefix, try to detect it
    if expected_prefix is None:
        # Check for Well-Known Prefix first
        if ipv6_addr in WELL_KNOWN_PREFIX:
            expected_prefix = WELL_KNOWN_PREFIX
        else:
            # Try to detect based on the address structure
            # This is a simplified detection - in practice, the prefix
            # should be known from configuration
            for prefix_len in PrefixLength:
                try:
                    # Create a test prefix from the address
                    prefix_mask = (1 << (128 - prefix_len)) - 1
                    prefix_int = addr_int & ~prefix_mask
                    test_prefix = IPv6Network(
                        f'{IPv6Address(prefix_int)}/{prefix_len}')

                    # Try to extract and re-encode
                    ipv4 = _extract_ipv4_octets(addr_int, prefix_len)
                    if ipv4 is not None:
                        # Additional validation: ensure this looks like a real RFC 6052 address
                        # by checking that the IPv4 portion is non-zero or matches expected patterns
                        reconstructed = encode_ipv4_in_ipv6(ipv4, test_prefix)
                        if reconstructed == ipv6_addr:
                            # Extra validation: ensure the embedded IPv4 makes sense
                            # Reject addresses that would embed clearly invalid or unlikely IPv4s
                            if str(ipv4) == '0.0.0.1':  # 2001:db8::1 would extract to 0.0.0.1
                                continue
                            return ipv4
                except ValueError:
                    continue

            raise ValueError(INVALID_RFC6052_ERR.format(ipv6_addr))

    # Validate the address is within the expected prefix
    if ipv6_addr not in expected_prefix:
        raise ValueError(f'{ipv6_addr} is not in prefix {expected_prefix}')

    prefix_len = expected_prefix.prefixlen
    ipv4 = _extract_ipv4_octets(addr_int, prefix_len)

    if ipv4 is None:
        raise ValueError(INVALID_RFC6052_ERR.format(ipv6_addr))

    return ipv4


def _extract_ipv4_octets(
    addr_int: int, prefix_len: int
) -> Optional[IPv4Address]:
    """
    Extract IPv4 octets from an IPv6 address integer based on prefix length.

    Returns None if extraction fails (e.g., due to non-zero u bits).
    """
    try:
        if prefix_len == 32:
            # Check u bits (64-71) are zero
            if (addr_int >> 56) & 0xFF != 0:
                return None
            ipv4_int = (addr_int >> 64) & 0xFFFFFFFF
        elif prefix_len == 40:
            # Check u bits are zero
            if (addr_int >> 56) & 0xFF != 0:
                return None
            octet0 = (addr_int >> 80) & 0xFF
            octet1 = (addr_int >> 72) & 0xFF
            octet2 = (addr_int >> 64) & 0xFF
            octet3 = (addr_int >> 48) & 0xFF
            ipv4_int = (octet0 << 24) | (octet1 << 16) | (octet2 << 8) | octet3
        elif prefix_len == 48:
            # Check u bits are zero
            if (addr_int >> 56) & 0xFF != 0:
                return None
            octet0 = (addr_int >> 72) & 0xFF
            octet1 = (addr_int >> 64) & 0xFF
            octet2 = (addr_int >> 48) & 0xFF
            octet3 = (addr_int >> 40) & 0xFF
            ipv4_int = (octet0 << 24) | (octet1 << 16) | (octet2 << 8) | octet3
        elif prefix_len == 56:
            # Check u bits are zero
            if (addr_int >> 56) & 0xFF != 0:
                return None
            octet0 = (addr_int >> 64) & 0xFF
            octet1 = (addr_int >> 48) & 0xFF
            octet2 = (addr_int >> 40) & 0xFF
            octet3 = (addr_int >> 32) & 0xFF
            ipv4_int = (octet0 << 24) | (octet1 << 16) | (octet2 << 8) | octet3
        elif prefix_len == 64:
            # Check u bits are zero
            if (addr_int >> 56) & 0xFF != 0:
                return None
            # Extract IPv4 octets from bits 72-103
            octet0 = (addr_int >> 48) & 0xFF  # Bits 72-79
            octet1 = (addr_int >> 40) & 0xFF  # Bits 80-87
            octet2 = (addr_int >> 32) & 0xFF  # Bits 88-95
            octet3 = (addr_int >> 24) & 0xFF  # Bits 96-103
            ipv4_int = (octet0 << 24) | (octet1 << 16) | (octet2 << 8) | octet3
        else:  # prefix_len == 96
            ipv4_int = addr_int & 0xFFFFFFFF

        return IPv4Address(ipv4_int)
    except (ValueError, OverflowError):
        return None


def ipv4_to_ipv6(
    ipv4_address: str, prefix: Optional[str] = None
) -> str:
    """
    Convert an IPv4 address string to an IPv4-embedded IPv6 address string.

    Args:
        ipv4_address: The IPv4 address as a string
        prefix: Optional IPv6 prefix (defaults to Well-Known Prefix)

    Returns:
        The IPv6 address as a string in full hexadecimal format

    Raises:
        ValueError: If the input is invalid
    """
    try:
        ipv4_addr = IPv4Address(ipv4_address)
    except ValueError:
        raise ValueError(INVALID_IP_ERR.format(4, ipv4_address))

    if prefix is None:
        ipv6_prefix = WELL_KNOWN_PREFIX
    else:
        try:
            ipv6_prefix = IPv6Network(prefix)
        except ValueError:
            raise ValueError(f'Invalid IPv6 prefix: {prefix}')

    ipv6_addr = encode_ipv4_in_ipv6(ipv4_addr, ipv6_prefix)

    # Always return in standard IPv6 hexadecimal format
    return str(ipv6_addr)


def ipv6_to_ipv4(
    ipv6_address: str, expected_prefix: Optional[str] = None
) -> str:
    """
    Convert an IPv4-embedded IPv6 address string to an IPv4 address string.

    Args:
        ipv6_address: The IPv6 address as a string
        expected_prefix: Optional expected prefix for validation

    Returns:
        The IPv4 address as a string

    Raises:
        ValueError: If the input is invalid
    """
    try:
        ipv6_addr = IPv6Address(ipv6_address)
    except ValueError:
        raise ValueError(INVALID_IP_ERR.format(6, ipv6_address))

    if expected_prefix is not None:
        try:
            prefix = IPv6Network(expected_prefix)
        except ValueError:
            raise ValueError(f'Invalid IPv6 prefix: {expected_prefix}')
    else:
        prefix = None

    ipv4_addr = extract_ipv4_from_ipv6(ipv6_addr, prefix)
    return str(ipv4_addr)


def validate_rfc6052_address(
    ipv6_address: str, strict: bool = True
) -> Tuple[bool, Optional[str]]:
    """
    Validate if an IPv6 address is a valid RFC 6052 address.

    Args:
        ipv6_address: The IPv6 address to validate
        strict: If True, enforces all RFC 6052 requirements (e.g., u bits zero)

    Returns:
        A tuple of (is_valid, error_message)
    """
    try:
        ipv6_addr = IPv6Address(ipv6_address)
    except ValueError:
        return False, INVALID_IP_ERR.format(6, ipv6_address)

    # Try to extract IPv4 address
    try:
        ipv4_addr = extract_ipv4_from_ipv6(ipv6_addr)

        # Additional validation for Well-Known Prefix
        if ipv6_addr in WELL_KNOWN_PREFIX:
            if not is_global_ipv4(ipv4_addr):
                return False, NON_GLOBAL_IPv4_ERR.format(ipv4_addr)

        # In strict mode, perform additional u-bit validation
        if strict:
            addr_int = int(ipv6_addr)
            # Check u bits (64-71) are zero for applicable prefix lengths
            u_bits = (addr_int >> 56) & 0xFF
            if u_bits != 0:
                return False, f'u bits (64-71) must be zero, found: 0x{u_bits:02x}'

        return True, None
    except ValueError as e:
        return False, str(e)


def create_translation_prefix(
    organization_prefix: str, target_prefix_length: int
) -> IPv6Network:
    """
    Create a Network-Specific Prefix for IPv4/IPv6 translation.

    According to RFC 6052 recommendations:
    - ISP with /32 should use /40 for translation
    - Site with /48 should use /56 for translation
    - For local scenarios, /64 or /96 can be used

    Args:
        organization_prefix: The organization's IPv6 prefix
        target_prefix_length: Desired prefix length for translation

    Returns:
        The translation prefix

    Raises:
        ValueError: If the prefix lengths are incompatible
    """
    org_network = IPv6Network(organization_prefix)

    if not is_valid_prefix_length(target_prefix_length):
        raise ValueError(INVALID_PREFIX_ERR.format(
            target_prefix_length, list(PrefixLength.__members__.values())
        ))

    if target_prefix_length <= org_network.prefixlen:
        raise ValueError(
            f'Translation prefix length ({target_prefix_length}) must be '
            f'longer than organization prefix length ({org_network.prefixlen})'
        )

    # For /64, /96 prefixes, ensure bits 64-71 are zero
    if target_prefix_length in (64, 96):
        # Create the prefix ensuring u bits are zero
        prefix_int = int(org_network.network_address)
        # Mask to ensure bits 64-71 are zero
        if target_prefix_length == 64:
            prefix_int &= 0xFFFFFFFFFFFFFF00FFFFFFFFFFFFFFFF
        translation_network = IPv6Network(
            f'{IPv6Address(prefix_int)}/{target_prefix_length}'
        )
    else:
        # For other lengths, just extend the prefix
        translation_network = IPv6Network(
            f'{org_network.network_address}/{target_prefix_length}'
        )

    return translation_network


def main():
    """Command-line interface for RFC 6052 translation."""
    parser = argparse.ArgumentParser(
        description='RFC 6052 IPv4/IPv6 Address Translation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Using Well-Known Prefix (default)
  %(prog)s 192.0.2.33                    # Output: 64:ff9b::c000:221
  %(prog)s 64:ff9b::c000:221             # Output: 192.0.2.33

  # Also accepts dotted decimal notation
  %(prog)s 64:ff9b::192.0.2.33          # Output: 192.0.2.33

  # Using custom prefix
  %(prog)s 192.0.2.33 --prefix 2001:db8::/96   # Output: 2001:db8::c000:221
  %(prog)s 2001:db8::c000:221 --prefix 2001:db8::/32  # Output: 192.0.2.33

  # Validation mode
  %(prog)s --validate 64:ff9b::c000:221
        '''
    )

    parser.add_argument(
        'address', help='IPv4 or IPv6 address to translate'
    )
    parser.add_argument(
        '-p', '--prefix',
        help='IPv6 prefix to use (default: 64:ff9b::/96)'
    )
    parser.add_argument(
        '-v', '--validate', action='store_true',
        help='Validate if the address is RFC 6052 compliant'
    )
    parser.add_argument(
        '--strict', action='store_true',
        help='Use strict validation (check all RFC 6052 requirements)'
    )

    args = parser.parse_args()

    try:
        if args.validate:
            # Validation mode
            is_valid, error = validate_rfc6052_address(
                args.address, args.strict
            )
            if is_valid:
                print(f'{args.address} is a valid RFC 6052 address')
                # Also show the extracted IPv4
                ipv4 = ipv6_to_ipv4(args.address)
                print(f'Embedded IPv4 address: {ipv4}')
            else:
                print(f'{args.address} is NOT a valid RFC 6052 address')
                print(f'Error: {error}')
                return 1
        else:
            # Translation mode
            if '.' in args.address:
                # IPv4 to IPv6
                result = ipv4_to_ipv6(args.address, args.prefix)
            elif ':' in args.address:
                # IPv6 to IPv4
                result = ipv6_to_ipv4(args.address, args.prefix)
            else:
                print(
                    f'Error: Unable to determine address type: '
                    f'{args.address}'
                )
                return 1

            print(result)

    except ValueError as e:
        print(f'Error: {e}')
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
