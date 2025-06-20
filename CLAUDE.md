# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository implements RFC 6052, providing algorithmic translation between IPv4 and IPv6 addresses for NAT64/DNS64 scenarios. It's a single-module Python library with both programmatic API and command-line interface.

## Core Architecture

- **Main Module**: `rfc6052.py` - Single file containing all core functionality
  - Core encoding/decoding functions: `encode_ipv4_in_ipv6()`, `extract_ipv4_from_ipv6()`
  - Public API functions: `ipv4_to_ipv6()`, `ipv6_to_ipv4()`
  - Validation functions: `validate_rfc6052_address()`, `is_global_ipv4()`
  - CLI entry point: `main()` function with argparse
- **Test Suite**: `test_rfc6052.py` - Comprehensive unittest-based test coverage
- **Package Setup**: `setup.py` - Standard setuptools configuration

## Key Concepts

- **Well-Known Prefix**: `64:ff9b::/96` - Default prefix for general use
- **Network-Specific Prefixes**: Support for /32, /40, /48, /56, /64, /96 prefix lengths
- **Global IPv4 Restriction**: Well-Known Prefix can only encode global (public) IPv4 addresses
- **U-bit Validation**: Bits 64-71 must be zero in certain prefix configurations per RFC 6052

## Development Commands

### Testing
```bash
# Run all tests
python3 test_rfc6052.py

# Run with verbose output
python3 test_rfc6052.py -v

# Run specific test class
python3 -m unittest test_rfc6052.TestRFC6052WellKnownPrefix

# Run single test method
python3 -m unittest test_rfc6052.TestRFC6052WellKnownPrefix.test_ipv4_to_ipv6_well_known
```

### Installation and Setup
```bash
# Install in development mode
pip install -e .

# Install package
pip install .
```

### CLI Usage Examples
```bash
# IPv4 to IPv6 using Well-Known Prefix
python3 rfc6052.py 192.0.2.33

# IPv6 to IPv4
python3 rfc6052.py 64:ff9b::c000:221

# Using custom prefix
python3 rfc6052.py 192.0.2.33 --prefix 2001:db8::/96

# Validation mode
python3 rfc6052.py --validate 64:ff9b::c000:221
```

## Code Organization

The codebase follows these patterns:
- Error messages are defined as module-level constants (e.g., `INVALID_IP_ERR`)
- Prefix length validation uses `PrefixLength` IntEnum
- IPv4/IPv6 address objects from `ipaddress` module are used throughout
- Functions return `IPv4Address`/`IPv6Address` objects internally, string conversion happens at API boundaries
- Comprehensive error handling with descriptive ValueError messages

## Testing Strategy

Tests are organized into logical classes:
- `TestRFC6052BasicFunctions`: Utility function tests
- `TestRFC6052WellKnownPrefix`: Well-Known Prefix specific tests
- `TestRFC6052NetworkSpecificPrefixes`: Tests for all prefix lengths
- `TestRFC6052Validation`: Address validation tests
- `TestRFC6052ErrorHandling`: Invalid input handling
- `TestRFC6052EdgeCases`: Boundary conditions and special cases

Each prefix length (/32, /40, /48, /56, /64, /96) has dedicated round-trip tests to ensure encoding/decoding consistency.