# rfc6052

A Python implementation of RFC 6052, providing algorithmic translation between IPv4 and IPv6 addresses for use in IPv4/IPv6 translation scenarios.

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![RFC](https://img.shields.io/badge/RFC-6052-green.svg)](https://datatracker.ietf.org/doc/html/rfc6052)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## What is RFC 6052?

RFC 6052 defines a standard method for embedding IPv4 addresses within IPv6 addresses, enabling seamless communication between IPv4 and IPv6 networks. According to [the RFC's abstract](https://datatracker.ietf.org/doc/html/rfc6052):

> This document discusses the algorithmic translation of an IPv6 address to a corresponding IPv4 address, and vice versa, using only statically configured information. It defines a well-known prefix for use in algorithmic translations, while allowing organizations to also use network-specific prefixes when appropriate.

### Key Features

- **Well-Known Prefix**: `64:ff9b::/96` for general use
- **Network-Specific Prefixes**: Support for organizational prefixes with lengths of 32, 40, 48, 56, 64, or 96 bits
- **Bidirectional Translation**: Convert between IPv4 and IPv6 addresses
- **Validation**: Ensure addresses comply with RFC 6052 requirements
- **Text Representation**: Proper formatting including dotted-decimal notation for /96 prefixes

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/rfc6052.git
cd rfc6052

# Install in development mode
pip install -e .

# Or copy the module directly
cp rfc6052.py /your/project/directory/
```

## Usage

### Command Line Interface

#### Basic Translation

```bash
# IPv4 to IPv6 using Well-Known Prefix (default)
$ python3 rfc6052.py 192.0.2.33
64:ff9b::c000:221

# IPv6 to IPv4
$ python3 rfc6052.py 64:ff9b::c000:221
192.0.2.33

# Also accepts dotted decimal notation as input
$ python3 rfc6052.py 64:ff9b::192.0.2.33
192.0.2.33

# Using custom Network-Specific Prefix
$ python3 rfc6052.py 192.0.2.33 --prefix 2001:db8::/96
2001:db8::c000:221

# Different prefix lengths
$ python3 rfc6052.py 192.0.2.33 --prefix 2001:db8::/32
2001:db8:c000:221::
```

### Python Module Usage

#### Basic Translation

```python
import rfc6052

# IPv4 to IPv6 translation using Well-Known Prefix
ipv6_addr = rfc6052.ipv4_to_ipv6('192.0.2.33')
print(ipv6_addr)  # 64:ff9b::c000:221

# IPv6 to IPv4 translation
ipv4_addr = rfc6052.ipv6_to_ipv4('64:ff9b::c000:221')
print(ipv4_addr)  # 192.0.2.33

# Also accepts dotted decimal notation as input
ipv4_addr = rfc6052.ipv6_to_ipv4('64:ff9b::192.0.2.33')
print(ipv4_addr)  # 192.0.2.33

# Using custom prefix
ipv6_addr = rfc6052.ipv4_to_ipv6('10.0.0.1', prefix='2001:db8::/96')
print(ipv6_addr)  # 2001:db8::a00:1
```

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
python3 test_rfc6052.py

# Run with verbose output
python3 test_rfc6052.py -v

# Run specific test class
python3 -m unittest test_rfc6052.TestRFC6052WellKnownPrefix
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.