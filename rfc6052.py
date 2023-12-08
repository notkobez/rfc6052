import argparse

from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import List

INVALID_IP_ERR: str = 'invalid IPv{} address: \'{}\''
IPv4_VERSION: int = 4
IPv6_VERSION: int = 6


def ipv4_to_ipv6(ipv4_address: str) -> str:
    try:
        ip: IPv4Address = ip_address(ipv4_address)
    except ValueError:
        raise ValueError(INVALID_IP_ERR.format(IPv4_VERSION, ipv4_address))

    if not isinstance(ip, IPv4Address):
        raise ValueError(INVALID_IP_ERR.format(IPv4_VERSION, ipv4_address))

    octets: List[int] = list(map(int, ipv4_address.split('.')))
    return '64:ff9b::{:02x}{:02x}:{:02x}{:02x}'.format(*octets)


def ipv6_to_ipv4(ipv6_address: str) -> str:
    try:
        ip: IPv6Address = ip_address(ipv6_address)
    except ValueError:
        raise ValueError(INVALID_IP_ERR.format(IPv6_VERSION, ipv6_address))

    if not isinstance(ip, IPv6Address):
        raise ValueError(INVALID_IP_ERR.format(IPv6_VERSION, ipv6_address))

    if not ipv6_address.startswith('64:ff9b::'):
        raise ValueError(
            'invalid RFC 6052 IPv6 address: \'{}\''.format(ipv6_address)
        )

    hextets: List[str] = list(map(str, ipv6_address.split(':')[-2:]))
    return '{}.{}.{}.{}'.format(
        int(hextets[0][0:2], 16), 
        int(hextets[0][2:4], 16), 
        int(hextets[1][0:2], 16), 
        int(hextets[1][2:4], 16)
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip")

    args = parser.parse_args()

    ip: str = args.ip
    if "." in ip:
        print(ipv4_to_ipv6(ipv4_address=ip))
    elif ":" in ip:
        print(ipv6_to_ipv4(ipv6_address=ip))
