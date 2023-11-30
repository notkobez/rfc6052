from ipaddress import ip_address, IPv4Address
from typing import List

INVALID_IPV4_ERR: str = 'invalid IPv4 address: \'{}\''

def ipv4_to_ipv6(ipv4_address: str) -> str:
    try:
        ip: IPv4Address = ip_address(ipv4_address)
    except ValueError as ve:
        raise ValueError(INVALID_IPV4_ERR.format(ipv4_address))
    
    if(type(ip) != IPv4Address):
        raise ValueError(INVALID_IPV4_ERR.format(ipv4_address))
         
    octets: List[int] = list(map(int, ipv4_address.split('.')))
    return '64:ff9b::{:02x}{:02x}:{:02x}{:02x}'.format(*octets)