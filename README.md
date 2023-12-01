# rfc6052

## What is RFC 6052

To quote [the RFC's abstract](https://datatracker.ietf.org/doc/html/rfc6052), 

> This document discusses the algorithmic translation of an IPv6 address to a corresponding IPv4 address, and vice versa, using only statically configured information. It defines a well-known prefix for use in algorithmic translations, while allowing organizations to also use network-specific prefixes when appropriate. Algorithmic translation is used in IPv4/IPv6 translators, as well as other types of proxies and gateways (e.g., for DNS) used in IPv4/IPv6 scenarios. [STANDARDS-TRACK]



## Examples
**IPv4 to IPv6 translation**
```
    import rfc6052

    indicators: str = [
        '192.168.1.1',
        '192.168.1.2',
        '192.168.1.3'
    ]

    translated_ips: str = []

    for indicator in indicators:
        try:
            translated_ips.append(rfc6052.ipv4_to_ipv6(indicator))
        except ValueError as ve:
            print(ve)
            continue

    print(translated_ips)
    # ['64:ff9b::c0a8:0101', '64:ff9b::c0a8:0102', '64:ff9b::c0a8:0103']
```

**IPv6 to IPv4 translation**
```
    import rfc6052

    indicators: str = [
        '64:ff9b::c0a8:0101', 
        '64:ff9b::c0a8:0102', 
        '64:ff9b::c0a8:0103'
    ]

    translated_ips: str = []

    for indicator in indicators:
        try:
            translated_ips.append(rfc6052.ipv6_to_ipv4(indicator))
        except ValueError as ve:
            print(ve)
            continue
    
    print(translated_ips)
    # ['192.168.1.1', '192.168.1.2', '192.168.1.3']
```