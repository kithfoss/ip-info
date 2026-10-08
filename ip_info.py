#!/usr/bin/env python3
"""ip-info — classify and describe IP addresses and CIDR blocks."""

import argparse
import ipaddress
import json
import sys


_LABEL_CATEGORY = {
    "TEST-NET-1": "documentation",
    "TEST-NET-2": "documentation",
    "TEST-NET-3": "documentation",
    "RFC 3849": "documentation",
    "RFC 6598": "shared address space",
    "IPv4-mapped": "IPv4-mapped",
    "RFC 6052": "translation",
    "6to4": "tunnel",
    "Teredo": "tunnel",
    "RFC 6666": "discard",
    "class E": "reserved",
}


def _categorize_addr(addr, rfc_label=None):
    # Override for well-known special ranges
    if rfc_label and rfc_label in _LABEL_CATEGORY:
        return [_LABEL_CATEGORY[rfc_label]]

    cats = []
    if addr.is_loopback:
        cats.append("loopback")
    if addr.is_link_local:
        cats.append("link-local")
    if addr.is_multicast:
        cats.append("multicast")
    if addr.is_unspecified:
        cats.append("unspecified")
    if addr.is_private and not cats:
        cats.append("private")
    elif addr.is_global and not cats:
        cats.append("public")
    if not cats:
        cats.append("reserved")
    return cats


def _rfc_label(addr):
    """Return a human-readable scope label for well-known ranges."""
    v4 = isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv4Network))
    if v4:
        a = addr if isinstance(addr, ipaddress.IPv4Address) else addr.network_address
        for net, label in _V4_LABELS:
            if a in net:
                return label
    else:
        a = addr if isinstance(addr, ipaddress.IPv6Address) else addr.network_address
        for net, label in _V6_LABELS:
            if a in net:
                return label
    return None


_V4_LABELS = [
    (ipaddress.ip_network("10.0.0.0/8"), "RFC 1918"),
    (ipaddress.ip_network("172.16.0.0/12"), "RFC 1918"),
    (ipaddress.ip_network("192.168.0.0/16"), "RFC 1918"),
    (ipaddress.ip_network("127.0.0.0/8"), None),
    (ipaddress.ip_network("169.254.0.0/16"), "RFC 3927"),
    (ipaddress.ip_network("100.64.0.0/10"), "RFC 6598"),
    (ipaddress.ip_network("192.0.2.0/24"), "TEST-NET-1"),
    (ipaddress.ip_network("198.51.100.0/24"), "TEST-NET-2"),
    (ipaddress.ip_network("203.0.113.0/24"), "TEST-NET-3"),
    (ipaddress.ip_network("224.0.0.0/4"), "RFC 5771"),
    (ipaddress.ip_network("240.0.0.0/4"), "class E"),
    (ipaddress.ip_network("255.255.255.255/32"), None),
    (ipaddress.ip_network("0.0.0.0/8"), None),
]

_V6_LABELS = [
    (ipaddress.ip_network("::1/128"), None),
    (ipaddress.ip_network("::/128"), None),
    (ipaddress.ip_network("::ffff:0:0/96"), "IPv4-mapped"),
    (ipaddress.ip_network("64:ff9b::/96"), "RFC 6052"),
    (ipaddress.ip_network("fe80::/10"), None),
    (ipaddress.ip_network("fc00::/7"), "RFC 4193"),
    (ipaddress.ip_network("ff00::/8"), None),
    (ipaddress.ip_network("2001:db8::/32"), "RFC 3849"),
    (ipaddress.ip_network("2002::/16"), "6to4"),
    (ipaddress.ip_network("2001::/32"), "Teredo"),
    (ipaddress.ip_network("100::/64"), "RFC 6666"),
]


def analyze(raw: str) -> dict:
    raw = raw.strip()
    if not raw:
        return {"input": raw, "error": "empty input"}

    is_cidr = "/" in raw

    try:
        if is_cidr:
            net = ipaddress.ip_network(raw, strict=False)
            rfc = _rfc_label(net)
            cats = _categorize_addr(net, rfc)

            result = {
                "input": raw,
                "kind": "network",
                "version": net.version,
                "network": str(net),
                "network_address": str(net.network_address),
                "prefixlen": net.prefixlen,
                "num_addresses": net.num_addresses,
                "category": cats[0] if len(cats) == 1 else cats,
                "is_private": net.is_private,
                "is_global": net.is_global,
            }
            if rfc:
                result["rfc"] = rfc

            if net.version == 4:
                result["broadcast"] = str(net.broadcast_address)
                if net.prefixlen <= 30:
                    result["host_min"] = str(net.network_address + 1)
                    result["host_max"] = str(net.broadcast_address - 1)
                    result["num_usable"] = net.num_addresses - 2
                elif net.prefixlen == 31:
                    result["host_min"] = str(net.network_address)
                    result["host_max"] = str(net.broadcast_address)
                    result["num_usable"] = 2
                else:
                    result["num_usable"] = 1
            else:
                result["num_usable"] = net.num_addresses

            return result

        else:
            addr = ipaddress.ip_address(raw)
            rfc = _rfc_label(addr)
            cats = _categorize_addr(addr, rfc)

            result = {
                "input": raw,
                "kind": "address",
                "version": addr.version,
                "address": str(addr),
                "category": cats[0] if len(cats) == 1 else cats,
                "is_private": addr.is_private,
                "is_global": addr.is_global,
                "is_loopback": addr.is_loopback,
                "is_multicast": addr.is_multicast,
                "is_link_local": addr.is_link_local,
            }
            if rfc:
                result["rfc"] = rfc

            if addr.version == 4:
                # Show which RFC 1918 block it belongs to, if any
                for net in [
                    ipaddress.ip_network("10.0.0.0/8"),
                    ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"),
                ]:
                    if addr in net:
                        result["private_block"] = str(net)
                        break

            return result

    except ValueError as e:
        return {"input": raw, "error": str(e)}


def _fmt_addr(info: dict) -> str:
    lines = []
    inp = info.get("input", "")

    if "error" in info:
        return f"{inp}\n  error: {info['error']}"

    version = info.get("version")
    cat = info.get("category")
    if isinstance(cat, list):
        cat_str = ", ".join(cat)
    else:
        cat_str = str(cat)
    rfc = info.get("rfc", "")

    lines.append(info.get("address") or info.get("network") or inp)
    lines.append(f"  version:   IPv{version}")

    if rfc and rfc != cat_str:
        lines.append(f"  category:  {cat_str} ({rfc})")
    else:
        lines.append(f"  category:  {cat_str}")

    # Network-specific extras
    if info.get("kind") == "network":
        lines.append(f"  network:   {info['network_address']}/{info['prefixlen']}")
        if "broadcast" in info:
            lines.append(f"  broadcast: {info['broadcast']}")
        if "host_min" in info:
            lines.append(f"  hosts:     {info['host_min']} – {info['host_max']}  ({info['num_usable']} usable)")
        lines.append(f"  total:     {info['num_addresses']} addresses")

    # Address-specific extras
    if info.get("kind") == "address" and info.get("private_block"):
        lines.append(f"  block:     {info['private_block']}")

    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ip-info",
        description="Classify and describe IP addresses and CIDR blocks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ip-info 192.168.1.1
  ip-info 10.0.0.0/24
  ip-info 8.8.8.8 ::1
  echo "172.16.0.0/12" | ip-info
  ip-info --json 8.8.8.8
""",
    )
    parser.add_argument("addresses", nargs="*", metavar="ADDRESS", help="IP addresses or CIDR blocks to inspect")
    parser.add_argument("--json", action="store_true", dest="as_json", help="output as JSON")
    args = parser.parse_args(argv)

    inputs = list(args.addresses)

    # stdin if no positional args and stdin is piped
    if not inputs and not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                inputs.append(line)

    if not inputs:
        parser.print_help()
        sys.exit(0)

    results = [analyze(inp) for inp in inputs]
    has_error = any("error" in r for r in results)

    if args.as_json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
    else:
        for i, info in enumerate(results):
            if i > 0:
                print()
            print(_fmt_addr(info))

    sys.exit(1 if has_error else 0)


if __name__ == "__main__":
    main()
