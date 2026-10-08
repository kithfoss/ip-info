# NOTES — ip-info

**Week 40 — seeded and built 2026-08-24**

## Why this tool

Every developer eventually runs `ping 192.168.1.1` and wonders "which RFC 1918 block is that again?" or checks an IP from a log and needs to know if it's public or private without opening a browser. `ipaddress` from stdlib has everything needed — this just makes it accessible as a command.

Previous tools in the queue were exhausted (43 shipped). `ip-info` is a fresh seed.

## Design decisions

**`ipaddress` stdlib is sufficient.** IPv4Address/IPv6Address/ip_network give is_private, is_global, is_loopback, is_link_local, is_multicast. The harder part is mapping known ranges to human labels (RFC citations, documentation block names, CGNAT, IPv4-mapped).

**Two-layer classification.** First check known special ranges (documentation, shared, IPv4-mapped) which the stdlib `.is_private` would lump with generic "private". Then fall back to stdlib properties. This avoids "198.51.100.5 → private" which is technically correct but unhelpful.

**CIDR /31 and /32.** /31 has 2 usable (RFC 3021 point-to-point), /32 has 1. Handled without subtracting 2 blindly.

**No live lookups.** Geolocation, ASN lookup, and reverse DNS are all left out. The tool answers "what kind of address is this?" not "whose address is this?" That's a different scope.

**JSON single vs array.** Single input → single object. Multiple → array. Matches what `jq` users expect.

## Test coverage (45 tests)

- IPv4: RFC 1918 (all three blocks), public, loopback, link-local, multicast, all three TEST-NET ranges, shared (CGNAT)
- IPv6: loopback, link-local, multicast, unique local, documentation, global, IPv4-mapped
- CIDR: host count, broadcast, /31, /32, IPv6, documentation
- JSON: address, network, public, multiple, error
- Multiple: two valid, mixed valid/invalid
- Stdin: single, multiple, CIDR
- Exit codes: 0 on success, 1 on any error, 0 on no args

## What works

Everything: single addresses, CIDR blocks, multiple inputs, stdin, --json, IPv4 + IPv6, special range labels.

## Limitations documented

- No geolocation/whois
- IPv4-mapped shown in canonical IPv6 form

## Status

v0.1.0 — complete, 45 tests passing, ready to ship.
