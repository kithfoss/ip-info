# ip-info

Tell me what this IP address is.

Classifies IPv4 and IPv6 addresses and CIDR blocks: private, public, loopback, link-local, multicast, documentation, and more. No external calls — pure stdlib.

## Usage

```
ip-info ADDRESS [ADDRESS ...]
ip-info [--json] ADDRESS
echo "10.0.0.1" | ip-info
```

## Examples

```
$ ip-info 192.168.1.1
192.168.1.1
  version:   IPv4
  category:  private (RFC 1918)
  block:     192.168.0.0/16

$ ip-info 8.8.8.8
8.8.8.8
  version:   IPv4
  category:  public

$ ip-info 10.0.0.0/24
10.0.0.0/24
  version:   IPv4
  category:  private (RFC 1918)
  network:   10.0.0.0/24
  broadcast: 10.0.0.255
  hosts:     10.0.0.1 – 10.0.0.254  (254 usable)
  total:     256 addresses

$ ip-info ::1
::1
  version:   IPv6
  category:  loopback

$ ip-info --json 192.168.1.1
{
  "input": "192.168.1.1",
  "kind": "address",
  "version": 4,
  "address": "192.168.1.1",
  "category": "private",
  "is_private": true,
  "is_global": false,
  "rfc": "RFC 1918",
  "private_block": "192.168.0.0/16",
  ...
}
```

## Flags

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON (single object or array for multiple inputs) |

## Categories

| Category | Examples |
|----------|---------|
| `private` | 10.x, 172.16–31.x, 192.168.x (RFC 1918); fc00::/7 (RFC 4193) |
| `public` | Globally routable addresses |
| `loopback` | 127.0.0.1, ::1 |
| `link-local` | 169.254.x.x (RFC 3927), fe80::/10 |
| `multicast` | 224–239.x.x.x (RFC 5771), ff00::/8 |
| `documentation` | 192.0.2.x, 198.51.100.x, 203.0.113.x, 2001:db8::/32 |
| `shared address space` | 100.64.0.0/10 (RFC 6598, CGNAT) |
| `IPv4-mapped` | ::ffff:0:0/96 |
| `tunnel` | 6to4 (2002::/16), Teredo (2001::/32) |

## Installation

```bash
bash install.sh
```

Creates a symlink at `~/.local/bin/ip-info`.

## Requirements

Python 3.3+, stdlib only (`ipaddress`, `argparse`, `json`).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All inputs parsed successfully |
| 1 | One or more inputs were invalid |

## Limitations

- Does not do live lookups (no geolocation, no whois, no ASN).
- IPv4-mapped IPv6 addresses are displayed in their IPv6 canonical form (e.g. `::ffff:c0a8:101` not `::ffff:192.168.1.1`).
