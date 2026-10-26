#!/usr/bin/env python3
"""Write small MaxMind DB files for tests: a City database and an ASN database.

They cover only the documentation ranges (RFC 5737), which have no real
location, so the answers are known in advance and cannot be mistaken for
real data: every record says "test" in its database type and description.

    python3 tests/fixtures/geo/make_geo_mmdb.py   # writes the two .mmdb files here

Format: https://maxmind.github.io/MaxMind-DB/ (IPv4 tree, 24-bit records).
"""

import ipaddress
import struct
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILD_EPOCH = 1767225600  # 2026-01-01, fixed so the files are reproducible

CITY = [
    ("203.0.113.0/25", "ID", "Indonesia", "JK", "Jakarta", "Jakarta", "AS"),
    ("203.0.113.128/25", "ID", "Indonesia", "JB", "West Java", "Bandung", "AS"),
    ("198.51.100.0/24", "CN", "China", "BJ", "Beijing", "Beijing", "AS"),
    ("192.0.2.0/24", "US", "United States", "CA", "California", "San Jose", "NA"),
]
ASN = [
    ("203.0.113.0/25", 64500, "Example Telecom ID (test)"),
    ("203.0.113.128/25", 64501, "Example Broadband ID (test)"),
    ("198.51.100.0/24", 64510, "Example Cloud CN (test)"),
    ("192.0.2.0/24", 64496, "Example Hosting US (test)"),
]


# ---- data section encoding -------------------------------------------------

def _ctrl(type_id, size):
    if size < 29:
        size_bits, extra = size, b""
    elif size < 29 + 256:
        size_bits, extra = 29, bytes([size - 29])
    else:
        size_bits, extra = 30, struct.pack(">H", size - 285)
    if type_id <= 7:
        return bytes([(type_id << 5) | size_bits]) + extra
    return bytes([size_bits, type_id - 7]) + extra


def _uint(type_id, n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return _ctrl(type_id, len(b)) + b


def enc(v, kind=None):
    if isinstance(v, str):
        b = v.encode()
        return _ctrl(2, len(b)) + b
    if isinstance(v, bool):
        return _ctrl(14, 1 if v else 0)
    if isinstance(v, int):
        return _uint({"u16": 5, "u64": 9}.get(kind, 6), v)
    if isinstance(v, dict):
        out = _ctrl(7, len(v))
        for k, x in v.items():
            if isinstance(x, tuple):  # (value, kind)
                out += enc(k) + enc(*x)
            else:
                out += enc(k) + enc(x)
        return out
    if isinstance(v, list):
        return _ctrl(11, len(v)) + b"".join(enc(x) for x in v)
    raise TypeError(v)


# ---- search tree --------------------------------------------------------------

def build(records, db_type, description, path):
    data = b""
    root = [None, None]
    for net, value in records:
        n = ipaddress.ip_network(net)
        offset = len(data)
        data += enc(value)
        bits = int(n.network_address)
        node = root
        for i in range(n.prefixlen):
            bit = (bits >> (31 - i)) & 1
            if i == n.prefixlen - 1:
                node[bit] = ("data", offset)
            else:
                if not isinstance(node[bit], list):
                    node[bit] = [None, None]
                node = node[bit]
    # Number the nodes breadth first.
    order, queue = [], [root]
    while queue:
        n = queue.pop(0)
        order.append(n)
        queue += [c for c in n if isinstance(c, list)]
    index = {id(n): i for i, n in enumerate(order)}
    count = len(order)

    def rec(c):
        if c is None:
            return count
        if isinstance(c, list):
            return index[id(c)]
        return count + 16 + c[1]

    tree = b"".join(rec(n[0]).to_bytes(3, "big") + rec(n[1]).to_bytes(3, "big") for n in order)
    meta = enc({
        "binary_format_major_version": (2, "u16"),
        "binary_format_minor_version": (0, "u16"),
        "build_epoch": (BUILD_EPOCH, "u64"),
        "database_type": db_type,
        "description": {"en": description},
        "ip_version": (4, "u16"),
        "languages": ["en"],
        "node_count": count,
        "record_size": (24, "u16"),
    })
    path.write_bytes(tree + bytes(16) + data + b"\xab\xcd\xefMaxMind.com" + meta)
    print(f"wrote {path} ({path.stat().st_size} bytes, {count} nodes)")


def main():
    city = [(net, {
        "city": {"names": {"en": city}},
        "continent": {"code": cont},
        "country": {"iso_code": cc, "names": {"en": cname}},
        "subdivisions": [{"iso_code": sub, "names": {"en": sname}}],
    }) for net, cc, cname, sub, sname, city, cont in CITY]
    build(city, "OpenShield-Test-City", "OpenShield test fixture, documentation ranges only; not real data",
          HERE / "test-city.mmdb")
    asn = [(net, {"autonomous_system_number": num, "autonomous_system_organization": org}) for net, num, org in ASN]
    build(asn, "OpenShield-Test-ASN", "OpenShield test fixture, documentation ranges only; not real data",
          HERE / "test-asn.mmdb")


if __name__ == "__main__":
    main()
