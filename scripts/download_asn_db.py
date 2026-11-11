#!/usr/bin/env python3
"""Build asn.db, the IP-to-ASN range table Botlocker reads, from iptoasn.com.

The source is free to use and redistribute, and needs no account. The script
downloads the IPv4 and IPv6 tables, drops ranges that are not announced (ASN 0),
merges them, and writes one tab-separated file:

    range_start    range_end    AS number    AS description

Point the proxy at the result with `asn_db = "/path/to/asn.db"` in botlocker.toml.

Each file is fully checked before anything is replaced. A failed download
leaves the existing asn.db in place.

Usage:
    python3 scripts/download_asn_db.py                    # writes data/asn/asn.db
    python3 scripts/download_asn_db.py --dest /var/lib/botlocker/asn
    python3 scripts/download_asn_db.py --max-age-days 7   # skip if asn.db is fresh
    python3 scripts/download_asn_db.py --keep-gz          # also keep the source .gz files

Only the standard library is needed.
"""

import argparse
import gzip
import ipaddress
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = "https://iptoasn.com/data"
SOURCES = {"v4": "ip2asn-v4.tsv.gz", "v6": "ip2asn-v6.tsv.gz"}
OUTPUT = "asn.db"
USER_AGENT = "botlocker-asn-download/1.0"
MIN_BYTES = 1024  # a real table is megabytes; anything this small is an error page


def fresh_enough(path: Path, max_age_days: float) -> bool:
    if not path.exists():
        return False
    age_days = (time.time() - path.stat().st_mtime) / 86400
    return age_days < max_age_days


def fetch(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def parse_table(data: bytes, name: str):
    """Returns (start, end, asn, description) rows for announced ranges.

    Raises ValueError if the download is not a gzipped iptoasn table.
    """
    if len(data) < MIN_BYTES:
        raise ValueError(f"{name}: only {len(data)} bytes, too small for a table")
    try:
        text = gzip.decompress(data).decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ValueError(f"{name}: not a gzipped text table ({e})") from e

    rows = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 5:
            raise ValueError(f"{name} line {number}: expected 5 columns, found {len(fields)}")
        start_s, end_s, asn_s, _, description = fields
        try:
            start = ipaddress.ip_address(start_s)
            end = ipaddress.ip_address(end_s)
            asn = int(asn_s)
        except ValueError as e:
            raise ValueError(f"{name} line {number}: {e}") from e
        if asn == 0:
            continue
        if start.version != end.version or int(start) > int(end):
            raise ValueError(f"{name} line {number}: bad range {start_s}-{end_s}")
        rows.append((int(start), int(end), start.version, asn, description))
    if not rows:
        raise ValueError(f"{name}: no announced ranges found")
    return rows


def render(rows) -> str:
    """Sorted 4-column lines, IPv4 first, then IPv6."""
    out = []
    for start, end, _, asn, description in sorted(rows, key=lambda r: (r[2], r[0])):
        out.append(
            f"{ipaddress.ip_address(start)}\t{ipaddress.ip_address(end)}\t{asn}\t{description}\n"
        )
    return "".join(out)


def write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dest", default="data/asn", type=Path,
                        help="directory to write asn.db into (default: data/asn)")
    parser.add_argument("--max-age-days", type=float, default=0.0,
                        help="skip if asn.db is newer than this many days (default: always build)")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="per-download timeout in seconds (default: 120)")
    parser.add_argument("--keep-gz", action="store_true",
                        help="also save the downloaded .gz tables next to asn.db")
    args = parser.parse_args()

    args.dest.mkdir(parents=True, exist_ok=True)
    target = args.dest / OUTPUT
    if fresh_enough(target, args.max_age_days):
        print(f"skip   {OUTPUT} (newer than {args.max_age_days} days)")
        return 0

    rows = []
    for name in SOURCES.values():
        url = f"{BASE_URL}/{name}"
        try:
            data = fetch(url, args.timeout)
            table = parse_table(data, name)
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"FAIL   {name}: {e}", file=sys.stderr)
            print(f"{OUTPUT} was not changed", file=sys.stderr)
            return 1
        rows.extend(table)
        if args.keep_gz:
            write_atomic(args.dest / name, data)
            print(f"kept   {name} ({len(data):,} bytes)")
        print(f"read   {name}: {len(table):,} announced ranges")

    text = render(rows).encode("utf-8")
    write_atomic(target, text)
    print(f"ok     {OUTPUT}: {len(rows):,} ranges, {len(text):,} bytes -> {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
