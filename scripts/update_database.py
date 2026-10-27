#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Update WiFuX's external WPS vulnerable-device database.

This script merges vulnwsc.txt from several maintained OneShot forks,
plus the VULN_CONFIRMED list exported from WiFuX's RouterModels.

Usage:
    python3 scripts/update_database.py
    python3 scripts/update_database.py --offline
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VULN_FILE = ROOT / "vulnwsc.txt"
ROUTER_DB = ROOT / "database" / "router_models.json"

SOURCES = [
    ("WiFuX", "https://raw.githubusercontent.com/msrofficial/WiFuX/main/vulnwsc.txt"),
    ("OneShot", "https://raw.githubusercontent.com/kimocoder/OneShot/master/vulnwsc.txt"),
    ("OneShot-Extended", "https://raw.githubusercontent.com/chkndrp/OneShot-Extended/master/vulnwsc.txt"),
    ("OneShot-fulvius", "https://raw.githubusercontent.com/fulvius31/OneShot/master/vulnwsc.txt"),
]


def fetch(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "WiFuX-db-updater/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def merge_entries(*groups: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for group in groups:
        for raw in group:
            value = raw.strip()
            if not value:
                continue
            key = value.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(value)
    out.sort(key=str.lower)
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="only merge local data")
    args = parser.parse_args()

    groups: list[list[str]] = []

    # Existing local list, so offline mode still keeps it.
    if VULN_FILE.exists():
        groups.append(VULN_FILE.read_text(encoding="utf-8", errors="replace").splitlines())

    if not args.offline:
        for name, url in SOURCES:
            try:
                text = fetch(url)
                groups.append(text.splitlines())
                print(f"[+] {name}: {len(text.splitlines())} lines")
            except Exception as exc:
                print(f"[!] {name}: download failed: {exc}", file=sys.stderr)

    # Include confirmed models extracted from main.py's RouterModels.
    if ROUTER_DB.exists():
        try:
            data = json.loads(ROUTER_DB.read_text(encoding="utf-8"))
            confirmed = data.get("vuln_confirmed", [])
            if isinstance(confirmed, list):
                groups.append([str(x) for x in confirmed])
                print(f"[+] RouterModels.VULN_CONFIRMED: {len(confirmed)} entries")
        except Exception as exc:
            print(f"[!] router_models.json: {exc}", file=sys.stderr)

    entries = merge_entries(*groups)
    VULN_FILE.write_text("\n".join(entries) + "\n", encoding="utf-8", newline="\n")
    print(f"[OK] wrote {VULN_FILE} with {len(entries)} unique entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
