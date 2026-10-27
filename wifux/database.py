"""WiFuX database layer.

Loads and unifies the three on-disk data sources that the packed ``main.py``
either embedded (and could not be updated without rebuilding bytecode) or read
only partially:

* ``database/router_models.json`` — vendor/model metadata (default PINs &
  credentials, Pixie-Dust rating, known vulns). Was embedded in the blob.
* ``database/pins.csv``           — ``PIN,OUI`` pairs from the OneShot
  (fulvius31) offline PIN database. Was present on disk but never read.
* ``vulnwsc.txt``                 — list of model names known to be WPS
  vulnerable. The tool already reads this at runtime.

Rows in ``pins.csv`` come in two flavours::

    00000000,A0:0B:BA     # a static known PIN for that OUI
    asus,64:D9:54         # an *algorithm* name to compute the PIN for that OUI

Static PINs are returned directly; algorithm names are surfaced separately so a
later ``wifux.wps`` module (ported from OneShot's ``WPSpin``) can compute them.

Pure standard library; safe on any CPython 3.6+.
"""

from __future__ import annotations

import csv
import json
import os
import re
from collections import defaultdict

# --- paths ------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
DEFAULT_DATA_DIR = os.path.join(_REPO_ROOT, "database")
DEFAULT_VULNWSC = os.path.join(_REPO_ROOT, "vulnwsc.txt")

# A pins.csv first field is a "static PIN" when it is all digits; a plain
# alphabetic token names an algorithm (e.g. "asus", "zhao", "vacante").
# Anything else (e.g. the two corrupt "003900ее" rows) is ignored.
_PIN_RE = re.compile(r"^\d{4,8}$")
_ALGO_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")  # e.g. asus, zhao, dlink1 (not 003900ее)


def normalize_oui(value):
    """Return the 3-byte OUI of a MAC/BSSID as ``AA:BB:CC`` (upper), or None.

    Accepts ``aa:bb:cc:dd:ee:ff``, ``AA-BB-CC-...``, ``aabbccddeeff`` or a bare
    ``aabbcc`` prefix.
    """
    if not value:
        return None
    hexit = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(hexit) < 6:
        return None
    oui = hexit[:6].upper()
    return "%s:%s:%s" % (oui[0:2], oui[2:4], oui[4:6])


class WiFuXDatabase:
    """Unified, read-only view over the WiFuX data files."""

    def __init__(self, data_dir=DEFAULT_DATA_DIR, vulnwsc_path=DEFAULT_VULNWSC):
        self.data_dir = data_dir
        self.vulnwsc_path = vulnwsc_path

        # OUI -> candidate data
        self.static_pins_by_oui = defaultdict(list)   # {OUI: [pin, ...]}
        self.algos_by_oui = defaultdict(list)         # {OUI: [algo_name, ...]}
        # vendor metadata
        self.vendors = {}                             # {vendor: {...}}
        # known-vulnerable model name strings
        self.vuln_names = []

        self._load_pins()
        self._load_models()
        self._load_vulnwsc()

    # -- loaders -------------------------------------------------------------

    def _load_pins(self):
        path = os.path.join(self.data_dir, "pins.csv")
        if not os.path.isfile(path):
            return
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.reader(fh):
                if len(row) < 2:
                    continue
                value = row[0].strip()
                oui = normalize_oui(row[1])
                if not oui or not value:
                    continue
                if _PIN_RE.match(value):
                    if value not in self.static_pins_by_oui[oui]:
                        self.static_pins_by_oui[oui].append(value)
                elif _ALGO_RE.match(value):
                    algo = value.lower()
                    if algo not in self.algos_by_oui[oui]:
                        self.algos_by_oui[oui].append(algo)
                # else: corrupt/unknown token -> skip

    def _load_models(self):
        path = os.path.join(self.data_dir, "router_models.json")
        if not os.path.isfile(path):
            return
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            blob = json.load(fh)
        self.vendors = blob.get("models", {}) or {}

    def _load_vulnwsc(self):
        if not os.path.isfile(self.vulnwsc_path):
            return
        with open(self.vulnwsc_path, "r", encoding="utf-8", errors="replace") as fh:
            self.vuln_names = [ln.strip() for ln in fh if ln.strip()]

    # -- lookups -------------------------------------------------------------

    def candidate_pins(self, bssid):
        """Static candidate PINs for a BSSID, OUI matches first."""
        oui = normalize_oui(bssid)
        if not oui:
            return []
        return list(self.static_pins_by_oui.get(oui, []))

    def algorithms(self, bssid):
        """Algorithm names registered for a BSSID's OUI (compute later)."""
        oui = normalize_oui(bssid)
        if not oui:
            return []
        return list(self.algos_by_oui.get(oui, []))

    def vendor_info(self, name):
        """Metadata for a vendor by exact or case-insensitive/substring match."""
        if not name:
            return None
        if name in self.vendors:
            return self.vendors[name]
        low = name.lower()
        for vendor, info in self.vendors.items():
            if vendor.lower() == low:
                return info
        for vendor, info in self.vendors.items():
            if low in vendor.lower() or vendor.lower() in low:
                return info
        return None

    def match_model(self, essid_or_model):
        """Return vulnwsc.txt entries that look like this ESSID/model, if any."""
        if not essid_or_model:
            return []
        low = essid_or_model.lower()
        hits = []
        for entry in self.vuln_names:
            el = entry.lower()
            if low == el or low in el or el in low:
                hits.append(entry)
        return hits

    def assess(self, bssid, essid=None):
        """One-shot assessment combining every source for a target AP."""
        oui = normalize_oui(bssid)
        pins = self.candidate_pins(bssid)
        algos = self.algorithms(bssid)
        vuln_hits = self.match_model(essid) if essid else []
        vendor = self.vendor_info(essid) if essid else None
        default_pins = list(vendor.get("default_pins", [])) if vendor else []

        # Computed algorithmic PINs (soft dependency on wifux.wps).
        computed = []
        try:
            from wifux.wps import pins_for_bssid
            computed = pins_for_bssid(bssid, algos)
        except Exception:
            computed = []

        # merge order: OUI static -> computed -> vendor defaults (dedup).
        # Keep the empty-PIN candidate ("" from pinEmpty/vacante) — it is a
        # real attack, not a missing value.
        all_pins = list(pins)
        for p in computed + default_pins:
            if p is not None and p not in all_pins:
                all_pins.append(p)
        return {
            "bssid": bssid,
            "oui": oui,
            "essid": essid,
            "candidate_pins": all_pins,
            "computed_pins": computed,
            "algorithms": algos,
            "vendor": vendor.get("models") if vendor else None,
            "pixie_dust": vendor.get("pixie_dust") if vendor else None,
            "pixie_rating": vendor.get("pixie_dust_rating") if vendor else None,
            "known_vulns": vendor.get("known_vulns", []) if vendor else [],
            "vulnwsc_matches": vuln_hits,
            "likely_vulnerable": bool(all_pins or algos or vuln_hits
                                      or (vendor and vendor.get("pixie_dust"))),
        }

    # -- stats ---------------------------------------------------------------

    def stats(self):
        return {
            "oui_with_static_pins": len(self.static_pins_by_oui),
            "static_pins_total": sum(len(v) for v in self.static_pins_by_oui.values()),
            "oui_with_algorithms": len(self.algos_by_oui),
            "algorithm_names": sorted({a for v in self.algos_by_oui.values() for a in v}),
            "vendors": len(self.vendors),
            "models_total": sum(len(i.get("models", [])) for i in self.vendors.values()),
            "vulnwsc_entries": len(self.vuln_names),
        }


# --- tiny CLI / demo --------------------------------------------------------

def _main(argv=None):
    import argparse

    p = argparse.ArgumentParser(
        prog="wifux.database",
        description="Query the WiFuX WPS vulnerability / PIN database.",
    )
    p.add_argument("-b", "--bssid", help="target BSSID/MAC, e.g. A0:0B:BA:11:22:33")
    p.add_argument("-e", "--essid", help="target network name / router model")
    p.add_argument("--stats", action="store_true", help="print database stats and exit")
    args = p.parse_args(argv)

    db = WiFuXDatabase()

    if args.stats or (not args.bssid and not args.essid):
        s = db.stats()
        print("WiFuX database")
        print("  OUIs with static PINs : %d  (%d PINs total)"
              % (s["oui_with_static_pins"], s["static_pins_total"]))
        print("  OUIs with algorithms  : %d  (%s)"
              % (s["oui_with_algorithms"], ", ".join(s["algorithm_names"]) or "-"))
        print("  Vendors / models      : %d / %d"
              % (s["vendors"], s["models_total"]))
        print("  vulnwsc.txt entries   : %d" % s["vulnwsc_entries"])
        return 0

    rep = db.assess(args.bssid, args.essid)
    print("Target   : %s  (OUI %s)" % (rep["bssid"], rep["oui"]))
    if rep["essid"]:
        print("ESSID    : %s" % rep["essid"])
    print("Likely vulnerable : %s" % ("YES" if rep["likely_vulnerable"] else "unknown"))
    if rep["candidate_pins"]:
        print("Candidate PINs    : %s" % ", ".join(rep["candidate_pins"]))
    if rep["algorithms"]:
        print("PIN algorithms    : %s" % ", ".join(rep["algorithms"]))
    if rep["pixie_rating"]:
        print("Pixie-Dust        : %s (rating %s)"
              % (rep["pixie_dust"], rep["pixie_rating"]))
    if rep["known_vulns"]:
        print("Known vulns       : %s" % "; ".join(rep["known_vulns"]))
    if rep["vulnwsc_matches"]:
        print("vulnwsc matches   : %s" % ", ".join(rep["vulnwsc_matches"][:5]))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
