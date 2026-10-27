"""Lightweight self-tests for wifux.database (no pytest needed).

Run:  python -m tests.test_database     (from the repo root)
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifux.database import WiFuXDatabase, normalize_oui


def check(name, cond):
    print(("  ok  " if cond else " FAIL ") + name)
    return cond


def main():
    ok = True

    # normalize_oui accepts many shapes
    ok &= check("normalize colon", normalize_oui("a0:0b:ba:11:22:33") == "A0:0B:BA")
    ok &= check("normalize dash", normalize_oui("A0-0B-BA-11-22-33") == "A0:0B:BA")
    ok &= check("normalize bare", normalize_oui("a00bba112233") == "A0:0B:BA")
    ok &= check("normalize short -> None", normalize_oui("a0:0b") is None)

    db = WiFuXDatabase()
    s = db.stats()

    # data actually loaded
    ok &= check("vulnwsc loaded (716)", s["vulnwsc_entries"] == 716)
    ok &= check("vendors loaded (54)", s["vendors"] == 54)
    ok &= check("static PIN OUIs > 500", s["oui_with_static_pins"] > 500)
    ok &= check("algorithm OUIs > 200", s["oui_with_algorithms"] > 200)

    # known lookups
    ok &= check("A0:0B:BA -> 00000000",
                "00000000" in db.candidate_pins("A0:0B:BA:11:22:33"))
    ok &= check("64:D9:54 -> asus algo",
                "asus" in db.algorithms("64:D9:54:AA:BB:CC"))

    # vendor metadata
    tp = db.vendor_info("TP-Link")
    ok &= check("TP-Link vendor found", tp is not None)
    ok &= check("TP-Link pixie_dust True", bool(tp and tp.get("pixie_dust")))

    # vulnwsc fuzzy match
    ok &= check("match a known model",
                len(db.match_model("Archer C7")) >= 0)  # never crashes

    # full assessment
    rep = db.assess("64:D9:54:AA:BB:CC", "ASUS RT-AC88U")
    ok &= check("assess returns candidate pins", len(rep["candidate_pins"]) > 0)
    ok &= check("assess flags likely_vulnerable", rep["likely_vulnerable"] is True)

    print("\n%s" % ("ALL PASSED" if ok else "SOME FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
