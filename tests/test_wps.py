"""Self-tests for wifux.wps (no pytest needed)."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifux.wps import WPSpin, NetworkAddress, pins_for_bssid, TAG_TO_ALGO, _OUI_MASKS


def check(name, cond, got=None):
    print(("  ok  " if cond else " FAIL ") + name + ("" if cond else "  got=%r" % (got,)))
    return cond


def main():
    ok = True
    gen = WPSpin()

    # checksum: 12345670 is a canonical valid WPS pin -> checksum(1234567) == 0
    ok &= check("checksum(1234567)==0", gen.checksum(1234567) == 0, gen.checksum(1234567))

    # NetworkAddress round-trips
    na = NetworkAddress("00:14:D1:AB:CD:EF")
    ok &= check("NA string", na.string == "00:14:D1:AB:CD:EF", na.string)
    ok &= check("NA integer", na.integer == 0x0014D1ABCDEF, hex(na.integer))

    # every algorithm produces an 8-digit pin with valid checksum
    all_valid = True
    for algo in gen.algos:
        pin = gen.generate(algo, "00:14:D1:AB:CD:EF")
        if algo == "pinEmpty":
            all_valid &= (pin == "")
            continue
        if not (len(pin) == 8 and pin.isdigit()):
            all_valid = False
            break
        # standard algos must satisfy the WPS body+checksum rule; the
        # preformatted fork algos carry their own formatting.
        if algo not in gen._PREFORMATTED:
            body, cs = int(pin[:7]), int(pin[7])
            if gen.checksum(body) != cs:
                all_valid = False
                break
    ok &= check("standard algos -> valid WPS checksum", all_valid)

    # pin24 is deterministic from the NIC
    ok &= check("pin24 deterministic",
                gen.generate("pin24", "00:14:D1:AB:CD:EF")
                == gen.generate("pin24", "FF:FF:FF:AB:CD:EF"))

    # OUI-mask suggestion: 0014D1 should suggest at least pin24/pinDLink family
    sug = list(gen._suggest(NetworkAddress("00:14:D1:AB:CD:EF").string))
    ok &= check("0014D1 has suggestions", len(sug) > 0, sug)

    # high-level: ASUS tag computes a pin
    pins = pins_for_bssid("64:D9:54:AA:BB:CC", ["asus"])
    ok &= check("pins_for_bssid(asus) non-empty", len(pins) > 0, pins)
    ok &= check("pins are 8-digit", all(len(p) == 8 and p.isdigit() for p in pins), pins)

    # full OUI masks loaded from data file (30 algos)
    ok &= check("OUI masks loaded (30 algos)", len(_OUI_MASKS) == 30, len(_OUI_MASKS))
    ok &= check("pin24 mask is full (>100)", len(_OUI_MASKS.get("pin24", ())) > 100,
                len(_OUI_MASKS.get("pin24", ())))

    # every pins.csv tag maps to a real algorithm (or is explicitly ignored)
    for tag in ("zhao", "vacante", "arcady", "trend", "asus", "dlink",
                "dlink1", "airocon", "twentyeight", "thirtytwo"):
        ok &= check("tag %-11s -> algo" % tag, tag in TAG_TO_ALGO, tag)
        ok &= check("  algo %s exists" % TAG_TO_ALGO[tag],
                    TAG_TO_ALGO[tag] in gen.algos)

    # vacante == empty PIN (verified against pinEmpty OUI set)
    ok &= check("vacante -> empty pin",
                gen.generate(TAG_TO_ALGO["vacante"], "E4:6F:13:11:22:33") == "")

    # the three fulvius algorithms run and produce 8-digit pins
    for algo in ("pinTrendNet", "pinArris"):
        pin = gen.generate(algo, "00:14:D1:AB:CD:EF")
        ok &= check("%s -> 8-digit" % algo, len(pin) == 8 and pin.isdigit(), pin)
    eb = gen.generate("pinEasybox", "00:14:D1:AB:CD:EF")
    ok &= check("pinEasybox -> 8-digit", len(eb) == 8 and eb.isdigit(), eb)

    # zhao (24-bit): the pin24 result is present when the zhao tag is given
    ok &= check("zhao yields pin24",
                gen.generate("pin24", "20:2B:C1:AA:BB:CC")
                in pins_for_bssid("20:2B:C1:AA:BB:CC", ["zhao"]))

    print("\n%s" % ("ALL PASSED" if ok else "SOME FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
