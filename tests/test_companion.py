"""Import/API self-tests for wifux.companion (no live attack).

The engine needs root + wpa_supplicant + pixiewps and a real interface, so it
cannot be exercised here; we only assert that it imports and exposes its API.
Run:  python -m tests.test_companion
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def check(name, cond):
    print(("  ok  " if cond else " FAIL ") + name)
    return cond


def main():
    ok = True
    import wifux.companion as c

    for name in ("Companion", "PixiewpsData", "ConnectionStatus",
                 "BruteforceStatus", "get_hex", "recvuntil"):
        ok &= check("exports %s" % name, hasattr(c, name))

    for meth in ("single_connection", "smart_bruteforce", "cleanup"):
        ok &= check("Companion.%s" % meth, hasattr(c.Companion, meth))

    # engine wires to the real PIN generator
    from wifux.wps import WPSpin
    sug = WPSpin().getSuggested("00:14:D1:AB:CD:EF")
    ok &= check("WPSpin.getSuggested -> dicts",
                isinstance(sug, list) and all('pin' in s for s in sug))

    # helpers behave
    ok &= check("get_hex parses hexdump line",
                c.get_hex("x: y: AA BB CC") == "AABBCC")

    # scanner imports and exposes its API
    from wifux.scanner import WiFiScanner
    ok &= check("WiFiScanner.iw_scanner", hasattr(WiFiScanner, "iw_scanner"))
    ok &= check("WiFiScanner.prompt_network", hasattr(WiFiScanner, "prompt_network"))

    # entrypoint imports and exposes main()
    import wifux.__main__ as m
    ok &= check("__main__.main callable", callable(m.main))

    print("\n%s" % ("ALL PASSED" if ok else "SOME FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
