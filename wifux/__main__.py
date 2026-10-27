"""WiFuX command-line entrypoint (clean rebuild).

    sudo python -m wifux -i wlan0 -K                          # scan, pick target, Pixie Dust
    sudo python -m wifux -i wlan0 -b AA:BB:CC:DD:EE:FF -K      # Pixie Dust on one AP
    sudo python -m wifux -i wlan0 -b AA:BB:CC:DD:EE:FF -B      # online bruteforce
    sudo python -m wifux -i wlan0 -b AA:BB:CC:DD:EE:FF -p 12345670
    python  -m wifux --pins -b AA:BB:CC:DD:EE:FF               # offline: just list candidate PINs

Run with no -b (and no --pbc) to scan for WPS networks and choose one. Scanning
uses `iw` in managed mode, so it needs no monitor mode (works on internal Wi-Fi).

Needs root + `wpa_supplicant` and `pixiewps` for live attacks (Linux /
Android-Termux). The `--pins` mode is offline and runs anywhere.
For authorized testing of networks you own or may test only.
"""

import argparse
import os
import subprocess
import sys


def iface_up(iface, down=False):
    action = 'down' if down else 'up'
    res = subprocess.run('ip link set {} {}'.format(iface, action),
                         shell=True, stdout=sys.stdout, stderr=sys.stdout)
    return res.returncode == 0


def cmd_pins(bssid):
    """Offline: print candidate PINs for a BSSID (no hardware needed)."""
    from wifux.database import WiFuXDatabase
    db = WiFuXDatabase()
    rep = db.assess(bssid)
    print("BSSID : %s  (OUI %s)" % (bssid, rep["oui"]))
    if rep["candidate_pins"]:
        print("Candidate PINs (%d):" % len(rep["candidate_pins"]))
        for p in rep["candidate_pins"]:
            print("   %s" % (p if p != "" else "<empty PIN>"))
    else:
        print("No candidate PINs for this OUI.")
    if rep["algorithms"]:
        print("Algorithm hints: %s" % ", ".join(rep["algorithms"]))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="wifux", add_help=True,
                                description="WiFuX — WPS auditing (clean rebuild).")
    p.add_argument('-i', '--interface', help='network interface, e.g. wlan0')
    p.add_argument('-b', '--bssid', help='target BSSID (your own / authorized AP)')
    p.add_argument('-p', '--pin', help='use a specific 8-digit WPS PIN')
    p.add_argument('-K', '--pixie-dust', action='store_true', help='Pixie Dust attack')
    p.add_argument('-F', '--pixie-force', action='store_true', help='pixiewps full range')
    p.add_argument('-B', '--bruteforce', action='store_true', help='online PIN bruteforce')
    p.add_argument('--pbc', action='store_true', help='WPS push-button connect')
    p.add_argument('-d', '--delay', type=float, help='delay between attempts (s)')
    p.add_argument('-w', '--write', action='store_true', help='save result to a file')
    p.add_argument('-v', '--verbose', action='store_true', help='verbose output')
    p.add_argument('--show-pixie-cmd', action='store_true', help='print the pixiewps command')
    p.add_argument('--pins', action='store_true',
                   help='offline: only list candidate PINs for --bssid and exit')
    args = p.parse_args(argv)

    # Offline mode — no hardware/root required.
    if args.pins:
        if not args.bssid:
            p.error("--pins requires -b/--bssid")
        return cmd_pins(args.bssid)

    # Live attack modes.
    if not args.interface:
        p.error("-i/--interface is required for live attacks (or use --pins)")
    if hasattr(os, "getuid") and os.getuid() != 0:
        sys.stderr.write("[!] Run it as root (su / sudo).\n")
        return 1

    from wifux.companion import Companion

    if not iface_up(args.interface):
        sys.stderr.write('[-] Unable to bring up interface "%s"\n' % args.interface)
        return 1

    # No target given -> scan and let the user pick. Scanning uses `iw` in
    # managed mode (no monitor mode needed), so it works on the internal chip.
    if not args.bssid and not args.pbc:
        from wifux.scanner import WiFiScanner
        from wifux.database import WiFuXDatabase
        try:
            vuln_list = WiFuXDatabase().vuln_names
        except Exception:
            vuln_list = []
        args.bssid = WiFiScanner(args.interface, vuln_list).prompt_network()
        if not args.bssid:
            iface_up(args.interface, down=True)
            return 1

    companion = None
    try:
        companion = Companion(args.interface, args.write, print_debug=args.verbose,
                              bssid=args.bssid or '')
        if args.pbc:
            companion.single_connection(pbc_mode=True)
        elif args.bruteforce:
            companion.smart_bruteforce(args.bssid, args.pin, args.delay)
        else:
            companion.single_connection(
                args.bssid, args.pin, args.pixie_dust, args.pbc,
                args.show_pixie_cmd, args.pixie_force)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Aborted\n")
    finally:
        if companion is not None:
            try:
                companion.cleanup()
            except Exception:
                pass
        iface_up(args.interface, down=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
