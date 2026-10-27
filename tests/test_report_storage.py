"""Self-tests for wifux.report and wifux.storage (no hardware)."""

import sys, os, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifux.report import ReportGenerator
from wifux.storage import StorageManager


def check(name, cond):
    print(("  ok  " if cond else " FAIL ") + name)
    return cond


SAMPLE = {'bssid': 'AA:BB:CC:DD:EE:FF', 'essid': 'MyAP',
          'wps_pin': '12345670', 'wpa_psk': 'secret123', 'date': '27.10.2026 16:40'}


def main():
    ok = True
    tmp = tempfile.mkdtemp()

    # ---- ReportGenerator ----
    rg = ReportGenerator(reports_dir=os.path.join(tmp, 'reports'))
    for fmt in ('csv', 'json', 'html'):
        path = rg.write(SAMPLE, fmt)
        ok &= check("report %s written" % fmt, os.path.isfile(path))
        text = open(path, encoding='utf-8').read()
        ok &= check("report %s has psk" % fmt, 'secret123' in text)

    # JSON is valid and structured
    jpath = rg.write([SAMPLE, SAMPLE], 'json')
    doc = json.load(open(jpath, encoding='utf-8'))
    ok &= check("json count field", doc.get('count') == 2)

    # HTML escapes
    bad = dict(SAMPLE, essid='<script>')
    hpath = rg.write(bad, 'html')
    ok &= check("html escapes <", '&lt;script&gt;' in open(hpath, encoding='utf-8').read())

    ok &= check("unknown format raises",
                _raises(lambda: rg.write(SAMPLE, 'pdf')))

    # ---- StorageManager ----
    sm = StorageManager(base_dir=os.path.join(tmp, '.WiFuX'))
    sm.add_result(SAMPLE)
    sm.add_result(SAMPLE)                       # dedup
    ok &= check("results stored + deduped", len(sm.load_results()) == 1)
    sm.add_result(dict(SAMPLE, wps_pin='00000000'))
    ok &= check("distinct result added", len(sm.load_results()) == 2)

    sm.save_session('AA:BB:CC:DD:EE:FF', {'last_pin': '1234'})
    ok &= check("session round-trips",
                sm.load_session('AA:BB:CC:DD:EE:FF') == {'last_pin': '1234'})
    ok &= check("session listed",
                'AA:BB:CC:DD:EE:FF' in sm.list_sessions())
    ok &= check("session deleted", sm.delete_session('AA:BB:CC:DD:EE:FF'))
    ok &= check("missing session -> None", sm.load_session('11:22:33:44:55:66') is None)

    print("\n%s" % ("ALL PASSED" if ok else "SOME FAILED"))
    return 0 if ok else 1


def _raises(fn):
    try:
        fn()
        return False
    except Exception:
        return True


if __name__ == "__main__":
    raise SystemExit(main())
