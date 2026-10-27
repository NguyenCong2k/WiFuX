"""WiFuX report generation — CSV / JSON / HTML.

A clean, from-scratch implementation of the WiFuX v2 report feature (the v2
``ReportGenerator`` lives inside the packed ``main.py`` and cannot be read, so
this is an equivalent, not a byte-for-byte port). It turns one result record or
a list of them into a report file.

A result record is a dict with the keys produced by
``Companion.last_result``::

    {'bssid', 'essid', 'wps_pin', 'wpa_psk', 'date'}

Pure standard library; safe on any CPython 3.6+.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime

FIELDS = ['date', 'bssid', 'essid', 'wps_pin', 'wpa_psk']
_HEADERS = {'date': 'Date', 'bssid': 'BSSID', 'essid': 'ESSID',
            'wps_pin': 'WPS PIN', 'wpa_psk': 'WPA PSK'}


def _as_list(results):
    if results is None:
        return []
    if isinstance(results, dict):
        return [results]
    return list(results)


def _row(r):
    return {k: ('' if r.get(k) is None else str(r.get(k, ''))) for k in FIELDS}


class ReportGenerator:
    """Write attack results as CSV, JSON or HTML."""

    def __init__(self, reports_dir=None):
        self.reports_dir = reports_dir or os.path.join(os.getcwd(), 'reports')

    def _path(self, fmt, path=None):
        if path:
            return path
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return os.path.join(self.reports_dir, 'wifux_report_%s.%s' % (stamp, fmt))

    def write(self, results, fmt='html', path=None):
        """Write `results` in `fmt` (html|csv|json); returns the file path."""
        fmt = fmt.lower()
        writer = {'csv': self.write_csv, 'json': self.write_json,
                  'html': self.write_html}.get(fmt)
        if writer is None:
            raise ValueError('Unknown report format: %s' % fmt)
        return writer(results, path)

    def write_csv(self, results, path=None):
        rows = [_row(r) for r in _as_list(results)]
        path = self._path('csv', path)
        with open(path, 'w', newline='', encoding='utf-8') as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS, delimiter=';',
                               quoting=csv.QUOTE_ALL)
            w.writerow(_HEADERS)
            for row in rows:
                w.writerow(row)
        return path

    def write_json(self, results, path=None):
        rows = [_row(r) for r in _as_list(results)]
        path = self._path('json', path)
        doc = {'tool': 'WiFuX', 'generated': datetime.now().isoformat(),
               'count': len(rows), 'results': rows}
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
        return path

    def write_html(self, results, path=None):
        rows = [_row(r) for r in _as_list(results)]
        path = self._path('html', path)
        trs = '\n'.join(
            '      <tr>' + ''.join('<td>%s</td>' % _esc(row[k]) for k in FIELDS) + '</tr>'
            for row in rows) or '      <tr><td colspan="5">No results</td></tr>'
        html = _HTML_TEMPLATE.format(
            generated=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            count=len(rows),
            headers=''.join('<th>%s</th>' % _HEADERS[k] for k in FIELDS),
            rows=trs,
        )
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(html)
        return path


def _esc(s):
    return (str(s).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('"', '&quot;'))


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFuX Report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; padding: 24px;
         background: #0b0f14; color: #e6edf3; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .meta {{ color: #8b98a5; font-size: 13px; margin-bottom: 20px; }}
  table {{ border-collapse: collapse; width: 100%; max-width: 900px;
          background: #11161d; border-radius: 10px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 10px 14px; font-size: 14px;
           border-bottom: 1px solid #222c38; word-break: break-all; }}
  th {{ background: #161d26; color: #9fb3c8; text-transform: uppercase;
       font-size: 11px; letter-spacing: .04em; }}
  tr:last-child td {{ border-bottom: 0; }}
  td:nth-child(4), td:nth-child(5) {{ font-family: ui-monospace, monospace;
       color: #7ee787; }}
  .warn {{ margin-top: 20px; color: #8b98a5; font-size: 12px; max-width: 900px; }}
</style>
</head>
<body>
  <h1>WiFuX — WPS audit report</h1>
  <div class="meta">Generated {generated} · {count} result(s)</div>
  <table>
    <thead><tr>{headers}</tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
  <p class="warn">For authorized security testing only — networks you own or may test.</p>
</body>
</html>
"""
