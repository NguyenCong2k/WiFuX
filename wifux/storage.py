"""WiFuX persistent storage — results history and attack sessions.

A clean, from-scratch implementation of the WiFuX v2 ``StorageManager`` (the v2
class lives in the packed ``main.py`` and cannot be read, so this is an
equivalent, not a byte-for-byte port). Everything lives under ``~/.WiFuX`` and
is plain JSON.

* results history : ``~/.WiFuX/results.json`` — every cracked AP.
* bruteforce sessions : ``~/.WiFuX/sessions/<BSSID>.json`` — resume state
  (kept compatible with the OneShot engine's own ``~/.WiFuX/sessions`` files,
  which are separate plain-text files written by Companion).

Pure standard library; safe on any CPython 3.6+.
"""

from __future__ import annotations

import json
import os
import pathlib


def _bssid_key(bssid):
    return (bssid or '').replace(':', '').upper()


class StorageManager:
    """Store results and sessions under ~/.WiFuX."""

    def __init__(self, base_dir=None):
        self.base_dir = base_dir or os.path.join(str(pathlib.Path.home()), '.WiFuX')
        self.sessions_dir = os.path.join(self.base_dir, 'sessions')
        self.results_file = os.path.join(self.base_dir, 'results.json')
        for d in (self.base_dir, self.sessions_dir):
            if not os.path.exists(d):
                os.makedirs(d)

    # -- results history -----------------------------------------------------

    def load_results(self):
        try:
            with open(self.results_file, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (FileNotFoundError, ValueError):
            return []

    def add_result(self, result):
        """Append one result dict (deduped by bssid+pin) and persist."""
        results = self.load_results()
        key = (result.get('bssid'), result.get('wps_pin'))
        if not any((r.get('bssid'), r.get('wps_pin')) == key for r in results):
            results.append(dict(result))
            with open(self.results_file, 'w', encoding='utf-8') as fh:
                json.dump(results, fh, indent=2, ensure_ascii=False)
        return results

    # -- bruteforce sessions -------------------------------------------------

    def _session_path(self, bssid):
        return os.path.join(self.sessions_dir, _bssid_key(bssid) + '.json')

    def save_session(self, bssid, state):
        with open(self._session_path(bssid), 'w', encoding='utf-8') as fh:
            json.dump(state, fh, indent=2)
        return self._session_path(bssid)

    def load_session(self, bssid):
        try:
            with open(self._session_path(bssid), 'r', encoding='utf-8') as fh:
                return json.load(fh)
        except (FileNotFoundError, ValueError):
            return None

    def delete_session(self, bssid):
        try:
            os.remove(self._session_path(bssid))
            return True
        except FileNotFoundError:
            return False

    def list_sessions(self):
        """BSSIDs (formatted) that have a saved session, from both stores."""
        out = []
        try:
            names = os.listdir(self.sessions_dir)
        except FileNotFoundError:
            names = []
        for name in sorted(names):
            stem = os.path.splitext(name)[0]
            hexit = ''.join(c for c in stem if c in '0123456789ABCDEFabcdef')
            if len(hexit) == 12:
                out.append(':'.join(hexit[i:i + 2] for i in range(0, 12, 2)).upper())
            else:
                out.append(stem)
        return out
