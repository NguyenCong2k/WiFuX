"""WPS PIN generation — WPSpin, ported from OneShot.

Ported, with light cleanup, from the OneShot WPS tool and its fulvius31 fork:
    rofl0r (original) -> drygdryg -> kimocoder/OneShot -> fulvius31/OneShot
OneShot and the wider pixiewps ecosystem are GPLv3; this module is therefore
GPLv3 and keeps that attribution. For authorized security testing only.

Given a BSSID it computes WPS PIN candidates for every vendor PIN-derivation
algorithm (24/28/32-bit, D-Link, ASUS, Airocon, TrendNet, EasyBox/Arcadyan,
Arris) plus known static PINs, and — via the full OUI mask table shipped in
``database/oui_masks.json`` — suggests which algorithms apply to a given OUI.

The ``database/pins.csv`` algorithm *tags* (zhao, vacante, arcady, ...) are
mapped to the real algorithms through :data:`TAG_TO_ALGO`; those tags are
hints, not literal PINs (the upstream tool ignores them — it only reads the
numeric rows — so we turn them into the algorithm each one actually names).

Pure standard library; safe on any CPython 3.6+.
"""

from __future__ import annotations

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
_MASKS_PATH = os.path.join(_REPO_ROOT, "database", "oui_masks.json")


def _load_masks(path=_MASKS_PATH):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return {k: tuple(v) for k, v in data.get("masks", {}).items()}
    except Exception:
        return {}


_OUI_MASKS = _load_masks()


class NetworkAddress:
    """A MAC address, convertible between string and integer forms."""

    def __init__(self, mac):
        if isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(mac)
        else:
            raise ValueError('MAC address must be string or integer')

    @property
    def string(self):
        return self._str_repr

    @string.setter
    def string(self, value):
        self._str_repr = value
        self._int_repr = self._mac2int(value)

    @property
    def integer(self):
        return self._int_repr

    @integer.setter
    def integer(self, value):
        self._int_repr = value
        self._str_repr = self._int2mac(value)

    def __int__(self):
        return self.integer

    def __str__(self):
        return self.string

    @staticmethod
    def _mac2int(mac):
        return int(mac.replace(':', '').replace('-', '').replace('.', ''), 16)

    @staticmethod
    def _int2mac(mac):
        s = hex(mac).split('x')[-1].upper().zfill(12)
        return ':'.join(s[i:i + 2] for i in range(0, 12, 2))


class WPSpin:
    """WPS pin generator (algorithmic + static), OUI-mask suggestions."""

    # algorithms that return a fully-formatted pin string themselves
    _PREFORMATTED = {'pinEmpty', 'pinTrendNet', 'pinEasybox', 'pinArris'}

    def __init__(self):
        self.ALGO_MAC = 0
        self.ALGO_EMPTY = 1
        self.ALGO_STATIC = 2

        self.algos = {
            'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin24},
            'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin28},
            'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin32},
            'pinDLink': {'name': 'D-Link PIN', 'mode': self.ALGO_MAC, 'gen': self.pinDLink},
            'pinDLink1': {'name': 'D-Link PIN +1', 'mode': self.ALGO_MAC, 'gen': self.pinDLink1},
            'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self.pinASUS},
            'pinAirocon': {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC, 'gen': self.pinAirocon},
            'pinTrendNet': {'name': 'TrendNet', 'mode': self.ALGO_MAC, 'gen': self.pinTrendNet},
            'pinEasybox': {'name': 'EasyBox / Arcadyan', 'mode': self.ALGO_MAC, 'gen': self.pinEasybox},
            'pinArris': {'name': 'Arris', 'mode': self.ALGO_MAC, 'gen': self.pinArris},
            'pinEmpty': {'name': 'Empty PIN', 'mode': self.ALGO_EMPTY, 'gen': lambda mac: ''},
            'pinCisco': {'name': 'Cisco', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1234567},
            'pinBrcm1': {'name': 'Broadcom 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2017252},
            'pinBrcm2': {'name': 'Broadcom 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4626484},
            'pinBrcm3': {'name': 'Broadcom 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7622990},
            'pinBrcm4': {'name': 'Broadcom 4', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6232714},
            'pinBrcm5': {'name': 'Broadcom 5', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinBrcm6': {'name': 'Broadcom 6', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3195719},
            'pinAirc1': {'name': 'Airocon 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3043203},
            'pinAirc2': {'name': 'Airocon 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7141225},
            'pinDSL2740R': {'name': 'DSL-2740R', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6817554},
            'pinRealtek1': {'name': 'Realtek 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinRealtek2': {'name': 'Realtek 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9571911},
            'pinRealtek3': {'name': 'Realtek 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
            'pinUpvel': {'name': 'Upvel', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2085483},
            'pinUR814AC': {'name': 'UR-814AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinUR825AC': {'name': 'UR-825AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 529417},
            'pinOnlime': {'name': 'Onlime', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9995604},
            'pinEdimax': {'name': 'Edimax', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3561153},
            'pinThomson': {'name': 'Thomson', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6795814},
            'pinHG532x': {'name': 'HG532x', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3425928},
            'pinH108L': {'name': 'H108L', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinONO': {'name': 'CBN ONO', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9575521},
        }

    @staticmethod
    def checksum(pin):
        """Standard WPS checksum of a 7-digit integer pin."""
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def generate(self, algo, mac):
        """Return the WPS pin string for an algorithm ID and MAC."""
        mac = NetworkAddress(mac)
        if algo not in self.algos:
            raise ValueError('Invalid WPS pin algorithm: %s' % algo)
        pin = self.algos[algo]['gen'](mac)
        if algo in self._PREFORMATTED:
            return pin  # already a formatted string (or '' for empty)
        pin = pin % 10000000
        pin = str(pin) + str(self.checksum(pin))
        return pin.zfill(8)

    def getList(self, mac, get_static=True):
        res = []
        for ID, algo in self.algos.items():
            if algo['mode'] == self.ALGO_STATIC and not get_static:
                continue
            res.append(self.generate(ID, mac))
        return res

    def getSuggested(self, mac):
        """Suggested algorithms for a MAC as dicts {id, name, pin}."""
        res = []
        for ID in self._suggest(mac):
            algo = self.algos[ID]
            name = algo['name']
            if algo['mode'] == self.ALGO_STATIC:
                name = 'Static PIN — ' + name
            res.append({'id': ID, 'name': name, 'pin': self.generate(ID, mac)})
        return res

    def getSuggestedList(self, mac):
        """Computed pins for the algorithms whose OUI mask matches this MAC."""
        return [self.generate(algo, mac) for algo in self._suggest(mac)]

    def getLikely(self, mac):
        res = [p for p in self.getSuggestedList(mac) if p]
        return res[0] if res else None

    def _suggest(self, mac):
        """Algorithm IDs whose OUI prefix mask matches this MAC."""
        prefix = NetworkAddress(mac).string.replace(':', '').upper()
        for algo_id, masks in _OUI_MASKS.items():
            if prefix.startswith(masks):
                yield algo_id

    # -- MAC-derived algorithms (OneShot) -----------------------------------

    def pin24(self, mac):
        return mac.integer & 0xFFFFFF

    def pin28(self, mac):
        return mac.integer & 0xFFFFFFF

    def pin32(self, mac):
        return mac.integer % 0x100000000

    def pinDLink(self, mac):
        nic = mac.integer & 0xFFFFFF
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) +
                ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) +
                ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pinDLink1(self, mac):
        mac.integer += 1
        return self.pinDLink(mac)

    def pinASUS(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
        return int(pin)

    def pinAirocon(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        return ((b[0] + b[1]) % 10) \
            + (((b[5] + b[0]) % 10) * 10) \
            + (((b[4] + b[5]) % 10) * 100) \
            + (((b[3] + b[4]) % 10) * 1000) \
            + (((b[2] + b[3]) % 10) * 10000) \
            + (((b[1] + b[2]) % 10) * 100000) \
            + (((b[0] + b[1]) % 10) * 1000000)

    # -- extra algorithms (fulvius31 fork), return formatted strings --------

    def pinTrendNet(self, mac):
        try:
            last_3 = mac.string.replace(':', '')[-6:]
            merge = last_3[4:] + last_3[2:4] + last_3[:2]
            string = int(merge, 16) % 10000000
            pin = 10 * string
            return "%08d" % (pin + self.checksum(pin))
        except ValueError:
            return "12345670"

    def pinEasybox(self, mac):
        try:
            last_two = mac.string.replace(':', '')[-4:]
            snstr = "%05d" % int(last_two, 16)
            m = [int(c, 16) for c in last_two]
            sn = [int(c) for c in snstr[1:]]
            k1 = (sum(sn[:2]) + sum(m[2:])) % 16
            k2 = (sum(sn[2:]) + sum(m[:2])) % 16
            hpin = [k1 ^ sn[3], k1 ^ sn[2], k2 ^ m[1], k2 ^ m[2],
                    m[2] ^ sn[3], m[3] ^ sn[2], k1 ^ sn[1]]
            hpinint = int(''.join("%X" % x for x in hpin), 16) % 10000000
            return "%07d%d" % (hpinint, self.checksum(hpinint))
        except ValueError:
            return "12345670"

    def pinArris(self, mac):
        def fib(n, memo={}):
            if n in memo:
                return memo[n]
            if n in (0, 1, 2):
                return 1
            memo[n] = fib(n - 1, memo) + fib(n - 2, memo)
            return memo[n]

        arr = [int(x, 16) for x in mac.string.split(':')]
        fibnum = []
        for v in arr:
            adj, counter = v, 0
            if adj > 30:
                while adj > 31:
                    adj -= 16
                    counter += 1
            if counter == 0 and adj < 3:
                adj = (sum(arr) - adj) & 0xff
                adj = (adj % 28) + 3
            fibnum.append(fib(adj) + (fib(counter) if counter else 0))
        fibsum = sum(f * fib(i + 16) for i, f in enumerate(fibnum)) + sum(arr)
        fibsum = (fibsum % 10000000 * 10) + self.checksum(fibsum)
        return "%08d" % fibsum


# Map the pins.csv algorithm tags to WPSpin algorithm IDs.
#   zhao     = zhaochunsheng 24-bit algorithm
#   vacante  = empty/null PIN (verified: all tagged OUIs are in pinEmpty mask)
#   arcady   = Arcadyan / EasyBox
TAG_TO_ALGO = {
    'zhao': 'pin24',
    'twentyfour': 'pin24',
    'twentyeight': 'pin28',
    'thirtytwo': 'pin32',
    'dlink': 'pinDLink',
    'dlink1': 'pinDLink1',
    'asus': 'pinASUS',
    'airocon': 'pinAirocon',
    'trend': 'pinTrendNet',
    'arcady': 'pinEasybox',
    'vacante': 'pinEmpty',
}

# Tags that carry no algorithm (corrupt upstream rows) — explicitly ignored.
TAG_IGNORE = {'003900ee', '427152ee'}


def pins_for_bssid(bssid, tags=None):
    """All candidate computed pins for a BSSID.

    Combines the full OUI-mask suggestions with any explicit pins.csv
    algorithm `tags` (mapped via TAG_TO_ALGO). Returns a de-duplicated,
    order-preserving list of pin strings (an empty-PIN candidate is kept as
    the literal empty string ``''``).
    """
    gen = WPSpin()
    pins = []

    def add(p):
        if p is not None and p not in pins:
            pins.append(p)

    for pin in gen.getSuggestedList(bssid):
        add(pin)
    for tag in (tags or []):
        t = str(tag).lower()
        if t in TAG_IGNORE:
            continue
        algo = TAG_TO_ALGO.get(t)
        if algo:
            add(gen.generate(algo, bssid))
    return pins
