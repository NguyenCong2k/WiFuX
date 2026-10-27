<div align="center">

```
██╗    ██╗██╗███████╗██╗   ██╗██╗  ██╗
██║    ██║██║██╔════╝██║   ██║╚██╗██╔╝
██║ █╗ ██║██║█████╗  ██║   ██║ ╚███╔╝
██║███╗██║██║██╔══╝  ██║   ██║ ██╔██╗
╚███╔███╔╝██║██║     ╚██████╔╝██╔╝ ██╗
 ╚══╝╚══╝ ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝
```

**WiFuX v2.0** — WPS Security Auditing Tool for Android / Termux

[![Version](https://img.shields.io/badge/version-2.0-brightgreen)](https://github.com/msrofficial/WiFuX/releases)
[![Platform](https://img.shields.io/badge/platform-Android%20%2F%20Termux-blue)](https://termux.dev)
[![Visitors](https://visitor-badge.laobi.icu/badge?page_id=msrofficial.wifux)](https://github.com/msrofficial/WiFuX)

</div>

---

## Overview

WiFuX is a WPS (Wi-Fi Protected Setup) security auditing tool built for Android devices running Termux. It automates Pixie Dust and Bruteforce attacks against WPS-enabled routers, allowing security researchers and network administrators to evaluate the strength of their own wireless infrastructure.

WiFuX v2.0 is a complete rewrite of the original v1 engine, introducing a global command system, session management, reporting, improved stability, and a built-in interactive help guide — all optimized for Android / Termux.

> This tool is intended for authorized security testing only. Only use it on networks you own or have explicit permission to test.

---

## Clean rebuild — `wifux/` package

This branch adds an **un-obfuscated, source-level rebuild** of the engine as a
plain Python package (`wifux/`), replacing the packed `main.py` blob. It is pure
standard library (runs on any CPython 3.6+ — no bytecode/version lock):

| Module | Purpose |
|---|---|
| `wifux/database.py` | WPS vuln & PIN database (`router_models.json`, `pins.csv`, `vulnwsc.txt`) |
| `wifux/wps.py` | WPS PIN generation — 24/28/32-bit, D-Link, ASUS, Airocon, TrendNet, EasyBox/Arcadyan, Arris, static |
| `wifux/companion.py` | WPS attack engine (wpa_supplicant + pixiewps) |
| `wifux/scanner.py` | Wi-Fi / WPS scanner |
| `wifux/__main__.py` | command-line entrypoint |

### Run

```bash
# offline — list candidate PINs for a BSSID (no root / no hardware)
python -m wifux --pins -b AA:BB:CC:DD:EE:FF

# live (needs root + wpa_supplicant + pixiewps + iw)
sudo python -m wifux -i wlan0 -K                       # scan, pick a target, Pixie Dust
sudo python -m wifux -i wlan0 -b AA:BB:CC:DD:EE:FF -K   # Pixie Dust on one AP
sudo python -m wifux -i wlan0 -b AA:BB:CC:DD:EE:FF -B   # online bruteforce
```

Scanning uses `iw` in **managed mode**, so no monitor mode is required (works on
internal Wi-Fi).

### Tests

```bash
python -m tests.test_wps && python -m tests.test_database && python -m tests.test_companion
```

> **Status:** database + PIN generation are complete and tested. The attack
> engine and scanner are ported and compile/import cleanly but have **not been
> live-tested** — verify on your own hardware before relying on them.

This rebuild is **GPLv3**, derived from OneShot — see [ATTRIBUTION.md](ATTRIBUTION.md).

---
<div align="center">

[![Support this project](https://img.shields.io/badge/Support%20this%20project-FFD700?style=for-the-badge&logo=ko-fi&logoColor=black)](https://www.supportkori.com/msrsakibur)
 
  <a href="https://youtu.be/Y73jDqTqkxI">
    <img src="https://img.shields.io/badge/wifux_full_setup_video_tutorial-2EA043?style=for-the-badge&logo=android&logoColor=white" alt="WiFuX Full Setup Video Tutorial">
  </a><br> </div>

## Requirements

- Android device with root access (Magisk or KernelSU)
- [Termux](https://f-droid.org/en/packages/com.termux/) installed (from fdroid. not from playstore)
- Root-capable WiFi adapter (internal wlan0 or external)

---

## Installation

WiFuX v2.0 installs globally. Once set up, you can run it from any directory using the `wifux` command.

### Method 1 — One Command (Recommended)

```bash
curl -sLo installer.sh https://raw.githubusercontent.com/msrofficial/WiFuX/main/installer.sh && bash installer.sh
```

This will automatically update packages, install all dependencies, clone the repository, and register the `wifux` global command.

### Method 2 — Manual

```bash
pkg update && pkg upgrade -y
pkg install root-repo git tsu python wpa-supplicant pixiewps iw -y
git clone https://github.com/msrofficial/WiFuX
cd WiFuX
chmod +x installer.sh
bash installer.sh
```

---

## Database

WiFuX uses two layers of router data:

- `vulnwsc.txt` — external list of WPS-vulnerable router models, read by `--vuln-list` / `--auto-vuln-list`.
- `RouterModels` inside `main.py` — embedded vendor metadata: default PINs, default credentials, Pixie Dust rating, and known vulnerabilities.

This upgrade branch refreshes the external list and exports the embedded database to `database/router_models.json` for future source-level refactors.

Refresh the external list:

```bash
python3 scripts/update_database.py
```

See [database/README.md](database/README.md) for sources and attribution.

---

## Commands

| Command | Description |
|---|---|
| `wifux` | Run WiFuX with default settings (wlan0 + Pixie Dust) |
| `wifux menu` | Open WiFuX interactive menu without auto-attack |
| `wifux old` | Run the legacy engine (w1.py) with wlan0 |
| `wifux update` | Pull latest updates from GitHub |
| `wifux help` | Open the built-in interactive help guide |
| `wifux fix` | Fix root / superuser issues |
| `wifux contact` | Contact the developer |

---

## Usage

**Default run — scan nearby networks and attack:**
```bash
wifux
```

**Pixie Dust on a specific router:**
```bash
wifux -i wlan0 -b <BSSID> -K
```

**Bruteforce on a specific router:**
```bash
wifux -i wlan0 -b <BSSID> -B
```

**Pixie Dust without touching Android WiFi settings:**
```bash
wifux -i wlan0 -K --dts
```

**Resume a previous session:**
```bash
wifux --list-sessions
wifux -i wlan0 --resume-session <BSSID>
```

**Generate an HTML report:**
```bash
wifux -i wlan0 -b <BSSID> -K --html-report
```

For the full argument reference, run `wifux help` and select option 5.

---

## Troubleshooting

**"No superuser binary detected"**

Run the built-in fix first:
```bash
wifux fix
```

If the issue persists, use the dedicated fix script:
```bash
curl -sO https://raw.githubusercontent.com/msrofficial/fix-termux-root/main/fix.sh && chmod +x fix.sh && ./fix.sh
```

Manual solutions: [github.com/msrofficial/fix-termux-root](https://github.com/msrofficial/fix-termux-root)

---

**Common issues and fixes**

| Problem | Fix |
|---|---|
| "Run it as root" error | Run `su` first, then retry |
| "Unable to up interface" | Check interface name with `ip link show` |
| wpa_supplicant crash | Run `pkill wpa_supplicant`, then retry |
| No WPS networks found | Disable Location/GPS, toggle WiFi off and on |
| Router keeps locking | Add `-d 3` delay or use `--lock-delay 120` |
| WiFi rfkill blocked | Use `--handle-rfkill` or run `rfkill unblock wifi` |
| Pixie Dust not working | Router may not be vulnerable — switch to Bruteforce (`-B`) |

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a full list of changes between versions.

---

## Disclaimer

WiFuX is provided for educational and authorized penetration testing purposes only. You are solely responsible for ensuring you have permission to test any network. The author is not liable for any misuse, damage, or legal consequences resulting from the use of this tool.

---

## Author

**MD Sakibur Rahman (MSR)**

| Platform | Link |
|---|---|
| GitHub | [msrofficial](https://github.com/msrofficial) |
| Facebook | [sakibur.msr](https://facebook.com/msr.sakibur) |
| Instagram | [msr.sakibur](https://instagram.com/msr.sakibur) |
| Telegram | [@msrofficial](https://t.me/msr0official) |
| Website | [msrsakibur.pro.bd](https://msrsakibur.pro.bd) |

Honorable mentions include: rofl0r, Rayhan, Alamin, Sojib, Sanji, Mustakin, Sakib, rizzi

---

<div align="center">
If WiFuX has been useful, consider leaving a star on GitHub.<br>
It helps the project grow and encourages further development.
</div>
