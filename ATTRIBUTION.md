# Attribution & License

The clean rebuild in `wifux/` is a derivative work and is licensed under the
**GNU General Public License v3.0** (see [LICENSE](LICENSE)).

## Lineage

The WPS engine, PIN-generation algorithms, scanner and the vulnerable-OUI data
are ported from the **OneShot** project and its forks:

- **OneShot** — original by **rofl0r**, developed by **drygdryg**
- **kimocoder/OneShot** — `WPSpin`, `NetworkAddress`, `Companion`, `WiFiScanner`, OUI mask tables
- **fulvius31/OneShot** — `pinTrendNet`, `pinEasybox` (Arcadyan), `pinArris`, and `pins.csv`
- **pixiewps** (wiire) — the Pixie-Dust tool invoked by the engine (GPLv3)

It also builds on **WiFuX** by **MD Sakibur Rahman (MSR)**
(<https://github.com/msrofficial/WiFuX>): the `vulnwsc.txt` list and the
`RouterModels` metadata exported to `database/router_models.json`.

## Data

- `database/pins.csv` — PIN/OUI pairs from the OneShot (fulvius31) database.
- `database/oui_masks.json` — OUI→algorithm masks from OneShot's `WPSpin._suggest`.
- `database/router_models.json` — exported from the WiFuX `RouterModels` data.
- `vulnwsc.txt` — merged WPS-vulnerable model list (WiFuX + OneShot forks).

Upstream projects keep their own licenses; their attribution is retained here
and in the source file headers.

## Use

For **authorized security testing only** — on networks you own or have explicit
written permission to test. WPS PIN / Pixie-Dust attacks against networks you do
not own are illegal in most jurisdictions. The authors and contributors accept
no liability for misuse.
