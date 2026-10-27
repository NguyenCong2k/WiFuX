# WiFuX database

This directory contains data used by the WiFuX upgrade branch.

## Files

| File | Purpose |
|---|---|
| `router_models.json` | Router/vendor metadata extracted from `RouterModels` in the packed `main.py` payload: default PINs, default credentials, Pixie Dust rating, known vulnerabilities, model lists. |
| `pins.csv` | PIN/OUI pairs imported from the maintained OneShot fork by fulvius31. Format: `PIN,OUI`. |
| `vuln_sources.json` | Metadata for the upstream sources used to build `vulnwsc.txt`. |

The main `vulnwsc.txt` remains at the repository root because WiFuX reads it from there.

## Update

```bash
python3 scripts/update_database.py
```

Offline merge (keep local data only):

```bash
python3 scripts/update_database.py --offline
```

## Sources

- WiFuX: https://github.com/msrofficial/WiFuX
- OneShot: https://github.com/kimocoder/OneShot
- OneShot-Extended: https://github.com/chkndrp/OneShot-Extended
- OneShot (fulvius31 fork): https://github.com/fulvius31/OneShot

## Notes

- `router_models.json` is an export of data embedded in the packed `main.py`. The packed file itself is not modified by this branch. Use the JSON as the source of truth for future source-level refactors.
- `vulnwsc.txt` is deduplicated case-insensitively and sorted alphabetically.
- Upstream projects have their own licenses. Keep their attribution when redistributing the data.
