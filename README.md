# aidal-anchors

Public, independent proof that AIDAL's decision records existed and were unaltered on a given date — designed to hold up even if AIDAL's own servers are gone.

## What's in this repo

- **`anchors/{date}.json`** — one file per day. Contains `master_hash`: SHA-256 of the sorted list of every decision hash logged on the platform in the trailing 7-day window as of that date, plus a record count and timestamp.
- **`anchors/{date}.json.asc`** — a detached GPG signature over that exact file, signed with AIDAL's private key.
- **`PUBLIC_KEY.asc`** — AIDAL's public key, so you can verify those signatures yourself.
- **`verify_offline.py`** — a standalone script (see below) that verifies your own exported decision chain without needing an AIDAL account, without trusting AIDAL, and without any network call for the core check.

## Run this without trusting AIDAL or contacting our servers

That's the point of all of this. `verify_offline.py` uses only the Python standard library — no dependencies to install, nothing to trust but your own Python interpreter and (optionally) your local `gpg`.

```bash
# Export your decisions from the AIDAL dashboard first (Overview page →
# "Export All Decisions"), then:
python3 verify_offline.py aidal_export_yourcompany_2026-07-15.json
```

This recomputes every decision's hash using AIDAL's exact production hashing logic, confirms it matches what was stored, and walks the full chain confirming each record correctly links to the one before it. If anything was altered, it tells you exactly which record.

### Optional: check a daily anchor's signature too

```bash
python3 verify_offline.py export.json \
  --anchor anchors/2026-07-15.json \
  --pubkey PUBLIC_KEY.asc
```

This confirms the anchor file is genuinely signed by AIDAL and unaltered since publication. **Read the `verify_anchor()` docstring in the script before relying on this** — `master_hash` is a rollup across all companies on the platform, not a per-company value, so this step verifies the anchor's authenticity, not that your specific record is provably included in it. The chain check above doesn't have that limitation and needs no anchor at all.

## Known gap: 3 early anchors don't currently verify

If you check `2026-05-01.json`, `2026-05-02.json`, or `2026-05-03.json` against their `.asc` files, GPG will report a bad signature. This was caught during testing (not by an external report) — those 3 early files' signatures don't match their currently-published content. Every anchor from `2026-05-04` onward verifies correctly (73 of 77 total files as of this writing). `2026-04-30`, the very first anchor, predates signing being implemented at all and has no `.asc`.

## License

MIT — see `LICENSE`.
