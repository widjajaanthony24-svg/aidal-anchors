#!/usr/bin/env python3
"""
AIDAL Offline Chain Verifier
============================
Run this without trusting AIDAL and without contacting our servers.

This is the whole point of the hash chain: "you don't have to trust us,
just the math" is only actually true if you can check the math yourself,
with no AIDAL account and no dependency on our infrastructure staying up.
This script does that. It is intentionally short enough to read top to
bottom in a few minutes — please do, rather than taking our word for it.

USAGE
-----
    python3 verify_offline.py aidal_export_yourcompany_2026-07-15.json

    # Optionally also check the day's public GPG-signed anchor:
    python3 verify_offline.py export.json --anchor anchor_2026-07-15.txt --pubkey PUBLIC_KEY.asc

WHAT THIS CHECKS
----------------
  1. Recomputes every decision's hash using AIDAL's exact production
     hashing logic and confirms it matches the hash stored at export time.
  2. Confirms each record's prev_hash correctly points to the previous
     record's hash, walking the full chain end to end.
  3. (optional) Verifies the GPG signature on a downloaded daily anchor
     file, confirming it's genuinely from AIDAL and unaltered since
     publication. Note: the current anchor publishes a rolled-up hash
     across ALL companies' activity, not a per-company breakdown — see
     the verify_anchor() docstring below for exactly what this can and
     can't prove about your own specific records.

Steps 1-2 require ONLY the export file and never touch the network. Step 3
is optional and shells out to your local `gpg` binary rather than
reimplementing OpenPGP signature verification in Python — a real GPG
install is far more trustworthy than a hand-rolled crypto implementation
would be.

No dependencies beyond the Python standard library.
"""
import sys
import json
import hashlib
import argparse
import subprocess
import shutil

# These are the exact fields the AIDAL server adds to a decision record
# AFTER computing its hash (see compute_hash's call site in log_decision,
# and _NON_HASHED_FIELDS in api.py). They must be excluded here too, or
# every record will appear tampered even when nothing was touched. If
# AIDAL ever adds a new post-hash field to decision records, this list
# and the server's _NON_HASHED_FIELDS constant both need updating together.
#
# hash_version is one of these fields, not a hash input — see compute_hash_v1
# below for why that split matters.
NON_HASHED_FIELDS = ("_hash", "explanation", "compliance", "explanation_source", "hash_version")


def compute_hash_v1(data: dict, prev_hash):
    """
    Mirrors AIDAL's production compute_hash() exactly:

        payload = json.dumps(data, sort_keys=True, default=str) + (prev_hash or "GENESIS")
        return hashlib.sha256(payload.encode()).hexdigest()

    sort_keys=True is what makes this deterministic regardless of dict
    ordering after a JSON export/re-parse round trip. Do not "improve"
    this serialization (e.g. by adding explicit separators) without also
    changing it on the server — the two must stay byte-for-byte identical,
    or this verifier will report false tampering on untouched records.

    This has been the ONLY hashing method AIDAL has ever used (confirmed
    against full git history — no drift, ever). It's named _v1 and dispatched
    through HASH_METHODS below purely so that IF a genuine v2 method is ever
    needed, old records (which have no hash_version field at all) and new
    ones (tagged hash_version="v1" or later "v2") can both still be verified
    correctly in the same run, instead of forcing a choice between "support
    old records" and "fix the serialization."
    """
    payload = json.dumps(data, sort_keys=True, default=str) + (prev_hash or "GENESIS")
    return hashlib.sha256(payload.encode()).hexdigest()


# Records logged before this field existed have no "hash_version" key at all
# (json.load gives None for a missing key via .get()) — they used, and always
# used, the v1 method. Add "v2": compute_hash_v2 here the day a real second
# method exists; until then this dict has exactly one real entry plus the
# None-means-v1 backward-compatibility alias.
HASH_METHODS = {
    None: compute_hash_v1,
    "v1": compute_hash_v1,
}


def compute_hash(data: dict, prev_hash, hash_version=None):
    method = HASH_METHODS.get(hash_version)
    if method is None:
        raise ValueError(
            f"Unknown hash_version {hash_version!r} — this verifier doesn't know how "
            "to check this record. You likely need a newer version of verify_offline.py; "
            "check aidal-anchors for an update."
        )
    return method(data, prev_hash)


def verify_chain(decisions: list):
    """Walks the full chain. Returns (ok: bool, message: str)."""
    if not decisions:
        return False, "No decisions in this export."

    prev_hash = None
    for i, record in enumerate(decisions):
        audit_id = record.get("audit_id", "?")
        d = dict(record.get("decision") or {})
        stored_hash = d.get("_hash")
        if not stored_hash:
            return False, f"TAMPERED AT RECORD #{i} (audit_id={audit_id}): no stored hash found on this record."

        verify_data = {k: v for k, v in d.items() if k not in NON_HASHED_FIELDS}
        hash_version = d.get("hash_version")  # None on records logged before this field existed
        try:
            computed = compute_hash(verify_data, prev_hash, hash_version)
        except ValueError as e:
            return False, f"CANNOT VERIFY RECORD #{i} (audit_id={audit_id}): {e}"
        if computed != stored_hash:
            return False, (
                f"TAMPERED AT RECORD #{i} (audit_id={audit_id}): "
                f"stored hash does not match the recomputed hash.\n"
                f"  hash_version: {hash_version!r}\n"
                f"  stored:    {stored_hash}\n"
                f"  recomputed:{computed}"
            )

        if i > 0:
            record_prev = record.get("prev_hash")
            if record_prev != prev_hash:
                return False, (
                    f"TAMPERED AT RECORD #{i} (audit_id={audit_id}): "
                    f"this record's prev_hash does not match the previous record's hash — "
                    f"the chain link is broken here."
                )

        prev_hash = stored_hash

    return True, f"VERIFIED — {len(decisions)} records, full chain intact, no tampering detected."


def verify_anchor(anchor_data_path: str, pubkey_path: str) -> str:
    """
    Checks the GPG signature on a downloaded daily anchor.

    AIDAL publishes each day's anchor as TWO files in aidal-anchors:
    `anchors/{date}.json` (the data) and `anchors/{date}.json.asc` (a
    detached GPG signature over that exact file). Pass the .json path here
    — the matching .asc is expected alongside it (same convention GPG
    itself uses for detached signatures).

    IMPORTANT — read this before relying on it: the anchor's `master_hash`
    is SHA-256 of the sorted list of every decision hash across ALL
    companies on the platform for a trailing 7-day window (see
    compute_master_hash / get_all_hashes_today in the AIDAL backend). The
    anchor file does NOT publish the individual hash list it was built
    from — only the rolled-up value and a record count. That means there
    is currently no way, even in principle, for a single company's export
    to be mathematically cross-checked against master_hash using only
    that company's own data — the ingredients for that specific check
    aren't public.

    What this function DOES verify, and it's still meaningful: that the
    anchor file is genuinely signed by AIDAL's private key and hasn't been
    altered since publication. Combined with the chain check above (which
    needs no network access and no anchor at all), that's real evidence —
    it just isn't a per-record proof against the anchor specifically. If
    AIDAL later publishes the full daily hash list (not just the rollup),
    this script can be extended to do that stronger check too.
    """
    gpg_bin = shutil.which("gpg") or shutil.which("gpg2")
    if not gpg_bin:
        return "ANCHOR CHECK SKIPPED — gpg not found locally. Install GnuPG (gpg) to verify the anchor's signature."

    sig_path = anchor_data_path + ".asc"
    try:
        with open(sig_path):
            pass
    except FileNotFoundError:
        return f"ANCHOR CHECK SKIPPED — no signature file found at {sig_path} (expected alongside {anchor_data_path})."

    try:
        subprocess.run([gpg_bin, "--import", pubkey_path], capture_output=True, text=True)
        verify_res = subprocess.run([gpg_bin, "--verify", sig_path, anchor_data_path], capture_output=True, text=True)
        if verify_res.returncode != 0:
            return f"ANCHOR SIGNATURE INVALID:\n{verify_res.stderr}"
        return (
            "ANCHOR SIGNATURE VALID — this anchor file is genuinely from AIDAL and unaltered since "
            "publication. Note: this confirms the anchor itself is authentic, not that any specific "
            "record of yours is included in it — see this function's docstring for why."
        )
    except Exception as e:
        return f"ANCHOR CHECK ERROR: {e}"


def main():
    parser = argparse.ArgumentParser(
        description="Verify an AIDAL decision export without trusting AIDAL or contacting our servers."
    )
    parser.add_argument("export_file", help="Path to an aidal_export_*.json file")
    parser.add_argument("--anchor", help="Path to a downloaded anchors/{date}.json file (its .json.asc signature must be alongside it)")
    parser.add_argument("--pubkey", help="Path to PUBLIC_KEY.asc (optional, used with --anchor)")
    args = parser.parse_args()

    with open(args.export_file) as f:
        raw = json.load(f)

    # Accept either the dashboard's export envelope {..., "decisions": [...]}
    # or a bare array of decision records.
    decisions = raw.get("decisions") if isinstance(raw, dict) else raw

    ok, message = verify_chain(decisions or [])
    print(message)

    anchor_failed = False
    if args.anchor and args.pubkey:
        if not ok:
            print("Skipping anchor check — chain verification already failed above.")
        else:
            anchor_result = verify_anchor(args.anchor, args.pubkey)
            print(anchor_result)
            if anchor_result.startswith("ANCHOR SIGNATURE INVALID"):
                anchor_failed = True
    elif args.anchor or args.pubkey:
        print("Both --anchor and --pubkey are required to check the daily anchor — skipping that step.")

    sys.exit(0 if (ok and not anchor_failed) else 1)


if __name__ == "__main__":
    main()
