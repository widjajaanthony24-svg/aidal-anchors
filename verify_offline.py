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

    # For a decision logged with client-side hashing (a "digest" field, no
    # input_features/output stored on AIDAL's side — see CANONICAL_FORMAT.md):
    # confirm YOUR OWN retained raw data matches the digest AIDAL sealed.
    python3 verify_offline.py export.json --audit-id aud_xxx --raw-decision my_raw_decision.json

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
  4. (optional, --audit-id + --raw-decision) For a decision logged via
     client-side hashing, recomputes the canonical digest from YOUR OWN
     retained raw data and confirms it matches the "digest" field AIDAL
     sealed into the chain. AIDAL never had your raw data for this kind of
     record, so steps 1-2 alone only prove the digest wasn't altered AFTER
     being sealed — this step is what proves the digest actually
     corresponds to real decision content, and only you can run it, since
     only you still have that content.

Steps 1-2 require ONLY the export file and never touch the network. Step 3
is optional and shells out to your local `gpg` binary rather than
reimplementing OpenPGP signature verification in Python — a real GPG
install is far more trustworthy than a hand-rolled crypto implementation
would be. Step 4 requires only the export file and your own retained data.

No dependencies beyond the Python standard library.
"""
import sys
import json
import hashlib
import argparse
import subprocess
import shutil

# Windows consoles default to cp1252, which can't print the em-dashes used
# throughout this script's output — they'd render as "?" or garbled bytes
# instead of crashing outright, easy to miss. UTF-8 stdout fixes it; no
# effect on Linux/macOS terminals, which are already UTF-8.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Fields AIDAL adds to a decision record AFTER computing its hash. They must
# be excluded here too, or every record appears tampered when nothing was
# touched. This is keyed on the record's own evidence_schema_version, because
# schema v3 moved `compliance` INSIDE the hash — verifying a v2 record with
# v3's list (or vice versa) reports false tampering.
#
# The v3 split is AIDAL's answer to "which parts of this record are evidence,
# and which are advisory?":
#   SEALED   — the decision, its digest, the digest verification result, and
#              the compliance verdict. Changing any of these breaks the hash.
#   ADVISORY — explanation + explanation_source only. Regenerable by design
#              (AIDAL exposes an endpoint to re-run explanation generation),
#              so they cannot be sealed without making a supported operation
#              indistinguishable from tampering. Treat them as commentary,
#              NOT as evidence.
#
# MUST be kept in sync with _NON_HASHED_FIELDS_BY_SCHEMA in aidal-backend's
# api.py. These live in two separate repos with no shared source of truth and
# have drifted once before — change both in the same commit, always.
NON_HASHED_FIELDS_BY_SCHEMA = {
    None: ("_hash", "explanation", "compliance", "explanation_source", "hash_version", "evidence_schema_version"),
    "v2": ("_hash", "explanation", "compliance", "explanation_source", "hash_version", "evidence_schema_version"),
    "v3": ("_hash", "explanation", "explanation_source", "explanation_generated_at",
           "explanation_regenerated", "explanation_originally_generated_at",
           "hash_version", "evidence_schema_version"),
    # v4 seals submitted_by_credential — same exclusion list as v3, because
    # the new field is INSIDE the hash. Records are attributable to a
    # specific, revocable credential from v4 onward.
    "v4": ("_hash", "explanation", "explanation_source", "explanation_generated_at",
           "explanation_regenerated", "explanation_originally_generated_at",
           "hash_version", "evidence_schema_version"),
}


def non_hashed_fields(evidence_schema_version):
    """Field-exclusion list for a record, keyed on that record's own schema version."""
    return NON_HASHED_FIELDS_BY_SCHEMA.get(evidence_schema_version, NON_HASHED_FIELDS_BY_SCHEMA[None])


def compute_hash_v1(data: dict, prev_hash):
    """
    Mirrors AIDAL's original production compute_hash() (2026 launch through
    the client-side-hashing rollout on 2026-08-05):

        payload = json.dumps(data, sort_keys=True, default=str) + (prev_hash or "GENESIS")
        return hashlib.sha256(payload.encode()).hexdigest()

    sort_keys=True is what makes this deterministic regardless of dict
    ordering after a JSON export/re-parse round trip. Every record logged
    under hash_version "v1" or absent (records from before the field
    existed) must keep verifying against exactly this serialization
    forever — see HASH_METHODS below.
    """
    payload = json.dumps(data, sort_keys=True, default=str) + (prev_hash or "GENESIS")
    return hashlib.sha256(payload.encode()).hexdigest()


def compute_hash_v2(data: dict, prev_hash):
    """
    Canonical Evidence Format v1 (see CANONICAL_FORMAT.md in aidal-backend)
    — compact separators, UTF-8 without forced ASCII-escaping, sorted keys.
    Adopted 2026-08-05 alongside client-side hashing, so a customer's own
    JSON library in any language reproduces identical bytes to AIDAL's.
    Records logged from that point on carry hash_version "v2".
    """
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str) + (prev_hash or "GENESIS")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_digest(data: dict) -> str:
    """
    AIDAL Canonical Evidence Format v1 (see CANONICAL_FORMAT.md) — the same
    algorithm a client uses to compute a decision's `digest` before sending
    only that digest to AIDAL. Used by verify_digest() below to recompute a
    digest from YOUR OWN retained raw decision data and confirm it matches
    what AIDAL sealed. Deliberately identical to compute_hash_v2's payload
    serialization (same format, different purpose: this covers only a
    decision's own content, never company_id/prev_hash/logged_at, which a
    client doesn't know and shouldn't need to).
    """
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# Records logged before hash_version existed at all have no such key
# (json.load gives None for a missing key via .get()) — they used, and
# always used, the v1 method.
HASH_METHODS = {
    None: compute_hash_v1,
    "v1": compute_hash_v1,
    "v2": compute_hash_v2,
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
    digest_mismatches = []
    regenerated = []
    for i, record in enumerate(decisions):
        audit_id = record.get("audit_id", "?")
        d = dict(record.get("decision") or {})
        stored_hash = d.get("_hash")
        if not stored_hash:
            return False, f"TAMPERED AT RECORD #{i} (audit_id={audit_id}): no stored hash found on this record."

        # Schema v3+ seals the result of AIDAL's digest cross-check into the
        # record. A sealed "MISMATCH" means that at seal time, the digest the
        # client supplied did NOT match the raw data they sent alongside it.
        # The chain is still intact — nobody altered the record afterwards —
        # but the record's own contents are internally inconsistent, which is
        # exactly the kind of thing that must not stay buried in an old HTTP
        # response. Collected and reported below rather than failing the
        # chain check, because these are two genuinely different findings.
        if d.get("digest_verification") == "MISMATCH":
            digest_mismatches.append(audit_id)

        # An explanation regenerated after sealing is commentary about a past
        # decision, not evidence of what was said at the time — and it is not
        # covered by the hash. Surfaced so nobody reads a 2029-generated
        # explanation as if it had been produced alongside a 2026 decision.
        if d.get("explanation_regenerated"):
            regenerated.append((audit_id, d.get("logged_at"), d.get("explanation_generated_at")))

        verify_data = {k: v for k, v in d.items() if k not in non_hashed_fields(d.get("evidence_schema_version"))}
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

    msg = f"VERIFIED — {len(decisions)} records, full chain intact, no tampering detected."
    if digest_mismatches:
        msg += (
            f"\n\nWARNING — {len(digest_mismatches)} record(s) were sealed with "
            f"digest_verification=\"MISMATCH\": at the time these were logged, the digest the client "
            f"supplied did not match the raw decision data sent with it. The chain is intact (nothing "
            f"was altered after sealing), but these records are internally inconsistent and the "
            f"discrepancy was never resolved:\n  " + "\n  ".join(digest_mismatches)
        )
    if regenerated:
        msg += (
            f"\n\nNOTE — {len(regenerated)} record(s) carry an explanation that was regenerated AFTER "
            f"the decision was sealed. Explanations are advisory and not covered by the hash, so this is "
            f"not tampering — but do not read these as the explanation that existed at decision time:\n  "
            + "\n  ".join(f"{aid}  sealed {sealed}  explanation generated {gen}" for aid, sealed, gen in regenerated)
        )
    return True, msg


def verify_digest(decisions: list, audit_id: str, raw_decision_path: str):
    """
    For a decision logged via client-side hashing (a "digest" field on the
    record, no input_features/output stored on AIDAL's side): recomputes
    the canonical digest from your own retained raw data and confirms it
    matches what AIDAL sealed. Returns (ok: bool, message: str).

    raw_decision_path should contain JSON shaped like what canonical_digest()
    expects — {"input_features": {...}, "output": {...}} — i.e. exactly what
    your own code hashed locally before sending AIDAL only the digest.
    """
    record = next((r for r in decisions if r.get("audit_id") == audit_id), None)
    if record is None:
        return False, f"No record with audit_id={audit_id} found in this export."

    d = record.get("decision") or {}
    stored_digest = d.get("digest")
    if not stored_digest:
        return False, (
            f"Record {audit_id} has no 'digest' field — this record was logged via the "
            "server-side hashing path (raw input_features/output sent to AIDAL directly), "
            "not client-side hashing. There's nothing for this check to compare against; "
            "the chain-hash check above already covers this record."
        )

    try:
        with open(raw_decision_path) as f:
            raw_data = json.load(f)
    except Exception as e:
        return False, f"Could not read raw decision data from {raw_decision_path}: {e}"

    recomputed = canonical_digest(raw_data)
    if recomputed != stored_digest:
        return False, (
            f"DIGEST MISMATCH for {audit_id}: your raw data does NOT match what AIDAL sealed.\n"
            f"  stored digest:     {stored_digest}\n"
            f"  recomputed digest: {recomputed}\n"
            "Either the raw data you provided isn't what was actually hashed at the time, or "
            "your JSON serialization doesn't match CANONICAL_FORMAT.md exactly — check key "
            "sorting, whitespace, and ASCII-escaping in whatever produced raw_decision_path."
        )
    return True, f"DIGEST VERIFIED — {audit_id}: your raw data matches the digest AIDAL sealed."


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
    parser.add_argument("--audit-id", help="Check a specific client-side-hashed record's digest (use with --raw-decision)")
    parser.add_argument("--raw-decision", help="Path to your own retained raw decision data — {\"input_features\":..., \"output\":...} — for the --audit-id digest check")
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

    digest_failed = False
    if args.audit_id and args.raw_decision:
        digest_ok, digest_message = verify_digest(decisions or [], args.audit_id, args.raw_decision)
        print(digest_message)
        digest_failed = not digest_ok
    elif args.audit_id or args.raw_decision:
        print("Both --audit-id and --raw-decision are required to check a digest — skipping that step.")

    sys.exit(0 if (ok and not anchor_failed and not digest_failed) else 1)


if __name__ == "__main__":
    main()
