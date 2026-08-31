#!/usr/bin/env python3
"""Fail closed release preflight for a directory of public assets."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from verify_review_gate import verify as verify_gate

REQUIRED_FILES = {"SHA256SUMS", "provenance.json", "sbom.spdx.json", "signature-verification.json"}


def fail(message):
    raise ValueError(message)


def files(directory):
    result = {path.relative_to(directory).as_posix(): path for path in directory.rglob("*") if path.is_file()}
    if not result:
        fail("release contains no assets")
    if any(name.startswith(".") or "/." in name for name in result):
        fail("hidden release assets are not allowed")
    return result


def parse_sums(path, asset_names):
    expected = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or len(parts[0]) != 64 or any(c not in "0123456789abcdef" for c in parts[0]):
            fail("SHA256SUMS contains an invalid entry")
        name = parts[1].removeprefix("*")
        if name.startswith("/") or ".." in Path(name).parts or name in expected:
            fail("SHA256SUMS contains unsafe or duplicate asset name")
        expected[name] = parts[0]
    required = asset_names - {"SHA256SUMS"}
    if set(expected) != required:
        fail("SHA256SUMS must bind every release asset except itself, with relative names")
    return expected


def verify_metadata(asset_names, sums, assets):
    deliverables = {name: value for name, value in sums.items() if name not in {"provenance.json", "sbom.spdx.json", "signature-verification.json"}}
    if not deliverables:
        fail("release must contain at least one non-metadata deliverable")
    provenance = json.loads(assets["provenance.json"].read_text(encoding="utf-8"))
    if provenance.get("apiVersion") != "router-infra-provenance/v1":
        fail("provenance apiVersion must be router-infra-provenance/v1")
    subject = provenance.get("subject")
    if not isinstance(subject, dict) or subject != deliverables:
        fail("provenance.subject must exactly bind non-metadata deliverables")
    sbom = json.loads(assets["sbom.spdx.json"].read_text(encoding="utf-8"))
    if sbom.get("spdxVersion") is None or not isinstance(sbom.get("name"), str):
        fail("SBOM must be an SPDX JSON document with a name")
    report = json.loads(assets["signature-verification.json"].read_text(encoding="utf-8"))
    if report.get("apiVersion") != "router-infra-signature-verification/v1":
        fail("signature report apiVersion is invalid")
    if report.get("status") != "verified" or not isinstance(report.get("verifier"), str) or not report["verifier"].strip():
        fail("an external signature verifier must report verified status")
    if report.get("subject") != deliverables:
        fail("signature report must exactly bind non-metadata deliverables")


def preflight(root, assets_dir, gate_path):
    assets = files(assets_dir)
    missing = REQUIRED_FILES - set(assets)
    if missing:
        fail("release is missing required metadata: " + ", ".join(sorted(missing)))
    sums = parse_sums(assets["SHA256SUMS"], set(assets))
    for name, expected in sums.items():
        actual = hashlib.sha256(assets[name].read_bytes()).hexdigest()
        if actual != expected:
            fail(f"SHA256SUMS does not match {name}")
    verify_metadata(set(assets), sums, assets)
    gate = json.loads(gate_path.read_text(encoding="utf-8"))
    verify_gate(root, gate, assets_dir, "public_release")
    bound = {entry["path"]: entry["sha256"] for entry in [gate["subject"], *gate["evidence"]]}
    if bound != sums:
        fail("public_release ReviewGate must exactly bind every hashed release asset")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        preflight(args.root.resolve(), args.assets_dir.resolve(), args.gate.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"release preflight failed: {error}", file=sys.stderr)
        return 1
    print("release preflight passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
