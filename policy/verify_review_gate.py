#!/usr/bin/env python3
"""Verify an infra/v1 ReviewGate binds exact repository-relative bytes."""
import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath

SCOPES = {"verified_promotion", "regulatory_change", "deployment", "public_release"}


def fail(message):
    raise ValueError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_file(root, name, alternate_root=None):
    relative = PurePosixPath(name)
    if not name or relative.is_absolute() or ".." in relative.parts:
        fail(f"unsafe repository-relative path: {name!r}")
    for base in (root, alternate_root):
        if base is None:
            continue
        candidate = (base / relative).resolve()
        if base not in candidate.parents or not candidate.is_file():
            continue
        return candidate
    fail(f"bound file is missing: {name}")


def verify_entry(root, entry, label, alternate_root=None):
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
        fail(f"{label} must contain exactly path and sha256")
    expected = entry["sha256"]
    if not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        fail(f"{label}.sha256 must be lowercase SHA-256")
    if sha256(safe_file(root, entry["path"], alternate_root)) != expected:
        fail(f"{label} hash does not match current bytes: {entry['path']}")


def verify(root, gate, alternate_root=None, required_scope=None):
    required = {"apiVersion", "kind", "scope", "subject", "evidence", "review"}
    allowed = required | {"base"}
    if not isinstance(gate, dict) or not required <= set(gate) or set(gate) - allowed:
        fail("gate has missing or unknown top-level fields")
    if gate["apiVersion"] != "router-infra/v1" or gate["kind"] != "ReviewGate":
        fail("not a router-infra/v1 ReviewGate")
    if gate["scope"] not in SCOPES or (required_scope and gate["scope"] != required_scope):
        fail("gate has an invalid or unexpected scope")
    verify_entry(root, gate["subject"], "subject", alternate_root)
    if "base" in gate:
        verify_entry(root, gate["base"], "base", alternate_root)
    if not isinstance(gate["evidence"], list) or not gate["evidence"]:
        fail("evidence must be a non-empty array")
    for index, item in enumerate(gate["evidence"]):
        verify_entry(root, item, f"evidence[{index}]", alternate_root)
    review = gate["review"]
    if not isinstance(review, dict) or set(review) != {"required", "reviewer", "reviewedAt", "decision"}:
        fail("review must contain exactly required, reviewer, reviewedAt, and decision")
    if review["required"] is not True or review["decision"] != "accepted":
        fail("gate does not contain an accepted required review")
    if not all(isinstance(review[key], str) and review[key].strip() for key in ("reviewer", "reviewedAt")):
        fail("reviewer and reviewedAt are required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gate", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--assets-dir", type=Path)
    parser.add_argument("--require-scope", choices=sorted(SCOPES))
    args = parser.parse_args()
    try:
        verify(args.root.resolve(), json.loads(args.gate.read_text(encoding="utf-8")),
               args.assets_dir.resolve() if args.assets_dir else None, args.require_scope)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"review gate rejected: {error}", file=sys.stderr)
        return 1
    print("review gate accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
