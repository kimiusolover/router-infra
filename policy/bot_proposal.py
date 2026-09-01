#!/usr/bin/env python3
"""Create and validate the data-only handoff between bot workflow stages."""
import argparse
import hashlib
import json
from pathlib import Path


API_VERSION = "router-infra-bot-proposal/v1"


def fail(message):
    raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def commit(value, label):
    if not isinstance(value, str) or len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
        fail(f"{label} must be a 40-character lowercase commit SHA")


def string_list(value, label, required=False):
    if not isinstance(value, list) or (required and not value) or not all(isinstance(item, str) and item.strip() for item in value):
        fail(f"{label} must be {'a non-empty ' if required else 'an '}array of non-empty strings")


def read_lines(value):
    return [line.strip() for line in value.splitlines() if line.strip()]


def create(args):
    manifest = {
        "apiVersion": API_VERSION,
        "baseCommit": args.base_commit,
        "patch": {"path": "proposal.patch", "sha256": digest(args.patch)},
        "allowedChangePaths": read_lines(args.allowed_change_paths),
        "protectedPaths": read_lines(args.protected_paths),
        "title": args.title,
        "body": args.body,
    }
    validate(manifest, args.patch.parent)
    args.output.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")


def validate(manifest, root):
    required = {"apiVersion", "baseCommit", "patch", "allowedChangePaths", "protectedPaths", "title", "body"}
    if not isinstance(manifest, dict) or set(manifest) != required or manifest["apiVersion"] != API_VERSION:
        fail("invalid bot proposal manifest")
    commit(manifest["baseCommit"], "baseCommit")
    patch = manifest["patch"]
    if not isinstance(patch, dict) or set(patch) != {"path", "sha256"} or patch["path"] != "proposal.patch":
        fail("manifest patch must name proposal.patch")
    if not isinstance(patch["sha256"], str) or len(patch["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in patch["sha256"]):
        fail("manifest patch.sha256 must be lowercase SHA-256")
    patch_path = root / patch["path"]
    if not patch_path.is_file() or digest(patch_path) != patch["sha256"]:
        fail("proposal patch hash does not match manifest")
    string_list(manifest["allowedChangePaths"], "allowedChangePaths", required=True)
    string_list(manifest["protectedPaths"], "protectedPaths")
    for label in ("title", "body"):
        if not isinstance(manifest[label], str) or "\0" in manifest[label]:
            fail(f"{label} must be a string without NUL")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create_parser = sub.add_parser("create")
    create_parser.add_argument("--base-commit", required=True)
    create_parser.add_argument("--patch", type=Path, required=True)
    create_parser.add_argument("--allowed-change-paths", required=True)
    create_parser.add_argument("--protected-paths", default="")
    create_parser.add_argument("--title", required=True)
    create_parser.add_argument("--body", required=True)
    create_parser.add_argument("--output", type=Path, required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "create":
            commit(args.base_commit, "baseCommit")
            create(args)
        else:
            validate(json.loads(args.manifest.read_text(encoding="utf-8")), args.manifest.parent)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print("bot proposal manifest accepted")


if __name__ == "__main__":
    main()
