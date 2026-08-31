#!/usr/bin/env python3
"""Check a static producer/consumer compatibility matrix without executing it."""
import argparse
import json
import sys
from pathlib import Path, PurePosixPath


def fail(message):
    raise ValueError(message)


def load_contract(workspace, entry):
    if not isinstance(entry, dict) or set(entry) != {"repository", "path"}:
        fail("each repository must contain exactly repository and path")
    path = PurePosixPath(entry["path"])
    if path.is_absolute() or ".." in path.parts:
        fail("contract path must be repository-relative")
    contract = workspace / entry["repository"] / path
    if not contract.is_file():
        fail(f"contract is missing: {entry['repository']}/{path}")
    value = json.loads(contract.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("apiVersion") != "router-infra-contract/v1":
        fail(f"invalid contract: {contract}")
    provided = value.get("provides", {})
    required = value.get("requires", {})
    if not all(isinstance(x, dict) for x in (provided, required)):
        fail(f"invalid provides/requires in {contract}")
    return entry["repository"], provided, required


def verify(workspace, matrix):
    if not isinstance(matrix, dict) or matrix.get("apiVersion") != "router-infra-matrix/v1":
        fail("matrix apiVersion must be router-infra-matrix/v1")
    entries = matrix.get("repositories")
    if not isinstance(entries, list) or not entries:
        fail("matrix.repositories must be non-empty")
    contracts = dict((name, (provided, required)) for name, provided, required in (load_contract(workspace, x) for x in entries))
    for consumer, (_, needs) in contracts.items():
        for provider, versions in needs.items():
            if provider not in contracts or not isinstance(versions, dict):
                fail(f"{consumer} has an invalid provider requirement: {provider}")
            available = contracts[provider][0]
            for api, version in versions.items():
                if available.get(api) != version:
                    fail(f"{consumer} requires {provider}.{api}={version!r}, found {available.get(api)!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", type=Path)
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        verify(args.workspace_root.resolve(), json.loads(args.matrix.read_text(encoding="utf-8")))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"contract verification failed: {error}", file=sys.stderr)
        return 1
    print("contract verification passed")
    return 0
