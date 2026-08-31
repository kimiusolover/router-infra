import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "policy"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "policy" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


review = load("verify_review_gate")
release = load("verify_release")
contracts = load("verify_contracts")


class PolicyTests(unittest.TestCase):
    def test_review_gate_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subject = root / "subject.txt"
            evidence = root / "evidence.txt"
            subject.write_text("subject")
            evidence.write_text("evidence")
            digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            gate = {"apiVersion": "router-infra/v1", "kind": "ReviewGate", "scope": "deployment", "subject": {"path": "subject.txt", "sha256": digest(subject)}, "evidence": [{"path": "evidence.txt", "sha256": digest(evidence)}], "review": {"required": True, "reviewer": "human", "reviewedAt": "2026-08-31T00:00:00Z", "decision": "accepted"}}
            review.verify(root, gate)
            subject.write_text("changed")
            with self.assertRaisesRegex(ValueError, "hash"):
                review.verify(root, gate)

    def test_release_requires_every_asset_to_be_gate_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            assets = root / "assets"
            assets.mkdir()
            (assets / "image.bin").write_bytes(b"safe fixture")
            digest = hashlib.sha256((assets / "image.bin").read_bytes()).hexdigest()
            sums = {"image.bin": digest}
            (assets / "provenance.json").write_text(json.dumps({"apiVersion": "router-infra-provenance/v1", "subject": sums}))
            (assets / "sbom.spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3", "name": "fixture"}))
            (assets / "signature-verification.json").write_text(json.dumps({"apiVersion": "router-infra-signature-verification/v1", "status": "verified", "verifier": "external", "subject": sums}))
            sums = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in release.files(assets).items() if name != "SHA256SUMS"}
            (assets / "SHA256SUMS").write_text("".join(f"{value}  {name}\n" for name, value in sorted(sums.items())))
            gate = {"apiVersion": "router-infra/v1", "kind": "ReviewGate", "scope": "public_release", "subject": {"path": "image.bin", "sha256": sums["image.bin"]}, "evidence": [{"path": "provenance.json", "sha256": sums["provenance.json"]}], "review": {"required": True, "reviewer": "human", "reviewedAt": "2026-08-31T00:00:00Z", "decision": "accepted"}}
            gate_path = root / "gate.json"; gate_path.write_text(json.dumps(gate))
            with self.assertRaisesRegex(ValueError, "exactly bind"):
                release.preflight(root, assets, gate_path)

    def test_contract_version_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, value in {"a": {"provides": {"manifest": "v2"}, "requires": {}}, "b": {"provides": {}, "requires": {"a": {"manifest": "v3"}}}}.items():
                path = root / name / ".router-infra"; path.mkdir(parents=True)
                (path / "contract.json").write_text(json.dumps({"apiVersion": "router-infra-contract/v1", **value}))
            matrix = {"apiVersion": "router-infra-matrix/v1", "repositories": [{"repository": "a", "path": ".router-infra/contract.json"}, {"repository": "b", "path": ".router-infra/contract.json"}]}
            with self.assertRaisesRegex(ValueError, "requires"):
                contracts.verify(root, matrix)
