import hashlib
import importlib.util
import json
import subprocess
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
bot_change = load("verify_bot_change")
bot_proposal = load("bot_proposal")


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

    def test_bot_change_refuses_protected_or_unlisted_paths(self):
        allowed = ("docs/**", "fixtures/**")
        accepted, reason = bot_change.classify(("docs/guide.md",), allowed, ())
        self.assertTrue(accepted, reason)
        accepted, reason = bot_change.classify((".github/workflows/ci.yml",), ("**",), ())
        self.assertFalse(accepted)
        self.assertIn("requires human review", reason)
        accepted, reason = bot_change.classify(("policy/rule.json",), allowed, ())
        self.assertFalse(accepted)
        self.assertIn("outside allowed", reason)

    def test_bot_change_cli_outcomes_for_workflow_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            (root / "docs").mkdir()
            (root / "docs" / "from.md").write_text("base")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)

            def check(expected, *extra):
                subprocess.run(["git", "add", "-A"], cwd=root, check=True)
                return subprocess.run(
                    [sys.executable, str(ROOT / "policy" / "verify_bot_change.py"),
                     "--allowed-change-paths", "docs/**", *extra],
                    cwd=root, text=True, capture_output=True, check=False,
                ).returncode == expected

            self.assertTrue(check(3))  # empty diff
            (root / "docs" / "proposal.md").write_text("proposal")
            self.assertTrue(check(0))  # eligible change to be committed/PR'd
            (root / "docs" / "proposal.md").unlink()
            (root / ".github").mkdir()
            (root / ".github" / "workflow.yml").write_text("name: protected")
            self.assertTrue(check(3))  # protected path -> needs-human-review
            (root / ".github" / "workflow.yml").unlink()
            subprocess.run(["git", "mv", "docs/from.md", "docs/to.md"], cwd=root, check=True)
            self.assertTrue(check(3))  # rename -> needs-human-review
            subprocess.run(["git", "reset", "--hard", "-q"], cwd=root, check=True)
            (root / "docs" / "to.md").write_text("base")
            self.assertTrue(check(3))  # copy -> needs-human-review

    def test_bot_workflow_interprets_multiword_commands_and_uses_safe_branch(self):
        prepare = (ROOT / ".github" / "workflows" / "bot-proposal-prepare.yml").read_text()
        create_pr = (ROOT / ".github" / "workflows" / "bot-proposal-pr.yml").read_text()
        self.assertIn('runs-on: ubuntu-latest', prepare)
        self.assertIn('permissions:\n  contents: read', prepare)
        self.assertIn('bash -o errexit -o nounset -o pipefail -c "$TEST_COMMAND"', prepare)
        self.assertIn('git diff --cached --binary --full-index HEAD > proposal.patch', prepare)
        self.assertIn('github.event.workflow_run.conclusion == \'success\'', create_pr)
        self.assertIn('git apply --check --index "$PROPOSAL_DIR/proposal.patch"', create_pr)
        self.assertIn('BOT_BRANCH: bot/proposal-${{ github.event.workflow_run.id }}-${{ github.run_attempt }}', create_pr)
        self.assertIn('gh pr create --base "$BASE_BRANCH" --head "$BOT_BRANCH"', create_pr)

    def test_bot_proposal_manifest_binds_patch_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            patch = root / "proposal.patch"
            patch.write_text("diff --git a/docs/a b/docs/a\n")
            output = root / "proposal.json"
            args = type("Args", (), {
                "base_commit": "a" * 40, "patch": patch,
                "allowed_change_paths": "docs/**", "protected_paths": "",
                "title": "Bot proposal", "body": "Generated after checks.", "output": output,
            })()
            bot_proposal.create(args)
            manifest = bot_proposal.validate(json.loads(output.read_text()), root)
            self.assertEqual(manifest["baseCommit"], "a" * 40)
            patch.write_text("tampered")
            with self.assertRaisesRegex(ValueError, "hash"):
                bot_proposal.validate(json.loads(output.read_text()), root)

    def test_bot_data_handoff_rechecks_and_applies_a_bound_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            (root / "docs").mkdir()
            (root / "docs" / "base.md").write_text("base")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True,
                                  capture_output=True, check=True).stdout.strip()
            (root / "docs" / "proposal.md").write_text("generated")
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            patch = root / "proposal.patch"
            patch.write_bytes(subprocess.run(
                ["git", "diff", "--cached", "--binary", "--full-index", "HEAD"],
                cwd=root, capture_output=True, check=True,
            ).stdout)
            output = root / "proposal.json"
            args = type("Args", (), {
                "base_commit": base, "patch": patch,
                "allowed_change_paths": "docs/**", "protected_paths": "",
                "title": "Bot proposal", "body": "Generated after checks.", "output": output,
            })()
            bot_proposal.create(args)
            subprocess.run(["git", "reset", "--hard", "-q"], cwd=root, check=True)
            manifest = bot_proposal.validate(json.loads(output.read_text()), root)
            self.assertEqual(base, manifest["baseCommit"])
            subprocess.run(["git", "apply", "--check", "--index", str(patch)], cwd=root, check=True)
            subprocess.run(["git", "apply", "--index", str(patch)], cwd=root, check=True)
            result = subprocess.run(
                [sys.executable, str(ROOT / "policy" / "verify_bot_change.py"),
                 "--allowed-change-paths", "docs/**"],
                cwd=root, text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
