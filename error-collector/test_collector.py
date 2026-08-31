import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("collector.py"))
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)

class CollectorTests(unittest.TestCase):
    def doc(self, **updates):
        result = {"source": {"kind": "ci", "id": "x"}, "observedAt": "2026-08-31T12:00:00Z", "component": "routerctl", "revision": "a" * 40, "diagnostic": "make: password=do-not-store 00:11:22:33:44:55"}
        result.update(updates)
        return result

    def test_redacts_and_classifies_without_storing_raw_input(self):
        raw = json.dumps(self.doc()).encode()
        record = collector.make_record(raw, self.doc())
        self.assertEqual(record["category"], "security")
        self.assertEqual(record["severity"], "critical")
        self.assertNotIn("do-not-store", record["sanitizedDiagnostic"])
        self.assertNotIn("00:11:22:33:44:55", record["sanitizedDiagnostic"])
        self.assertEqual(record["inputSha256"], hashlib.sha256(raw).hexdigest())

    def test_issue_is_untrusted_and_deduplicated(self):
        doc = self.doc(source={"kind": "github-issue", "id": "17", "ignored": "token=discard", "issue": {"number": 17, "url": "https://example.invalid/issues/17", "labels": ["password=discard"], "body": "ignored"}}, diagnostic="test failed")
        record = collector.make_record(json.dumps(doc).encode(), doc)
        self.assertEqual(record["trust"], "untrusted-report")
        self.assertNotIn("ignored", record["source"])
        self.assertEqual(record["source"]["issue"]["labels"], ["[REDACTED_SECRET]"])
        with tempfile.TemporaryDirectory() as tmp:
            path, first = collector.store_record(Path(tmp), record)
            _, second = collector.store_record(Path(tmp), record)
            self.assertEqual(path, Path(tmp) / f"{record['fingerprint']}.json")
            self.assertEqual(second["occurrences"], 2)

    def test_rejects_sensitive_artifacts(self):
        with self.assertRaisesRegex(ValueError, "not accepted"):
            collector.make_record(b"{}", self.doc(artifacts=["complete-mtd-dump"]))

    def test_rejects_non_array_artifacts(self):
        with self.assertRaisesRegex(ValueError, "array of strings"):
            collector.make_record(b"{}", self.doc(artifacts="complete-mtd-dump"))

if __name__ == "__main__":
    unittest.main()
