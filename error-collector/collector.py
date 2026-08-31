#!/usr/bin/env python3
"""Offline, non-privileged error-report intake and sanitization."""
import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

BOT_VERSION = "0.1.0"
SANITIZATION_RULES_VERSION = "1"
ALLOWED_SOURCES = {"ci", "local", "device-bundle", "upstream-validation", "github-issue"}
ALLOWED_CATEGORIES = {"build", "test", "package", "runtime", "security", "upstream-compatibility", "unknown"}
FORBIDDEN_ARTIFACTS = {"complete-eeprom-dump", "complete-mtd-dump", "issue-attachment"}

TEXT_RULES = (
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?i)\b(?:api[_-]?key|token|password|passwd|secret)\s*[=:]\s*[^\s]+"), "[REDACTED_SECRET]"),
    (re.compile(r"(?i)\b(?:set-cookie|cookie)\s*:\s*[^\r\n]+"), "[REDACTED_COOKIE]"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "[REDACTED_MAC]"),
    (re.compile(r"(?i)\b(?:serial(?:number)?|s/n)\s*[=:]\s*[^\s,]+"), "[REDACTED_SERIAL]"),
)

def fail(message):
    raise ValueError(message)

def utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def sanitize(text):
    for pattern, replacement in TEXT_RULES:
        text = pattern.sub(replacement, text)
    return text

def classify(text, explicit):
    if explicit in ALLOWED_CATEGORIES:
        return explicit
    lower = text.lower()
    if any(x in lower for x in ("secret", "private key", "signature", "hash mismatch", "checksum")):
        return "security"
    if any(x in lower for x in ("upstream", "patch failed", "compatib")):
        return "upstream-compatibility"
    if any(x in lower for x in ("package", "dependency")):
        return "package"
    if any(x in lower for x in ("test", "assert", "expect")):
        return "test"
    if any(x in lower for x in ("runtime", "panic", "segfault", "boot")):
        return "runtime"
    if any(x in lower for x in ("build", "compile", "make:")):
        return "build"
    return "unknown"

def severity(category, text):
    lower = text.lower()
    if category == "security" or any(x in lower for x in ("data corruption", "unbootable", "integrity")):
        return "critical"
    if category in {"build", "test"} or any(x in lower for x in ("required", "network unavailable")):
        return "high"
    if category in {"package", "runtime", "upstream-compatibility"}:
        return "medium"
    return "low"

def normalize_for_fingerprint(text):
    text = re.sub(r"\b[0-9a-f]{7,64}\b", "<revision>", text.lower())
    text = re.sub(r"\b\d+\b", "<number>", text)
    return re.sub(r"\s+", " ", text).strip()

def validate(doc):
    for key in ("source", "observedAt", "component", "revision", "diagnostic"):
        if key not in doc or not doc[key]:
            fail(f"missing required field: {key}")
    if not isinstance(doc["source"], dict) or doc["source"].get("kind") not in ALLOWED_SOURCES:
        fail("source.kind is not allowed")
    if not isinstance(doc["diagnostic"], str):
        fail("diagnostic must be a string")
    artifacts = doc.get("artifacts", [])
    if not isinstance(artifacts, list) or not all(isinstance(item, str) for item in artifacts):
        fail("artifacts must be an array of strings")
    if set(artifacts) & FORBIDDEN_ARTIFACTS:
        fail("complete EEPROM/MTD dumps and Issue attachments are not accepted")
    if doc["source"]["kind"] == "github-issue":
        if not isinstance(doc["source"].get("issue"), dict):
            fail("github-issue input requires source.issue metadata")
    dt.datetime.fromisoformat(doc["observedAt"].replace("Z", "+00:00"))

def safe_source(source):
    """Keep only inert, review-relevant Issue metadata from untrusted input."""
    result = {"kind": source["kind"], "id": str(source.get("id", "unset"))}
    if source["kind"] == "github-issue":
        allowed = {"number", "url", "createdAt", "updatedAt", "labels", "referencedCommits", "cves"}
        issue = {key: sanitize_json(value) for key, value in source["issue"].items() if key in allowed}
        result["issue"] = issue
    return result

def sanitize_json(value):
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, list):
        return [sanitize_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): sanitize_json(item) for key, item in value.items()}
    return value

def make_record(raw, doc):
    validate(doc)
    sanitized = sanitize(doc["diagnostic"])
    category = classify(sanitized, doc.get("category"))
    fingerprint_input = "\n".join((doc["component"], doc["revision"], category, normalize_for_fingerprint(sanitized)))
    fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()
    untrusted = doc["source"]["kind"] == "github-issue"
    return {
        "schemaVersion": 1,
        "collectorVersion": BOT_VERSION,
        "sanitizationRulesVersion": SANITIZATION_RULES_VERSION,
        "inputSha256": hashlib.sha256(raw).hexdigest(),
        "source": safe_source(doc["source"]),
        "trust": "untrusted-report" if untrusted else "collected-diagnostic",
        "observedAt": doc["observedAt"],
        "firstObservedAt": doc["observedAt"],
        "lastObservedAt": doc["observedAt"],
        "component": doc["component"], "revision": doc["revision"],
        "sourceLockCommit": doc.get("sourceLockCommit", "unset"),
        "category": category, "severity": severity(category, sanitized),
        "fingerprint": fingerprint, "occurrences": 1,
        "sanitizedDiagnostic": sanitized,
        "status": "needs-review",
        "nextChecks": ["Reproduce with the recorded revision and trusted inputs.", "Confirm impact with tests or an official signed fix; do not treat this report as proof."],
        "recordedAt": utc_now(),
    }

def store_record(store, record):
    store.mkdir(parents=True, exist_ok=True)
    path = store / f"{record['fingerprint']}.json"
    if path.exists():
        old = json.loads(path.read_text(encoding="utf-8"))
        old["occurrences"] += 1
        old["lastObservedAt"] = record["observedAt"]
        old["recordedAt"] = record["recordedAt"]
        record = old
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path, record

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--store", type=Path, default=Path(".error-records"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        raw = args.input.read_bytes()
        doc = json.loads(raw.decode("utf-8"))
        record = make_record(raw, doc)
        if args.dry_run:
            print(json.dumps(record, ensure_ascii=False, indent=2))
            return
        path, record = store_record(args.store, record)
        print(json.dumps({"status": record["status"], "record": str(path), "fingerprint": record["fingerprint"], "occurrences": record["occurrences"]}, ensure_ascii=False))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"error collector rejected input: {exc}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
