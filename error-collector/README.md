# Error collector

This is an offline, least-privilege collector for build, test, package,
runtime, security, and upstream-compatibility failure reports.  Its scope is
limited to intake, byte-oriented secret detection, text sanitization,
classification, de-duplication, and a human review summary.

It never connects to a router or GitHub, downloads Issue attachments or linked
content, executes report text, creates Issues, patches code, merges, signs,
publishes, updates, restarts, or flashes a device.  GitHub Issue input is an
`untrusted-report`; a report can only point a human reviewer at work to do.

## Input

Pass a UTF-8 JSON document containing these required fields:

```json
{
  "source": {"kind": "ci", "id": "run-42"},
  "observedAt": "2026-08-31T12:00:00Z",
  "component": "router-packages",
  "revision": "0123456789abcdef0123456789abcdef01234567",
  "diagnostic": "make: *** target failed"
}
```

Allowed source kinds are `ci`, `local`, `device-bundle`, `upstream-validation`,
and `github-issue`. `artifacts`, when supplied, must be an array of strings.
Device bundles must be explicitly supplied by a human.
For `github-issue`, include `source.issue` with only the Issue number, URL,
timestamps, labels, referenced commits, and CVEs that were explicitly copied
into the input. Attachments and complete EEPROM/MTD dumps are rejected before
storage.

The source document's SHA-256 is retained for provenance, but its original
contents are never written by this tool. Sanitized records belong only in a
private local store; `.error-records/` is ignored by Git.

## Run

```sh
python3 error-collector/collector.py \
  --input error-collector/examples/ci-failure.json \
  --store .error-records
```

Use `--dry-run` to print the candidate record without writing it. The output
includes the input hash, sanitization-rule version, collector version, source
lock commit, untrusted status where applicable, classification, severity,
fingerprint, occurrence count, and reviewer prompts.
