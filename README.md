# router-infra

Shared development and release infrastructure for the router repositories.

This repository provides reusable CI actions and workflows, release policy,
signing integration, SBOM generation, and provenance conventions. Repository-
specific CI remains beside the code it validates; consumers opt into shared
workflows by pinned revision.

No firmware, package recipe, device definition, or private signing material is
stored here.

## Shared safety contracts

The reusable building blocks are deliberately policy-only:

- `policy/verify_review_gate.py` validates a hash-bound, accepted human review.
- `policy/verify_release.py` requires a complete asset manifest, SBOM,
  provenance, an external signature-verification report, and a release gate.
- `policy/verify_contracts.py` checks declared producer/consumer API versions
  across checked-out repositories without running untrusted commands.
- `.github/workflows/verify.yml` and `release.yml` are reusable workflows.

Consumers pin this repository to an immutable revision and keep their own
build/test logic beside the code it validates.  A `public_release` gate only
protects the release path implemented by `release.yml`; repository permissions
must separately prevent direct publication.

See [the integration guide](docs/integration.md) and the sample contracts in
`examples/`.

## Error collector

`error-collector/collector.py` is a deliberately non-privileged intake tool.
It sanitizes one explicitly supplied diagnostic JSON document, classifies it,
and writes a de-duplicated local record.  It does not contact GitHub or a
device, fetch attachments or URLs, create Issues, or perform any corrective or
release action.

See [`error-collector/README.md`](error-collector/README.md) for the input
contract and private-storage requirements.
