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
- `.github/workflows/bot-proposal-prepare.yml` runs repository-owned checks on
  `main` with `contents: read`, then publishes only a hash-bound patch and
  manifest artifact when the diff is eligible.
- `.github/workflows/bot-proposal-pr.yml` is invoked from a consumer's
  `workflow_run`; it verifies the successful `main` run, current base commit,
  artifact hash, patch applicability, and paths before creating a `bot/*` PR.

Consumers pin this repository to an immutable revision and keep their own
build/test logic beside the code it validates.  A `public_release` gate only
protects the release path implemented by `release.yml`; repository permissions
must separately prevent direct publication.

The preparation stage is suitable for GitHub-hosted runners and never receives
write permissions. Its artifact is data, not a program. The PR stage must be a
thin consumer workflow triggered only by the preparation workflow's successful
`main` push; it must not run an artifact script or its `test-command`. Give
`contents: write` and `pull-requests: write` only to that stage, and limit its
pushes to `bot/*` with repository rules. The bot never merges, tags, signs,
publishes, contacts a device, or treats a proposal as approval.

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
