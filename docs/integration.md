# router-infra integration

Pin an action or workflow invocation to a 40-character immutable
`router-infra` commit. The reusable workflows reject tags and branches.
Repository-specific tests, build inputs, device definitions, and release assets
stay in the consumer repository.

## Release contract

Before an Actions workflow publishes a tag, run the pinned
`actions/release-preflight` action with an asset directory and a
`router-infra/v1` `ReviewGate`. The preflight requires:

- `SHA256SUMS` with a relative-name, one-to-one binding for every asset except
  `SHA256SUMS` itself;
- `provenance.json` with `apiVersion: router-infra-provenance/v1`;
- `sbom.spdx.json` with SPDX JSON identity fields;
- `signature-verification.json` with an external verifier, `status: verified`,
  and `apiVersion: router-infra-signature-verification/v1`; and
- an accepted `public_release` gate that binds every hashed asset exactly.

Provenance and signature reports bind only non-metadata deliverables. Their
own bytes are still protected by `SHA256SUMS` and the ReviewGate, avoiding a
self-referential hash cycle. `router-infra` neither receives nor stores a
private signing key.

## Cross-repository contracts

Each participating repository may publish `.router-infra/contract.json`:

```json
{
  "apiVersion": "router-infra-contract/v1",
  "provides": {"manifest": "v2"},
  "requires": {"certificateDB": {"evidence": "v1"}}
}
```

A checked-out workspace supplies a matrix listing each repository and contract
path. `actions/contract-check` validates exact producer/consumer versions; it
does not execute a repository command or fetch content.
