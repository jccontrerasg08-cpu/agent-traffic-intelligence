# Supply-Chain Security

ATI minimizes the trust surface of automation rather than adding Actions for convenience.

## Current controls

- GitHub Actions are pinned to full commit SHAs.
- Workflow permissions are least privilege.
- CodeQL and Dependency Review are separate controls.
- OpenSSF Scorecard runs independently and uploads SARIF.
- Dependabot updates Python and Actions dependencies in grouped batches.
- `actions/labeler` is metadata-only: no checkout or execution of PR-head code under `pull_request_target`.
- `tj-actions/changed-files` is intentionally not used; changed-file optimization must use GitHub-native filters or repository-owned code.

## OSV status

OSV-Scanner 2.x supports Python lockfiles such as `uv.lock`, `pylock.toml`, `requirements.txt`, Poetry/PDM/Pipenv locks. ATI currently has no dependency lockfile. A scheduled OSV workflow is therefore intentionally deferred instead of publishing a misleading successful scan with no dependency inventory. Add the pinned OSV workflow when a supported lockfile becomes part of the repository contract.

## Releases

Artifact attestations are planned for release/build provenance. An attestation proves provenance/identity claims about an artifact; it is not evidence that the artifact is vulnerability-free or trustworthy by itself.
