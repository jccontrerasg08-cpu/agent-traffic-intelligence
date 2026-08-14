# Supply-Chain Security

ATI minimizes the trust surface of automation instead of adding Actions for convenience.

## Current controls

- GitHub Actions are pinned to full commit SHAs.
- Workflow permissions are least privilege.
- CodeQL and Dependency Review remain separate controls.
- OpenSSF Scorecard runs independently and uploads SARIF.
- `actions/labeler` is metadata-only: no checkout or execution of PR-head code under `pull_request_target`.
- `tj-actions/changed-files` is intentionally not used; changed-file optimization uses GitHub-native filters or repository-owned code.

## OSV status

OSV-Scanner 2.x supports Python dependency inventories such as `uv.lock`, `pylock.toml`, requirements files, and Poetry/PDM/Pipenv lockfiles. ATI currently has no dependency lockfile, so a scheduled OSV workflow is intentionally deferred instead of publishing a misleading successful scan with no dependency inventory.

## Releases

Artifact attestations are planned for release/build provenance. An attestation proves provenance claims about an artifact; it does not prove that the artifact is vulnerability-free or safe.
