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

ATI maintains `requirements-dev.txt`, a hash-pinned Python dependency lockfile for development and verification. CI installs it with `--require-hashes`, so future OSV scanning can use a concrete dependency inventory. A scheduled OSV workflow is not yet configured; the project does not claim continuous OSV coverage until that control exists.

## Releases

Artifact attestations are planned for release/build provenance. An attestation proves provenance claims about an artifact; it does not prove that the artifact is vulnerability-free or safe.
