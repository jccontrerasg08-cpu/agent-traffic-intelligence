# Identity Source Health Operations

`Identity Source Health` is a scheduled/manual observability workflow for the external material used by V1 identity verification. It is deliberately separate from deterministic pull-request CI.

## What it does

The workflow:

1. installs the ATI core from the checked-out revision;
2. refreshes only sources declared in `identity/verification_profiles.json`;
3. validates every refreshed document against its configured parser/profile before it can be used;
4. prints provenance-safe status metadata such as provider, URI, digest, and retrieval timestamp.

The workflow uses an ephemeral cache under the GitHub-hosted runner. It does **not** commit source snapshots, modify provider profiles, open issues, or change trust policy automatically.

## Failure meaning

A source-health failure is an engineering/operations signal, not evidence that traffic from the affected provider is malicious or fraudulent.

Typical causes include:

- provider endpoint unavailable or DNS/TLS failure;
- source URI redirected or retired;
- media type or JSON shape changed;
- parser/profile drift;
- a standards/profile revision changed;
- a provider stopped publishing material ATI previously relied on.

Do not translate these failures into `risk_score` or an identity `FAILED` state. Runtime verification should remain neutral (`UNAVAILABLE`, `STALE`, or `INDETERMINATE`) unless authoritative evidence proves a contradiction.

## Response procedure

When the workflow fails:

1. inspect the failed provider/source URI and the current ATI commit;
2. check the provider's primary documentation or the pinned standards document;
3. reproduce with `ati sources refresh` and `ati sources validate` in an isolated cache;
4. compare the current source shape/semantics with the configured parser and binding scope;
5. add or update a regression test before changing parser/profile behavior;
6. update `reviewed_on` only after authority and semantics have actually been re-reviewed;
7. rerun deterministic CI after every repository change.

Do not preserve an obsolete endpoint merely because it still redirects or responds. Prefer the provider's currently documented authority unless redirect/final-URI behavior is intentionally modeled and tested.

## Security rules

- No raw production request IPs, signatures, cookies, Authorization values, or bodies belong in source-health logs or issues.
- `Signature-Agent` supplied by request traffic is never a generic download permission; discovery remains registry-only.
- A downloaded document is not trusted merely because HTTPS succeeded. ATI validates size/media type, source policy, digest, parser shape, and configured semantics before use.
- Automated source-health must never silently rewrite `main`, binding scope, or negative semantics.

## Manual commands

```bash
export ATI_SOURCE_CACHE=/tmp/ati-source-health
ati sources status
ati sources refresh
ati sources validate
```

Use a fresh cache when investigating a provider change so the previous known-good cache remains available for comparison.
