# Standards Status

**Last reviewed:** 2026-08-16

ATI treats stable RFCs and evolving Internet-Drafts differently. Stable primitives are implemented directly; draft-dependent behavior is pinned to an exact reviewed revision and must not silently advance when upstream publishes a new version.

| Layer | ATI profile | Status in ATI |
| --- | --- | --- |
| HTTP Message Signatures | RFC 9421 | Stable cryptographic primitive |
| Web Bot Auth HTTP-signature protocol | `draft-meunier-webbotauth-httpsig-protocol-01` | Current pinned Internet-Draft; replaces the older architecture draft family |
| HTTP Message Signatures Directory | `draft-meunier-webbotauth-httpsig-directory-00` | Current pinned Internet-Draft; replaces the older directory draft family |
| Published IP ranges / JAFAR | `draft-illyes-webbotauth-jafar-00` | Pinned Internet-Draft |
| Signature Agent Card / registry | `draft-meunier-webbotauth-registry-03` | Current pinned Internet-Draft |

RFC 9421 is the stable base. The other entries remain Internet-Drafts and therefore are **work in progress**: they can be revised, replaced, withdrawn, or expire. ATI records the exact revisions in `StandardsProfile`; an upstream change requires source review, tests, and an explicit code/profile update.

## Current protocol model

The current Web Bot Auth HTTP-signature profile uses a Structured Fields `Signature-Agent` dictionary. ATI recognizes the protocol discovery types explicitly instead of inferring them from a path, media type, or response body:

- `directory` — the default when no `type` parameter is present;
- `jwks_uri` — a generic RFC 7517 JWK Set endpoint;
- `cimd` — Client ID Metadata / Signature Agent Card discovery.

Unknown discovery types are unsupported rather than guessed. ATI also keeps the deployed Cloudflare structured-string form as an explicit legacy interoperability profile; malformed current-profile input is never silently reinterpreted as legacy input.

The registry-03 Agent Card model uses `client_id`, either `jwks_uri` or inline `jwks`, and the `web_bot_auth` extension. Metadata is self-asserted until an authority-bound cryptographic chain proves the relevant identity.

## Binding and deployment policy

ATI separates key possession from provider/agent identity. A valid request signature can prove possession of a key without proving that a specific URL, provider, or bot product controls that key.

For cached remote key material, provider/source profiles declare one of two response-binding policies:

- `strict_current` — higher identity scope requires a current, body-bound `KeyAuthorityBinding` derived from a successfully verified directory response signature; otherwise successful request authentication is downgraded to `KEY` scope.
- `deployed_compatible` — an explicitly configured direct-HTTPS source may retain its configured identity scope for interoperability with documented deployed providers that do not yet require the stricter response-binding chain.

This compatibility policy is declarative and source-specific. It is not a global relaxation of RFC 9421 verification or discovery safety.

## Drift monitoring

Use the explicit network-capable command:

```console
ati standards health
```

The command reads the pinned drafts from `StandardsProfile`, queries the constrained IETF Datatracker API directly, validates exact JSON responses without redirects, and reports revision/state drift without changing any pin. Exit status is:

- `0` — current pins observed;
- `1` — review required because a revision/state changed;
- `2` — operational or upstream-payload error.

Normal `ati analyze` remains offline and does not call Datatracker.

`.github/workflows/source-health.yml` runs the same check only on its scheduled/manual path, alongside configured provider-source refresh and validation. The workflow is read-only and does not rewrite standards pins or trust policy.
