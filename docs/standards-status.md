# Standards Status

**Last reviewed:** 2026-10-02

ATI treats stable RFCs and evolving Internet-Drafts differently. Stable primitives are implemented directly; draft-dependent behavior is pinned to an exact reviewed revision and must not silently advance when upstream publishes a new version.

| Layer | ATI profile | Status in ATI |
| --- | --- | --- |
| HTTP Message Signatures | RFC 9421 | Stable cryptographic primitive |
| Web Bot Auth HTTP-signature protocol | `draft-ietf-webbotauth-httpsig-protocol-00` | Working-group draft, adopted 2026-09-01; succeeds `draft-meunier-webbotauth-httpsig-protocol-02` |
| HTTP Message Signatures Directory | `draft-ietf-webbotauth-httpsig-protocol-00`, Section 5.5 | Merged into the protocol draft; `draft-meunier-webbotauth-httpsig-directory-00` is superseded |
| Published IP ranges / JAFAR | `draft-illyes-webbotauth-jafar-00` | Pinned Internet-Draft |
| Signature Agent Card / registry | `draft-meunier-webbotauth-registry-03` | Current pinned Internet-Draft |

RFC 9421 is the stable base. The other entries remain Internet-Drafts and therefore are **work in progress**: they can be revised, replaced, withdrawn, or expire. ATI records the exact revisions in `StandardsProfile`; an upstream change requires source review, tests, and an explicit code/profile update.

## Review of the working-group adoption (2026-10-02)

`ati standards health` reported the drift: the IETF webbotauth working group adopted the
protocol as `draft-ietf-webbotauth-httpsig-protocol-00`, whose text is the same as the
individual `-02`, and folded the directory draft into it. Compared with the previously
pinned `-01`, the normative changes and how ATI meets them are:

| Change in the draft | ATI |
| --- | --- |
| A signature MUST cover the `Signature-Agent` member under its own label, and a verifier MUST NOT attribute a signature to a member it does not cover | Fixed in this review. ATI used to accept a signature that covered *another* signer's member. A signature is now bound to the member keyed by its own label when one exists, and otherwise only to a single covered member (the shape of the draft's own test vectors). Ambiguous coverage is a mismatch. |
| `Signature-Agent` is REQUIRED on signed requests | Not enforced as a failure. A signature without it can still verify against a key the operator configured, but it never binds to an agent URL (`signature_agent_present: false`), matching Section 4.3, where a missing URL leaves only the key thumbprint as identity. |
| Keys are looked up by the pair (Signature-Agent URL, `keyid`) | Already the case: a verifier is built per trusted key source and binds only to its own URL. |
| Discovery MUST be served with status 200, and a verifier MUST NOT follow redirects (Section 5.5) | Fixed in this review. Key-directory refresh used the general fetcher, which followed up to three redirects and accepted any 2xx. It now stops at the first redirect and accepts only 200, plus 304 to revalidate a 200 already cached. IP-range sources keep the general policy, which this draft does not govern. The one configured directory, `agent.bot.goog`, answers 200 directly. |
| The legacy sf-string `Signature-Agent` is kept only for migration (Appendix E.2.2) | Already an explicit, opt-in `cloudflare-legacy` profile. |

The draft's own Appendix E.2 Ed25519 vectors run through the real verification chain in
[`tests/identity/crypto/test_webbotauth_wg_vectors.py`](../tests/identity/crypto/test_webbotauth_wg_vectors.py).
Running them exposed one more defect: the RFC 9421 library judged `created` and `expires`
against the wall clock, not the time of the request, so any recorded log older than the
validity window failed to verify. Verification now uses the request's time throughout.

The Signature-Agent syntax profile keeps its identifier, `ietf-httpsig-protocol-01`,
because the dictionary syntax it names did not change and the identifier is stored in
configuration.

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
