# Web Bot Auth Support

ATI treats RFC 9421 HTTP Message Signatures as the stable cryptographic primitive and Web Bot Auth Internet-Drafts as versioned application profiles.

## Verification chain

A cryptographically valid request is not automatically a verified bot. ATI independently checks:

1. RFC 9421 signature validity.
2. `tag="web-bot-auth"` selection to prevent signature confusion.
3. `created` / `expires` under a bounded ATI window.
4. A signed `@authority` or `@target-uri` component.
5. JWK thumbprint and active key window.
6. Trusted directory binding.
7. Signed `Signature-Agent` binding when present.
8. Optional bounded nonce replay detection.

Only components returned as covered by successful RFC 9421 verification are trusted.

## Discovery safety

Default discovery is `registry_only`. Arbitrary request-controlled `Signature-Agent` URLs are data, not fetch instructions. A future public discovery mode would require HTTPS, public-destination checks, redirect revalidation, TLS hostname verification, response limits, and DNS-rebinding-resistant transport.

## Interoperability

ATI supports the current Structured Fields dictionary representation and explicitly marked legacy string compatibility. Provider profiles can distinguish a signed agent identity URI from its key-directory URI, which is required for the currently documented Google-Agent deployment.
