# Web Bot Auth Support

ATI treats RFC 9421 HTTP Message Signatures as the stable cryptographic primitive and Web Bot Auth Internet-Drafts as versioned application profiles.

## Pinned profile

See `docs/standards-status.md` for the exact draft revisions. Draft-specific parsing is isolated so future revisions cannot silently reinterpret ATI's stable identity model.

## Verification chain

A cryptographically valid request is not automatically a verified bot. ATI checks, independently:

1. RFC 9421 signature validity.
2. `tag="web-bot-auth"` selection to prevent signature confusion.
3. `created` and `expires` with a bounded ATI validity window.
4. A required signed authority/target component.
5. JWK thumbprint/key identity and active key window.
6. Directory trust and binding.
7. `Signature-Agent` binding when present.
8. Optional bounded nonce replay detection.

Only signed/covered components returned by the RFC 9421 verifier are trusted. Unsigned request fields next to a valid signature are not promoted to authenticated metadata.

## Discovery safety

Default discovery is `registry_only`. An arbitrary request-controlled `Signature-Agent` URL cannot trigger outbound HTTP. A future public discovery mode would require HTTPS, public-destination validation, redirect revalidation, TLS hostname verification, response limits and DNS-rebinding-resistant transport.

## Interoperability

ATI supports the current Structured Fields dictionary representation and explicitly marked legacy string compatibility. Provider profiles may separate a signed agent identity URI from its key-directory URI, as required by currently documented Google-Agent behavior.
