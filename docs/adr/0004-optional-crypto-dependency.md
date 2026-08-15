# ADR 0004: Optional Cryptographic Verification Dependency

## Status

Accepted for V1.

## Decision

The deterministic core keeps zero third-party runtime dependencies. RFC 9421/Web Bot Auth support is installed through the optional `verification` extra and wrapped behind ATI-owned interfaces.

## Consequence

Third-party crypto implementation types do not leak into ATI's stable domain model, and normal V0 installs preserve their dependency footprint.
