# ADR 0003: Ephemeral Verification Context

## Status

Accepted for V1.

## Decision

Raw source address and signature reconstruction material live only in non-serializable `VerificationContext`. `RequestEvent` and normal detection output remain privacy-minimized.

## Consequence

Network/crypto identity can operate without weakening V0's storage/output privacy contract. Adapters that cannot provide trusted source provenance must return unavailable/indeterminate rather than borrowing untrusted forwarded headers.
