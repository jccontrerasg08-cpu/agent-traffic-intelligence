# ADR 0005: Registry-Only Signature-Agent Discovery

## Status

Accepted for V1.

## Decision

Request-controlled unknown `Signature-Agent` URIs are never fetched automatically. Default discovery only permits canonical provider/profile directory URIs.

## Consequence

ATI does not turn bot authentication into an SSRF primitive. A future public discovery mode requires a separate hardened fetch policy and threat review.
