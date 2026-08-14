# ADR 0006: Provider and Agent Binding Are Separate

## Status

Accepted for V1.

## Decision

Every identity assertion carries `KEY`, `PROVIDER` or `AGENT` scope. Only trusted exact-agent binding can move the categorical state to `VERIFIED`.

## Consequence

Shared provider infrastructure, such as a common crawler IP list, cannot silently verify a more specific User-Agent than the source actually supports.
