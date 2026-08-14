# ADR 0002: Separate automation, AI, identity, and risk

**Status:** Accepted

## Decision

Do not collapse detection into a single `bot_score`.

## Rationale

A verified AI crawler is highly automated and AI-related but may be low-risk. A credential-stuffing browser bot may be highly automated and risky but not AI-related. Identity confidence answers a third question: whether the actor is who it claims to be.

## Consequences

Rules and models must declare which dimensions they affect. Consumers can set policy independently from classification.
