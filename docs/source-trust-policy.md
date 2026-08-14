# Identity Source Trust Policy

Identity verification depends on both evidence and authority. ATI records what a source is authoritative for instead of treating every official-looking URL as universal truth.

## Hierarchy

1. Published RFC requirements.
2. Version-pinned Internet-Drafts, explicitly labeled work in progress.
3. Provider-owned documentation and machine-readable endpoints.
4. Provider-documented DNS naming rules.
5. Open-source projects and third-party lists as research/interoperability references only.

## Negative semantics

Every range publication has an explicit miss policy:

- `authoritative_negative`: a miss may contradict the claim when the source is applicable and fresh.
- `positive_only`: a hit is evidence but a miss stays indeterminate.
- `unknown`: ATI does not manufacture negative confidence.

## Provenance

Cached source documents carry canonical URI, provider/authority, binding scope, retrieval time, source creation time when available, freshness metadata, content type, parser/profile version and SHA-256 digest. Detection evidence references provenance rather than embedding full remote documents.

## Registry-only discovery

Only preconfigured trusted source/directory URIs may be fetched by default. Request-controlled unknown `Signature-Agent` URLs are data, not instructions.
