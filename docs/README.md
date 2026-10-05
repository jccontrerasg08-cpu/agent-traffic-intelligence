# Documentation map

Grouped by what you are trying to do. Documents are in English unless marked *(es)*;
the Spanish ones are the original working records and are kept in their language.

## Start here

| Document | Read it to learn |
|---|---|
| [Case study](case-study.md) | The problem, the constraints, the design and what the evidence does and does not show. |
| [Engineering principles in practice](engineering-principles.md) | Where *The Pragmatic Programmer*, *Code Complete*, *Clean Code* and *Designing Data-Intensive Applications* show up in this code, file by file. |
| [Architecture overview *(es)*](architecture/README.md) | Module boundaries, environments and the case catalogue. |
| [Threat model](threat-model.md) | What ATI defends against, what it trusts, and what it deliberately does not do. |

## Decisions

Architecture decision records: one decision, its context and its consequences each.

| ADR | Decision |
|---|---|
| [0001](adr/0001-observe-before-enforce.md) | Observe before enforce |
| [0002](adr/0002-separate-score-dimensions.md) | Separate automation, AI, identity and risk |
| [0003](adr/0003-ephemeral-verification-context.md) | Raw verification material is ephemeral |
| [0004](adr/0004-optional-crypto-dependency.md) | Cryptography is an optional extra |
| [0005](adr/0005-registry-only-signature-agent-discovery.md) | Signature-agent discovery only through the registry |
| [0006](adr/0006-provider-agent-binding-scope.md) | Provider and agent binding are separate |
| [0007](adr/0007-pf2-feature-firewall.md) | The PF-2 feature firewall: split metadata never reaches the estimator |
| [0008](adr/0008-aggregate-only-warehouse-export.md) | The warehouse receives aggregates only |
| [0009](adr/0009-range-snapshot-validity.md) | A range snapshot vouches for a fixed period, not for its HTTP freshness |

## Architecture and contracts

| Document | Scope |
|---|---|
| [Modular boundaries *(es)*](architecture/modular-boundaries.md) | Each package's contract, public facade and entry conditions. |
| [Environment matrix *(es)*](architecture/environment-matrix.md) | Local, CI and service profiles and their constraints. |
| [Cases and variations *(es)*](cases-and-variations.md) | Active and proposed variations, expected cases and covering tests. |
| [Schemas](schemas.md) | Event and detection JSON schemas. |
| [Conformance](conformance.md) | Which standards are implemented, and to what extent. |
| [Railway service topology *(es)*](architecture/railway-service-topology.md) | Laboratory and analyzer as separate services. |

## Identity verification

[Identity verification](identity-verification.md) ·
[Web Bot Auth](web-bot-auth.md) ·
[Provider verification](provider-verification.md) ·
[Source trust policy](source-trust-policy.md) ·
[Source refresh](source-refresh.md) ·
[Source health operations](source-health-operations.md) ·
[Standards status](standards-status.md)

## Evaluation and data

| Document | Scope |
|---|---|
| [Evaluation and dataset plan](evaluation.md) | Metrics, corpus manifests, the ATI-PF-2 ladder and the BigQuery runbook. |
| [Controlled observation](controlled-observation.md) | Running authorized, marker-labelled campaigns. |
| [Controlled observation protocol *(es)*](architecture/controlled-observation-protocol.md) | The repetition protocol campaigns follow. |
| [Public observation catalogue *(es)*](architecture/public-observation-catalog.md) | What may be observed without a campaign. |
| [Privacy: network data](privacy-network-data.md) | How addresses and identifiers are pseudonymized and retained. |

## Operations and security

[Observe-only Railway service *(es)*](railway-observe-only.md) ·
[Supply-chain security](supply-chain-security.md) ·
[Recommended repository settings](repository-settings.md) ·
[Environments](../environments/README.md)

## Evidence

Dated records of what was run and observed against real infrastructure. They state what
was measured and, separately, what was **not** established.

- [ATI-PF-2 live collection and baseline](architecture/pf2-live-collection-evidence.md)
- [Worker → Railway perimeter verification *(es)*](architecture/worker-railway-perimeter-verification.md)
- [Controlled observation verification *(es)*](architecture/controlled-observation-verification.md)
- [Extended observation evidence map *(es)*](architecture/extended-observation-evidence-map.md)
- [External DNS reachability *(es)*](architecture/external-dns-reachability-evidence.md)
- [Railway 404 evidence *(es)*](architecture/railway-404-evidence.md)
- [Public observation ledger *(es)*](architecture/public-observation-evidence-ledger.md)
- [Modularization ledger *(es)*](architecture/modularization-evidence-ledger.md)

## Research

[Landscape](research/open-source-landscape.md): adjacent projects and papers, how ATI differs, and the leakage taxonomy mapped to ATI's guards.

## History

[Development history](history/README.md): the original design specs, implementation plans
and dated audits, kept verbatim for traceability. They describe intent at the time, not
current behaviour.
