# Landscape: projects and research near ATI

**Reviewed:** 2026-10-02, from each project's own repository or the paper itself. A
description below says what that source states. Where a project's documentation does not
mention a capability, the table says "not described" rather than "absent". Projects change,
so check the link before relying on a row.

This is positioning research, not a list of things to incorporate. Its purpose is to say
honestly what already exists, where ATI is ordinary, and where it does something the
others do not.

## Where ATI sits

Most tools near this space answer one of three questions: *who does this request claim to
be*, *should it be let in*, or *how much traffic of each kind did we get*. ATI is built
around a fourth: **how much of what we conclude about automated traffic is actually
supported by evidence**.

| Capability | User-Agent catalogues | Edge gatekeepers | Log analytics | Cryptographic identity libraries | ATI |
|---|---|---|---|---|---|
| Recognises declared agents | yes | yes | yes | no | yes, as a *claim* only |
| Verifies identity: IP ranges, FCrDNS | no | allowlists, varies | not described | no | yes |
| Verifies identity: Web Bot Auth signatures | no | not described | not described | yes | yes, with the official vectors |
| Behavioural session features | no | challenge outcome | heuristics | no | yes, bounded and explainable |
| Enforces (blocks, challenges) | via generated configs | yes | no | no | **never**: observe-only by design |
| Stores raw IP addresses | n/a | decides on live addresses | yes (Logwick says so) | n/a | no: keyed pseudonyms only |
| Evaluation with ground-truth labels | no | no | not described | conformance tests | yes, with leakage guards |

## Projects

### User-Agent catalogues: what agents *say* they are

- [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) (MIT). A community list
  of AI crawlers kept in `robots.json` and generated into `robots.txt`, `.htaccess`, nginx,
  Caddy, HAProxy and lighttpd blocks. It matches on User-Agent strings.
- [crawler-user-agents](https://github.com/monperrus/crawler-user-agents) (MIT). One JSON
  file of regular expressions for crawler User-Agents, with libraries in several languages
  and CI that validates the patterns.
- [isbot](https://github.com/omrilotan/isbot) (Unlicense). A TypeScript User-Agent
  matcher. Its README is candid that it does not detect bots disguised as people, and it
  recommends reverse DNS for anything security-relevant.
- [Known Agents](https://knownagents.com/posts/dark-visitors-is-now-known-agents),
  formerly Dark Visitors. A commercial directory and analytics service that ai.robots.txt
  draws on in part.

**ATI's position.** A User-Agent is an assertion, so ATI's curated catalogue produces a
`claimed` identity and nothing more ([ADR 0002](../adr/0002-separate-score-dimensions.md)).
Matching names is commodity work. The value is in checking the claim.

### Edge gatekeepers: whether to let a request in

- [Anubis](https://github.com/TecharoHQ/anubis) (MIT, Go). A reverse proxy that makes
  browsers solve a proof-of-work challenge and lets allowlisted crawlers through by policy,
  with User-Agent and IP rules. It is widely deployed in front of open-source
  infrastructure ([releases](https://github.com/TecharoHQ/anubis/releases): v1.27.0,
  2026-08-08).
- [CrowdSec](https://github.com/crowdsecurity/crowdsec) (MIT, Go). It parses logs into
  behaviour scenarios and applies remediation at the firewall, proxy or CDN, backed by a
  shared community blocklist. Its WAF component includes a proof-of-work challenge that
  lets verified crawlers through.

**ATI's position.** These tools act, and acting has a price measured in real users turned
away. ATI deliberately stops before that point
([ADR 0001](../adr/0001-observe-before-enforce.md)). Its output is the kind of explained,
calibrated evidence a gatekeeper's policy could later consume, once its false-positive
cost has been measured.

### Log analytics for AI traffic: how much of each kind

- [Logwick](https://github.com/stani-chirk/logwick) (AGPL-3.0, Node.js). The closest
  project in shape: local, no JavaScript tag, classifying edge JSONL logs into users, known
  crawlers, AI training scrapers, AI user-fetch agents and suspicious automation. It uses a
  multi-phase ruleset of User-Agent patterns, path heuristics and behavioural signals. Its
  README notes that logs contain IP addresses, which are personal data, and keeps them in
  local SQLite.
- [AgentECHO](https://github.com/galaar-org/AgentECHO) (MIT, Go and TypeScript). A
  Next.js SDK that sends HMAC-signed events to a Go collector backed by ClickHouse. It
  identifies about twenty AI crawlers by User-Agent and estimates licensing revenue per
  route.

**ATI's position.** ATI overlaps with Logwick most. The differences are deliberate.
Identity is verified, not matched. Raw addresses never reach storage. The four scores stay
separate. And classification is backed by an evaluation protocol rather than by rules
alone. ATI's licence is permissive, where Logwick's is AGPL.

### Cryptographic identity: proving who signed a request

- [cloudflare/web-bot-auth](https://github.com/cloudflare/web-bot-auth) (Apache-2.0).
  The reference TypeScript and Rust libraries for Web Bot Auth: signing, verifying and
  directory hosting, plus a browser extension, a Caddy verifier plugin, Workers, and a live
  [test deployment](https://http-message-signatures-example.research.cloudflare.com/).
- Independent ports exist, for example a Go package from
  [WebDecoy](https://pkg.go.dev/github.com/WebDecoy/web-bot-auth).

**ATI's position.** ATI is a *verifier inside an analysis pipeline*, not a signing
library. It builds on RFC 9421 through the
[`http-message-signatures`](https://pypi.org/project/http-message-signatures/) package and
adds the Web Bot Auth policy, discovery safety and authority binding. The IETF draft's own
Appendix E.2 vectors run through ATI's real verifier
([test](../../tests/identity/crypto/test_webbotauth_wg_vectors.py)). Running them during
this review found three defects, now fixed and recorded in
[standards status](../standards-status.md#review-of-the-working-group-adoption-2026-10-02).

### Client-side detection: what the browser reveals

- [BotD](https://github.com/fingerprintjs/BotD) (MIT). Runs entirely in the browser and
  detects headless browsers, Selenium, Playwright and similar tools. Its README says the
  library is in stability-only mode, and it points to a commercial product for AI-agent and
  server-side detection.
- [FPScanner](https://github.com/antoinevastel/fpscanner) (MIT). Browser fingerprinting
  with payload encryption, anti-replay and cross-context checks, aimed at automation
  frameworks.

**ATI's position.** ATI is server-first and needs no JavaScript on the page. Browser
signals would be optional extra evidence. They are not part of the core, because many of
the agents that matter never run page scripts.

### Adversarial references

Crawl4AI and Playwright, Selenium and stealth tooling are useful for generating controlled
evasive traffic in a laboratory. Their role here is to test the detector, never to bypass
third-party protections.

## Research

### Detection papers: what is reported versus what is shown

- Iliou et al., *Detection of Advanced Web Bots by Combining Web Logs with Mouse
  Behavioural Biometrics*, Digital Threats: Research and Practice 2(3), 2021,
  [doi:10.1145/3447815](https://doi.org/10.1145/3447815). It pairs a web-log module with a
  mouse-movement module and evaluates against bots of two levels of evasiveness. The
  dataset is available on request.
- Jarad and Bicakci, *When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS
  Fingerprints*, 2026, [arXiv:2602.09606](https://arxiv.org/abs/2602.09606). Gradient
  boosting over JA4 TLS fingerprints from JA4DB, reporting an AUC of 0.998. The abstract
  does not describe how labels were assigned, or whether test data was separated in time or
  by source.

The second paper is typical of the field rather than an outlier. A very high score is easy
to obtain when labels come from the same signals the model sees, or when near-identical
samples land on both sides of a split. ATI's matched fixture shows the same thing at small
scale: an unmatched design scores a PR-AUC of 1.000 and means nothing
([case study](../case-study.md#the-hard-part-not-fooling-yourself)).

### Evaluation methodology ATI follows

- Kaufman, Rosset, Perlich and Stitelman, *Leakage in Data Mining: Formulation, Detection,
  and Avoidance*, ACM TKDD 6(4), 2012,
  [doi:10.1145/2382577.2382579](https://doi.org/10.1145/2382577.2382579). This paper is the
  source of the "learn-predict separation" that ATI enforces structurally.
- Kapoor and Narayanan, *Leakage and the Reproducibility Crisis in Machine-Learning-Based
  Science*, Patterns 4(9), 2023,
  [doi:10.1016/j.patter.2023.100804](https://doi.org/10.1016/j.patter.2023.100804). It
  gives a taxonomy of leakage, mapped onto ATI below.
- Saito and Rehmsmeier, *The Precision-Recall Plot Is More Informative than the ROC Plot
  When Evaluating Binary Classifiers on Imbalanced Datasets*, PLOS ONE, 2015,
  [doi:10.1371/journal.pone.0118432](https://doi.org/10.1371/journal.pone.0118432). This
  is why ATI reports PR-AUC rather than ROC-AUC.
- Gebru et al., *Datasheets for Datasets*, Communications of the ACM 64(12), 2021,
  [doi:10.1145/3458723](https://doi.org/10.1145/3458723). It is the model for the
  laboratory's
  [corpus datasheet](https://github.com/jccontrerasg08-cpu/ati-observation-lab/blob/main/docs/pf2-corpus-datasheet.md).

| Leakage type (Kapoor and Narayanan) | Guard in ATI or the laboratory |
|---|---|
| No separate test set | Every split has a fixed holdout. The last collection window is the final temporal holdout, and a model only counts as winning there ([`build_pf2_splits`](../../src/agent_traffic_intelligence/evaluation/pf2/baseline.py)). |
| Pre-processing on train and test together | Standardization statistics and the operating threshold are fitted on the training partition only. |
| Duplicates across the split | The corpus builder refuses duplicated request identifiers, and the baseline refuses a split manifest that repeats a row or a session. |
| Illegitimate features | The feature firewall rejects any column outside the 67 permitted features. Pseudonyms, tasks and windows live in a separate manifest ([ADR 0007](../adr/0007-pf2-feature-firewall.md)). |
| Temporal leakage | Temporal splits are forward-chained and never train on a later window. |
| Non-independence between train and test | Holdouts are grouped by session and by task, and confidence intervals resample whole sessions. |
| Sampling bias in the test distribution | The matched-executor design, and the corpus builder's refusal of any executor, pacing, scenario or catalogue version that occurs in one class only. What remains unknown, generalization to unmarked public traffic, is stated as not established. |

## What this review changed

1. **Upgraded to the working-group draft and fixed three defects**, as described above
   and in [standards status](../standards-status.md).
2. **Replaced an undated, unlinked comparison** with this one. Every claim about another
   project now links to its source.
3. **Confirmed the gap ATI fills.** No project reviewed combines verified identity,
   privacy-minimized storage and a leakage-guarded evaluation. That combination, not any
   single detector, is the contribution.

## Industry framing (non-normative)

Quantum Metric's article
[Decoding AI traffic: how to tell agents, scrapers, and crawlers apart](https://www.quantummetric.com/blog/decoding-ai-traffic-how-to-tell-agents-scrapers-and-crawlers-apart)
(December 2025) separates LLM crawlers, on-demand retrieval scrapers, agentic browsers and
autonomous agents. It argues that one "bot" metric distorts engagement and attribution
analysis. ATI agrees and goes further in one respect. Official provider material and
standards outrank any commercial taxonomy for identity decisions, and commercial metrics
are never used as labels or thresholds.

## Design conclusions

1. A static User-Agent catalogue is commodity functionality. It yields claims, not
   identities.
2. Identity verification is a separate axis from the claim. It is anchored in published
   ranges, FCrDNS and signatures, and checked against the standards' own vectors.
3. Behaviour must still carry signal when User-Agent and TLS fingerprints are spoofed.
4. The evaluation design is part of the product. A metric without its split, its labels
   and its baseline is not evidence.
5. Enforcement stays downstream of detection until false-positive costs are measured.
6. Analytics should keep materially different machine journeys apart instead of
   collapsing them into one bot bucket.
