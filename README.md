# Agent Traffic Intelligence

Self-hosted, explainable intelligence for automated and AI-originated web traffic.

> **Status: pre-alpha / observe-only.** V1 can verify selected machine identities, but ATI still does not block, challenge, throttle, or mutate production traffic.

## Why this exists

Modern web traffic no longer fits a single `human | bot` flag. A verified search crawler, an AI training crawler, a user-triggered AI fetcher, browser automation, and an abusive scraper can all be automated while having very different identities, purposes, and risk.

Agent Traffic Intelligence keeps those dimensions separate:

- `automation_score`: evidence that the request/session is automated.
- `ai_score`: evidence that the automation is AI-related.
- `identity_confidence`: evidence that a claimed actor identity is authentic.
- `risk_score`: evidence that observed behavior is operationally risky or abusive.

A User-Agent claim is **not** identity verification. V1 can add independent network or cryptographic evidence without automatically changing automation, AI-relatedness, or risk.

## Architecture

```text
JSONL access logs
      |
      v
parser + privacy transform
      |\
      | +--> ephemeral VerificationContext
      |        raw source address/signature material
      |        never persisted in RequestEvent
      v
normalized RequestEvent
      |\
      | +--> curated agent registry ----> claimed identity
      |                                  |
      |                                  +--> official ranges / FCrDNS
      |                                  +--> RFC 9421 / Web Bot Auth
      |                                           |
      |                                           v
      |                                  verification evidence
      v
request/session features
      |
      +-----> evidence rules
                 |
                 v
       independent logistic scores
                 |
                 v
         detection JSONL
```

The deterministic core has **zero third-party Python runtime dependencies**. Cryptographic verification is an optional extra.

## Quick start

Requires Python 3.11+.

```bash
python -m pip install -e .
ati registry validate
```

If your input contains a raw client IP, set a secret pseudonymization key. The key is never written to output.

```bash
export ATI_HASH_KEY='replace-with-a-long-random-secret'
ati analyze examples/data/access.jsonl --source nginx --output detections.jsonl
```

Explain one result:

```bash
ati explain detections.jsonl --request-id '<request-id>'
```

For PowerShell:

```powershell
$env:ATI_HASH_KEY = 'replace-with-a-long-random-secret'
ati analyze examples/data/access.jsonl --source nginx --output detections.jsonl
```

## V1 verified identity

Install the optional cryptographic stack when RFC 9421 / Web Bot Auth verification is needed:

```bash
python -m pip install -e '.[verification]'
```

External identity sources are refreshed **explicitly**. `ati analyze` never downloads or silently refreshes provider material.

```bash
ati sources status
ati sources refresh
ati sources validate
```

By default the cache lives under `~/.cache/agent-traffic-intelligence/identity-sources`. Override it with `ATI_SOURCE_CACHE` when an operator needs an explicit location.

Analyze with verification enabled:

```bash
ati analyze examples/data/access.jsonl \
  --source nginx \
  --verify-identity \
  --verification-mode offline \
  --output verified.jsonl
```

Verification modes:

- `offline`: cached official ranges and cached cryptographic material only; no DNS verification.
- `hybrid`: cached material plus provider-documented FCrDNS where configured.
- `live`: currently has the same verifier availability as `hybrid`; source downloads remain an explicit `ati sources refresh` operation.

Verification can resolve to `claimed`, `verified`, `failed`, or `conflicted`. Operational failures such as missing cache, DNS failure, stale source material, or an unavailable optional dependency do not become identity failures by themselves.

Current provider verification policy is deliberately conservative:

- OpenAI: agent-scoped official range publications where available.
- Google: official crawler range publications, provider-documented FCrDNS, and `Google-Agent` Web Bot Auth material.
- Perplexity: agent-scoped published IP ranges.
- Anthropic: no IP-range verification is configured because Anthropic does not currently publish crawler IP ranges.

See [`docs/identity-verification.md`](docs/identity-verification.md), [`docs/web-bot-auth.md`](docs/web-bot-auth.md), and [`docs/standards-status.md`](docs/standards-status.md).

## Input contract

ATI accepts line-delimited JSON objects. Common Nginx-style keys are recognized:

```json
{
  "time_iso8601": "2026-08-14T08:00:00+00:00",
  "remote_addr": "203.0.113.42",
  "request_method": "GET",
  "request_uri": "/docs?ignored=true",
  "status": 200,
  "body_bytes_sent": 1234,
  "server_protocol": "HTTP/2",
  "http_user_agent": "Mozilla/5.0 compatible; GPTBot/1.0"
}
```

The normalizer strips query strings before generating a `RequestEvent`. Raw IPs are replaced by keyed BLAKE2b pseudonyms. Prefer a pre-pseudonymized `client_id` when your edge can provide one. Generated request identifiers include the input line number, so they are unique within one analyzed JSONL stream even when two records otherwise match.

`ati analyze` rejects lines longer than 1,000,000 characters by default; use `--max-line-characters` to set a stricter or larger operational limit. Session state is bounded by default to 10,000 active clients and 128 events per client. When the active-client limit is reached, ATI evicts the least-recently-used client history; tune `--max-clients`, `--max-events-per-client`, and `--session-window-seconds` for the memory envelope of the deployment. The completion summary reports processed events, active sessions, evictions, and the configured client limit.

When `--output` is used, ATI writes to a sibling temporary file and replaces the destination only after successful processing. This preserves the prior output on errors and makes it safe to intentionally use the same input and output path.

See [`docs/schemas.md`](docs/schemas.md) and [`examples/nginx/ati-json.conf`](examples/nginx/ati-json.conf).

## Output

V0-compatible analysis omits the `verification` field entirely. With V1 verification enabled, a separate versioned verification payload records the resolved identity state and privacy-safe evidence. This preserves the original four score dimensions while making stronger identity evidence auditable.

Scores remain conservative hand-authored estimates, not calibrated probabilities. Learned calibration is a later milestone.

## Curated identity registry

The packaged registry contains primary-source-backed identities from OpenAI, Anthropic, Perplexity, and Google. Every entry records its official source and `last_verified` date.

Important distinctions encoded in the registry include:

- model-development crawlers vs search crawlers vs user-triggered fetchers;
- company identity vs AI-related purpose, so a service bot from an AI company is not automatically labeled AI traffic;
- current and transitional User-Agent names;
- User-Agent claims vs actual verification.

The registry intentionally does **not** treat `Google-Extended` as an HTTP User-Agent because Google documents it as a robots.txt product token, not a separate crawler User-Agent.

## Behavioral features

ATI keeps feature engineering small and inspectable:

- path depth and static-asset classification;
- bounded per-client request count and duration;
- mean inter-arrival time and coefficient of variation;
- requests per minute;
- asset and error ratios;
- unique-path ratio;
- Shannon path entropy;
- selected non-sensitive browser-context presence flags.

No single behavioral feature is treated as proof of automation.

## Privacy and security defaults

ATI output does not contain:

- raw client IP addresses;
- query-string values;
- Cookie or Authorization values;
- request or response bodies.

Raw source addresses and signature material required for V1 verification live only in an ephemeral `VerificationContext`; they are not copied into normalized events or detections. User-Agent strings remain because they are a core claim signal and should still receive appropriate retention controls.

Read [`SECURITY.md`](SECURITY.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/source-trust-policy.md`](docs/source-trust-policy.md) before using real traffic.

## Research positioning

The project is informed by, but does not copy, work including Anubis, CrowdSec, FingerprintJS BotD, FPScanner, AgentECHO, Logwick, River, JA4/JA4+, crawler/adversarial tooling, and industry research on differentiating AI traffic types. See [`docs/research/open-source-landscape.md`](docs/research/open-source-landscape.md) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

Our intended differentiation is the combination of:

1. verifiable identity as a first-class dimension;
2. behavior and identity kept separate from risk;
3. explainable evidence for every score change;
4. privacy-minimized server-side operation;
5. unknown-agent discovery and drift-aware ML as later research;
6. vendor-neutral adapters from logs toward reverse proxies, Zeek/Suricata, and edge providers.

## Roadmap

### V0: passive log intelligence

- [x] JSONL parser and privacy transform
- [x] curated agent claims
- [x] request/session features
- [x] explainable rules and four scores
- [x] CLI
- [ ] real-world shadow-mode benchmark dataset
- [ ] probability calibration

### Local evaluation

Evaluate authorized labels against existing automation scores without uploading or retaining a corpus:

```bash
ati evaluate detections.jsonl --labels labels.jsonl --threshold 0.5
```

The evaluator reports coverage, confusion-matrix metrics, and Brier score. It does not train or calibrate a model. See [`docs/evaluation.md`](docs/evaluation.md) for the JSONL contract, label provenance requirements, and leakage-safe benchmark design.

### V1: verified identity

- [x] ephemeral verification context preserving V0 privacy/output behavior
- [x] official IP-range verification with provenance/freshness
- [x] provider-documented FCrDNS support
- [x] RFC 9421 / Web Bot Auth optional verification stack
- [x] deterministic resolver with explicit conflicts
- [x] content-addressed source cache and hardened explicit refresh
- [x] `ati sources status|refresh|validate`
- [x] Python 3.11/3.12/3.13 core + verification CI
- [x] wheel/sdist build and clean-install verification
- [ ] additional log/edge adapters beyond the current JSONL/Nginx-oriented seam
- [ ] real-world shadow-mode conformance corpus

### V2: learned detection

- CatBoost/LightGBM/XGBoost benchmarks on leakage-safe splits;
- calibration and cost-sensitive thresholds;
- unseen-family evaluation;
- anomaly discovery and clustering;
- concept-drift experiments with River.

### V3: real-time sensor

A Go or Rust sidecar/reverse proxy in observe-only mode first. Enforcement remains a separate policy component and only follows validated false-positive targets.

## Development

```bash
python -m pip install -e '.[dev,verification]'
pytest --cov=agent_traffic_intelligence
ruff check .
mypy src
```

Or:

```bash
make check
```

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request.

## Non-goals

- claiming an exact underlying foundation model from traffic without explicit evidence;
- bypassing access controls or anti-bot systems;
- collecting request bodies or credentials;
- shipping a production blocking policy before shadow-mode validation.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
