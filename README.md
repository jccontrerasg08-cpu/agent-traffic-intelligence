# Agent Traffic Intelligence

Self-hosted, explainable intelligence for automated and AI-originated web traffic.

> **Status: pre-alpha / observe-only.** V0 analyzes access logs. It does not block, challenge, throttle, or mutate production traffic.

## Why this exists

Modern web traffic no longer fits a single `human | bot` flag. A verified search crawler, an AI training crawler, a user-triggered AI fetcher, browser automation, and an abusive scraper can all be automated while having very different identities, purposes, and risk.

Agent Traffic Intelligence keeps those dimensions separate:

- `automation_score`: evidence that the request/session is automated.
- `ai_score`: evidence that the automation is AI-related.
- `identity_confidence`: evidence that a claimed actor identity is authentic.
- `risk_score`: evidence that observed behavior is operationally risky or abusive.

A User-Agent claim is **not** identity verification. V0 intentionally gives known User-Agent claims low `identity_confidence` until stronger verification adapters exist.

## V0 architecture

```text
JSONL access logs
      |
      v
parser + privacy transform
      |
      v
normalized RequestEvent
      |\
      | +--> curated agent registry
      |          |
      v          v
request/session features
      |          |
      +-----> evidence rules
                 |
                 v
       independent logistic scores
                 |
                 v
         detection JSONL
```

The runtime has **zero third-party Python dependencies**. Development tooling is optional.

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

## Input contract

V0 accepts line-delimited JSON objects. Common Nginx-style keys are recognized:

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

The normalizer strips query strings before generating a `RequestEvent`. Raw IPs are replaced by keyed BLAKE2b pseudonyms. Prefer a pre-pseudonymized `client_id` when your edge can provide one.

See [`docs/schemas.md`](docs/schemas.md) and [`examples/nginx/ati-json.conf`](examples/nginx/ati-json.conf).

## Output example

```json
{
  "automation_score": 0.8581,
  "ai_score": 0.8320,
  "identity_confidence": 0.0630,
  "risk_score": 0.0832,
  "identity": {
    "provider": "openai",
    "agent": "GPTBot",
    "actor_type": "ai_crawler",
    "intent": "model-development",
    "verification_state": "claimed"
  },
  "evidence": [
    {
      "code": "known-agent-ua-claim",
      "source": "registry",
      "description": "User-Agent claims a curated identity; User-Agent alone is spoofable and is not verification."
    }
  ]
}
```

Scores are estimates from a conservative hand-authored V0 baseline, not calibrated probabilities yet. Learned calibration is a later milestone.

## Curated identity registry

The packaged registry currently contains primary-source-backed identities from OpenAI, Anthropic, Perplexity, and Google. Every entry records its official source and `last_verified` date.

Important distinctions encoded in the registry include:

- model-development crawlers vs search crawlers vs user-triggered fetchers;
- company identity vs AI-related purpose, so a service bot from an AI company is not automatically labeled AI traffic;
- current and transitional User-Agent names;
- User-Agent claims vs actual verification.

The registry intentionally does **not** treat `Google-Extended` as an HTTP User-Agent because Google documents it as a robots.txt product token, not a separate crawler User-Agent.

## Behavioral features

V0 keeps feature engineering small and inspectable:

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

User-Agent strings remain in normalized events because they are a core identity signal. Operators should still treat them as potentially identifying metadata and apply appropriate retention controls.

Read [`SECURITY.md`](SECURITY.md) and [`docs/threat-model.md`](docs/threat-model.md) before using real traffic.

## Research positioning

The project is informed by, but does not copy, open-source work including Anubis, CrowdSec, FingerprintJS BotD, FPScanner, AgentECHO, Logwick, River, JA4/JA4+, and crawler/adversarial tooling. See [`docs/research/open-source-landscape.md`](docs/research/open-source-landscape.md) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

Our intended differentiation is the combination of:

1. verifiable identity as a first-class dimension;
2. behavior and identity kept separate from risk;
3. explainable evidence for every score change;
4. privacy-minimized server-side operation;
5. future unknown-agent discovery and drift-aware ML;
6. vendor-neutral adapters from logs to reverse proxies, Zeek/Suricata, and edge providers.

## Roadmap

### V0: passive log intelligence

- [x] JSONL parser and privacy transform
- [x] curated agent claims
- [x] request/session features
- [x] explainable rules and four scores
- [x] CLI
- [ ] real-world shadow-mode benchmark dataset
- [ ] probability calibration

### V1: verified identity

- official IP/rDNS adapters where providers publish verifiable infrastructure;
- Web Bot Auth / HTTP Message Signature verification;
- cached identity material with provenance and freshness metadata;
- adapters for Nginx, Envoy, HAProxy, Traefik, Cloudflare logs, Zeek, and Suricata.

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
python -m pip install -e '.[dev]'
pytest
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
