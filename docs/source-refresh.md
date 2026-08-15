# Source Refresh and Freshness

External identity sources are separated from deterministic analysis.

- `offline`: use packaged/local cache only; no DNS or HTTP.
- `hybrid`: use a fresh cache first and refresh only under explicit verification policy.
- `live`: resolver/source network access is explicitly enabled.

The source cache is content-addressed by SHA-256. URLs never become filesystem paths. Manifest writes are atomic.

Live fetch policy is HTTPS-only, validates public destination IPs, revalidates every redirect, limits response size and redirects, requires JSON media types, and supports ETag/Last-Modified conditional requests. Production transport connects to an already validated IP while preserving TLS hostname/SNI verification to reduce DNS-rebinding exposure.

Scheduled source-health checks belong outside merge-blocking PR CI. Source changes should create reviewable engineering events rather than silently rewriting trust policy.
