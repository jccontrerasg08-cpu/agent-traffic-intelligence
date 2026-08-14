# Security Policy

## Supported versions

This project is pre-alpha. Security fixes are applied to the default branch until a stable release line exists.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting when enabled. Do not open public issues containing exploit details, credentials, secrets, production traffic, raw packet captures or personal data. If private reporting is unavailable, contact the maintainer privately before sharing sensitive reproduction material.

## Public reproduction data

Never attach real access logs without independent sanitization. Remove or transform raw IP addresses, cookies/authorization, query values, request/response bodies, account identifiers, session tokens and signature material. Prefer synthetic fixtures.

## Identity verification safety

V1 is observe-only. User-Agent is a claim, not authentication. A verified identity is not automatically safe and does not lower `risk_score` by itself.

Raw source address and signature values are ephemeral verification inputs and must never be serialized in detections or normal logs. Untrusted forwarded headers must not drive positive network verification.

Unknown `Signature-Agent` URIs are not fetched automatically. Live source fetching must use HTTPS, public-destination checks, redirect revalidation, response limits and TLS hostname verification. DNS/network timeout, stale cache and missing optional crypto support are operational conditions, not identity failures.

## Source and key compromise

Provider range documents and key directories are external trust dependencies. Cached evidence records URI, profile, freshness and SHA-256 provenance. If a provider source/key is suspected compromised, disable or remove that source profile and review affected detections rather than silently rewriting history.

## Repository automation

Actions are pinned to full commit SHAs and permissions are least privilege. `pull_request_target` workflows must never checkout or execute PR-head code. Artifact attestations, when release publishing is added, establish provenance only and do not replace vulnerability review.
