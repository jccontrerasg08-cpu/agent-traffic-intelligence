# Open-Source Landscape

Reviewed 2026-08-14. This document is architectural research, not an incorporation list.

## Closest projects

| Project | Strength | Gap relative to ATI direction |
|---|---|---|
| Anubis | practical AI crawler firewall with weighted policy/challenge model | focused on access control; ATI starts with measurement, identity confidence, behavior and ML research |
| AgentECHO | AI bot traffic analytics, server SDKs, known UA catalog | known-agent analytics overlaps strongly; ATI differentiates on verification, unknown-agent behavior, privacy-minimized logs and model evaluation |
| Logwick | local server-log classification/sessionization, no JS | strong overlap with log analytics; ATI uses a permissive core license and separates four score dimensions plus future cryptographic identity |
| FPScanner | modern browser fingerprint and automation detection | browser-centric; ATI is server-first and treats browser telemetry as optional future evidence |
| BotD | simple browser bot detection | useful client signal but limited against sophisticated automation and not server-first |
| CrowdSec | mature event/scenario/remediation architecture | broad security engine rather than AI-agent identity/intelligence |
| ai-scraping-defense | multi-layer reverse-proxy/honeypot defense | defense-focused and experimental; ATI keeps observe/enforce separated |

## Adversarial references

Crawl4AI and modern Playwright/Selenium/stealth tooling are useful for generating controlled evasive traffic in a lab. Their role is testing the detector, not enabling unauthorized bypass of third-party protections.

## Design conclusions

1. A static User-Agent catalog is commodity functionality.
2. Identity verification must be a separate axis from claimed identity.
3. Behavior must work when User-Agent and TLS signals are spoofed.
4. The dataset/evaluation methodology is part of the product, not an afterthought.
5. Unknown-agent discovery and drift monitoring are a better research frontier than adding hundreds of brittle regexes.
6. Enforcement should remain downstream from detection until false-positive costs are measured.
