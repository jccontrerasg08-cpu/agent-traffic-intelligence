# Provider Verification Matrix

**Reviewed:** 2026-08-14. Provider capabilities are time-sensitive; runtime truth comes from versioned profiles and source provenance rather than this prose table.

| Provider | Official ranges | FCrDNS | Web Bot Auth / signed agent | Binding notes |
| --- | --- | --- | --- | --- |
| OpenAI | GPTBot, OAI-SearchBot, OAI-AdsBot JSON publications | No ATI rule unless provider documents one | Not assumed | Bot-specific publications may provide agent-scope positive evidence; misses remain conservative unless source semantics say otherwise. |
| Google | Separate common/special/user-triggered range sets | Documented reverse + forward confirmation | `Google-Agent` deployment | Network categories prove Google/provider context unless a narrower binding is documented. Signed Google-Agent uses identity URI `https://agent.bot.goog` and keys at its well-known directory. |
| Perplexity | Separate `PerplexityBot` and `Perplexity-User` publications | Not configured | Not assumed | Separate official publications can bind the exact documented agent. |
| Anthropic | No current crawler IP-range source configured | Not configured | Not assumed | Anthropic does not currently publish crawler ranges, so ATI emits no range-based Anthropic evidence. Historical shared publications are not active trust inputs. |
| Cloudflare examples | Not an ATI provider identity source | Not configured | Public signed-agent interoperability examples | Used as offline interoperability references, not as authority for unrelated providers. |

Provider-owned documentation and machine-readable endpoints outrank third-party bot lists. ASN/cloud hosting alone is never provider authentication.
