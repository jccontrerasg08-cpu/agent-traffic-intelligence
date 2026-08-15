# Standards Status

**Last reviewed:** 2026-08-14

| Layer | ATI profile |
| --- | --- |
| HTTP Message Signatures | RFC 9421 |
| Web Bot Auth architecture | `draft-meunier-web-bot-auth-architecture-05` |
| HTTP Message Signatures Directory | `draft-meunier-http-message-signatures-directory-05` |
| Published IP ranges / JAFAR | `draft-illyes-webbotauth-jafar-00` |
| Signature Agent Card / registry | `draft-meunier-webbotauth-registry-03` |

RFC 9421 is stable standards-track work. The other entries are Internet-Drafts and may change. ATI pins their revisions through `StandardsProfile`; a newer draft requires review, tests, and an explicit profile update.

The registry-03 Agent Card model is CIMD/OAuth-style metadata with `client_id`, `jwks_uri` or inline `jwks`, plus the `web_bot_auth` extension. Parsing metadata does not authenticate it.
