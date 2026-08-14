# Standards Status

**Last reviewed:** 2026-08-14

| Layer | ATI profile |
| --- | --- |
| HTTP Message Signatures | RFC 9421 |
| Web Bot Auth architecture | `draft-meunier-web-bot-auth-architecture-05` |
| HTTP Message Signatures Directory | `draft-meunier-http-message-signatures-directory-05` |
| Published IP ranges / JAFAR | `draft-illyes-webbotauth-jafar-00` |
| Signature Agent Card / registry | `draft-meunier-webbotauth-registry-03` |

RFC 9421 is stable standards-track work. The other entries above are Internet-Drafts and can change. ATI pins them through `StandardsProfile`; a newer draft revision requires review, tests and an explicit profile update.

The registry-03 Agent Card model is CIMD/OAuth-style metadata with `client_id`, `jwks_uri` or inline `jwks`, plus the `web_bot_auth` extension. It is deliberately not treated as authenticated merely because a document parses successfully.
