# Privacy: Network Identity Data

V1 needs temporary request material that V0 intentionally does not persist. ATI therefore has two views of an input record:

- `RequestEvent`: privacy-minimized and serializable.
- `VerificationContext`: ephemeral and deliberately non-serializable.

`VerificationContext` may temporarily hold source IP, target URI components and signature-related headers needed to reconstruct covered RFC 9421 components. It must not be added to `Detection.to_dict()`, normal logs, public cache keys or exception text.

Forwarded headers are not trusted by default. A source address is useful for positive identity only when its provenance is `DIRECT_PEER` or a future explicitly configured `TRUSTED_EDGE_CLIENT` path.

After verification, only privacy-safe facts survive: method, outcome, provider/agent binding scope, source digest/freshness and non-identifying match metadata such as prefix length.
