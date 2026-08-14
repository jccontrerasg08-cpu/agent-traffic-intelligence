# ADR 0001: Observe before enforce

**Status:** Accepted

## Decision

The first production-facing mode is passive. It may classify and log but cannot block, challenge, throttle, or mutate upstream requests.

## Rationale

Bot classification is adversarial and false positives are expensive. A shadow period provides real prevalence, calibration, and failure-mode data before remediation is introduced.

## Consequences

V0 can run safely on copied logs. Real-time enforcement is deferred and must consume the same detection contract rather than embedding policy inside classifiers.
