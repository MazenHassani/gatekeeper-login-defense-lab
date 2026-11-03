# Local verification evidence

Verified 2026-11-03 with OpenJDK 21.0.12.1, Maven 3.9.9, Redis 8.0.5 and Linux x86-64. These are local development checks, not production certification.

## Functional and failure checks

`mvn -f java/pom.xml verify`: **44 tests passed**, zero failures/errors/skips.

- 16 core tests: fixed-window expiry, outcome feedback, bounded capacity/no live eviction, shadow safety, shared-NAT denial, failure-generation isolation, simultaneous source admissions, semaphore saturation, exception/idempotent/cancellation release, completed-permit reuse, pseudonymous keys, invalid input and proxy spoofing.
- 12 Redis tests: shared feedback, capacity/policy mismatch, concurrent instance invariants, **two separate JVMs sharing a 30-attempt limit**, expiration generations, refusal, accidental unshared-key rejection, uncertain read timeout without blind retry, held local permit during outage, bounded client-pool exhaustion, Redis out-of-memory denial, nonpersistent restart/history loss, and latency sampling.
- 5 Spring Security tests: four wrapper contract tests using lambda/mock managers plus one actual `ProviderManager`/`DaoAuthenticationProvider` with BCrypt and unknown-user dummy verification. The contract checks cover provider skipped when denied, successful application authentication, provider outage cleanup, generic credential failure, unauthenticated delegate result rejection and already-authenticated input rejection.
- 5 actual HTTP example tests: successful credential verification/no session, equivalent generic wrong-password/unknown-user response, spoofed forwarding does not bypass policy, correct-password denial after failed-history limit, cross-origin/body guards, assets/metrics/CSP.
- 1 local-memory latency harness test.
- 5 adversarial memory-store tests: full live-capacity identity churn with a deterministic expiry-inspection bound, mass expiry/targeted replacement, concurrent churn preserving failed history, nanoTime rollover, and out-of-order concurrent clock samples. Timings are recorded without brittle wall-clock pass thresholds.

**Framework boundary:** this tests real Spring Security password-provider behavior, not a deployed Spring Boot application, HTTP filter chain, servlet integration, framework proxy middleware or full session/MFA flow. The HTTP integration tests exercise the JDK example server.

Redis tests start their own ephemeral loopback-only server, with persistence off, a 64 MiB memory bound and noeviction. OOM/pause/restart operations affect only that test-owned instance. They do not test Redis Cluster, Sentinel, multi-region behavior, real failover, TLS or production ACLs. The restart test intentionally demonstrates lost history; it is not a durability guarantee.

The separate original Python simulation also passes its 12 tests. JavaScript syntax checks pass for both dashboards.

## Admission latency sample

Reproduce with `mvn -f java/pom.xml verify`; fresh JSON is written to `java/target/benchmark-*.json`. Recorded raw samples' summaries are under [measurements](measurements/).

| Store | p50 | p95 | p99 |
|---|---:|---:|---:|
| Local memory | 35.258 µs | 1,305.397 µs | 2,287.536 µs |
| Loopback Redis | 446.980 µs | 946.199 µs | 1,242.202 µs |

Each uses 100 warmup admissions, 2,000 measured calls, 4 worker threads and one source/account. Timing is around `admit` only; completion occurs afterward. **No password work, network login traffic, identity diversity, sustained saturation, confidence intervals or deployment topology is represented.** JIT, scheduling, shared-host noise and execution order matter; the higher memory tail here is not evidence Redis is faster in general. No throughput/capacity or bot-detection claim follows from this sample.

## Saturation defect reproduction and regression

Static review found that the initial memory store scanned every entry under its synchronized lock whenever a new identity hit capacity. This was a real denial-of-service amplification path, not evidence of large-site readiness. Static review is not an independent security audit.

An identical capped in-process probe was compiled against the initial `22c89f5` JAR and the corrected store. Each filled the store with live state, then measured 200 unique capacity-denied requests. The fixed clock keeps everything unexpired and isolates the problematic live-capacity path.

| Live entries | Initial denied-request p50 | Corrected denied-request p50 |
|---|---:|---:|
| 10,000 | 266.706 µs | 1.223 µs |
| 100,000 | 2,607.118 µs | 0.518 µs |
| 1,000,000 | 21,829.369 µs | 0.495 µs |

The automated 100,000-entry regression recorded exactly 1,000 expiry-candidate inspections for 1,000 denied churn requests. The deterministic maintenance/index-size invariants are the primary regression guards; these noisy local timings are supporting reproduction evidence, not a general speedup or capacity claim. The probe has no warmup and runs ascending sizes, so JIT/order effects explain some variation. Raw p50/p95/p99 results and method are in [the saturation record](measurements/2026-11-03-memory-saturation.json).

Reproduce the current probe after `mvn -f java/pom.xml verify`:

```sh
java -Xmx512m -cp java/target/classes:java/target/test-classes dev.gatekeeper.MemoryStoreSaturationProbe
```

## Dependency check

OSV querybatch returned no known vulnerabilities for the 26 resolved Maven coordinates on 2026-11-03. Exact coordinates/results and scope exclusions are in [the dependency record](measurements/2026-11-03-dependencies.json). This is a point-in-time known-vulnerability check, not an audit, license review, supply-chain guarantee or scan of build plugins/JDK/Redis/OS. Recheck before deployment.

## Browser verification

Chrome was used for the real Java integration. One correct-password request followed by eight invalid attempts produced 9 evaluated requests, 4 admitted password checks, 5 pre-hash denials, 1 successful authentication and 3 invalid credential checks. The screenshot is a real capture of that loopback run with a synthetic fixture; it does not show real users or attack effectiveness. No simulated fingerprints/challenges feed this Java integration.

## Deployment gates still open

Independent security review, representative load/false-positive evaluation, operational canary traffic, real Redis topology/partition/failover/ACL/TLS tests, validated edge/proxy configuration, JVM/resource profiling, rollout/key-rotation testing and on-call ownership remain required before a serious deployment. No Maven Central artifact or stable release has been published.
