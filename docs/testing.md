# Local verification evidence

Verified 2026-11-03 with OpenJDK 21.0.12.1, Maven 3.9.9, Redis 8.0.5 and Linux x86-64. These are local development checks, not production certification.

## Functional and failure checks

`mvn -f java/pom.xml verify`: **38 tests passed**, zero failures/errors/skips.

- 16 core tests: fixed-window expiry, outcome feedback, bounded capacity/no live eviction, shadow safety, shared-NAT denial, failure-generation isolation, simultaneous source admissions, semaphore saturation, exception/idempotent/cancellation release, completed-permit reuse, pseudonymous keys, invalid input and proxy spoofing.
- 12 Redis tests: shared feedback, capacity/policy mismatch, concurrent instance invariants, **two separate JVMs sharing a 30-attempt limit**, expiration generations, refusal, accidental unshared-key rejection, uncertain read timeout without blind retry, held local permit during outage, bounded client-pool exhaustion, Redis out-of-memory denial, nonpersistent restart/history loss, and latency sampling.
- 4 Spring Security contract tests: provider skipped when denied, successful application authentication, provider outage cleanup, generic credential failure, unauthenticated delegate result rejection and already-authenticated input rejection.
- 5 actual HTTP example tests: successful credential verification/no session, equivalent generic wrong-password/unknown-user response, spoofed forwarding does not bypass policy, correct-password denial after failed-history limit, cross-origin/body guards, assets/metrics/CSP.
- 1 local-memory latency harness test.

Redis tests start their own ephemeral loopback-only server, with persistence off, a 64 MiB memory bound and noeviction. OOM/pause/restart operations affect only that test-owned instance. They do not test Redis Cluster, Sentinel, multi-region behavior, real failover, TLS or production ACLs. The restart test intentionally demonstrates lost history; it is not a durability guarantee.

The separate original Python simulation also passes its 12 tests. JavaScript syntax checks pass for both dashboards.

## Admission latency sample

Reproduce with `mvn -f java/pom.xml verify`; fresh JSON is written to `java/target/benchmark-*.json`. Recorded raw samples' summaries are under [measurements](measurements/).

| Store | p50 | p95 | p99 |
|---|---:|---:|---:|
| Local memory | 58.008 µs | 1,057.064 µs | 2,138.093 µs |
| Loopback Redis | 484.843 µs | 1,115.952 µs | 1,506.428 µs |

Each uses 100 warmup admissions, 2,000 measured calls, 4 worker threads and one source/account. Timing is around `admit` only; completion occurs afterward. **No password work, network login traffic, identity diversity, sustained saturation, confidence intervals or deployment topology is represented.** JIT, scheduling, shared-host noise and execution order matter; the higher memory tail here is not evidence Redis is faster in general. No throughput/capacity or bot-detection claim follows from this sample.

## Dependency check

OSV querybatch returned no known vulnerabilities for the 26 resolved Maven coordinates on 2026-11-03. Exact coordinates/results and scope exclusions are in [the dependency record](measurements/2026-11-03-dependencies.json). This is a point-in-time known-vulnerability check, not an audit, license review, supply-chain guarantee or scan of build plugins/JDK/Redis/OS. Recheck before deployment.

## Browser verification

Chrome was used for the real Java integration. One correct-password request followed by eight invalid attempts produced 9 evaluated requests, 4 admitted password checks, 5 pre-hash denials, 1 successful authentication and 3 invalid credential checks. The screenshot is a real capture of that loopback run with a synthetic fixture; it does not show real users or attack effectiveness. No simulated fingerprints/challenges feed this Java integration.

## Deployment gates still open

Independent security review, representative load/false-positive evaluation, operational canary traffic, real Redis topology/partition/failover/ACL/TLS tests, validated edge/proxy configuration, JVM/resource profiling, rollout/key-rotation testing and on-call ownership remain required before a serious deployment. No Maven Central artifact or stable release has been published.
