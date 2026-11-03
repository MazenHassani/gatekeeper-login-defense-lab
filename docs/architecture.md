# Admission architecture and scope

Status: experimental 0.1. No claim of big-site readiness, bot detection accuracy or audited security.

## Problem and alternatives

Gatekeeper's narrow job is application-aware admission immediately before password work, followed by actual authentication outcome feedback. Allow never authenticates. It does not replace an edge service or identity provider.

- [Bucket4j](https://bucket4j.com/) already provides mature token buckets and distributed backends. Prefer it for generic rate limiting.
- [Resilience4j](https://resilience4j.readme.io/docs/ratelimiter) provides local rate/concurrency resilience primitives.
- [Spring Cloud Gateway](https://docs.spring.io/spring-cloud-gateway/reference/spring-cloud-gateway-server-webflux/gatewayfilter-factories/requestratelimiter-factory.html) and [Envoy global rate limiting](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/other_features/global_rate_limiting) enforce traffic policy at gateways.
- Existing identity platforms supply MFA, passkeys, sessions, recovery and account security. Use them for authentication.

The proposed integration seam combines source/pair policy, a bounded password-work permit, feedback, shadow decisions and explicit input trust. This is an integration convenience, not a novel security algorithm or evidence that established alternatives are insufficient.

## Boundaries and invariants

1. Edge infrastructure protects network/connection/body budgets. Gatekeeper runs after bounded parsing, before user lookup/password work.
2. The server derives the source from a peer address. Forwarding headers matter only when the immediate peer and intervening rightmost hops are explicitly trusted. The original socket peer must be available; never blindly reuse a framework-mutated remote address.
3. Account normalization belongs to the application. Keys use a keyed digest; no raw usernames, passwords or IP metric labels.
4. Store atomically consumes a per-source fixed-window attempt budget and observes source+account failed-verification history. There is no account-wide lockout or fingerprint allow-list.
5. Each admitted call must hold one local semaphore permit for the entire authentication operation. No waiting queue. Release exactly once, including exceptions. Cancellation must actually stop work before closing its permit.
6. Application verifies credentials and owns MFA/session/authorization. Unknown users require equivalent dummy password work and generic errors.
7. Shadow mode bypasses policy denials only. Concurrency, store errors, memory capacity and invalid-input safeguards remain enforced. Start shadow with sufficient storage capacity and monitor friction.

## Local state under adversarial saturation

The memory backend uses a capped map and a balanced expiry index containing exactly one node per retained entry. Hash-table backing storage is allocated at construction. Per admission, expiry work checks at most 32 indexed candidates and the two requested keys; index operations are O(log N). Live saturation fails closed without full-map scans or eviction. Expired backlogs drain incrementally. The metadata table and expiry nodes add bounded memory overhead; the synchronized store still serializes operations and makes no real-time latency guarantee.

Clock samples may arrive out of order when concurrent callers sample before acquiring the store lock. Relative deadlines allow those earlier samples, preserve nanoTime wraparound behavior and keep old feedback isolated from replacement windows. The admission contract still requires a server-supplied monotonic clock.

## Distributed design

Redis may coordinate rate/failure policy across application instances with the same secret, namespace and policy. Atomic Lua scripts use server TIME and Redis expiration generations. Source and source+account keys are in a source-selected shard with the same Cluster hash tag. Per-shard cardinality is capped. No global hash tag; no assertion of cross-shard atomicity. A single hot source is deliberately confined to one shard. Distributed concurrency is not implemented: node-local permits protect each process, and the total cluster budget grows with node count.

Lua execution is atomic but Redis scripts block their shard. Keep bounded scripts, monitor latency, use a dedicated noeviction deployment with memory headroom. TTL is not a cardinality cap. On capacity exhaustion or uncertain timeout deny the current request; never blindly retry a mutation. Redis failure can lose recorded outcomes or failover state; local concurrency remains available as a separate guard, not a claim of global correctness through failure.

TLS, Redis ACLs, bounded connection pools/timeouts, network isolation and stable shared-key rollout are deployment responsibilities. A Redis Cluster/Sentinel deployment must have its own failure tests before use. Only configurations actually tested in this repository are supported as experimental paths; a design is not a tested production option.

## Availability, privacy and operations

Fail closed on store failure/capacity; no automatic fail-open switch. This reduces hashing exposure but can deny all legitimate traffic. Operators should have a reviewed rollout/rollback procedure, upstream controls, and recovery access independent of the gate. Do not silently turn policy off during an attack. Success does not erase failed history (prevents reset tricks); expiry provides recovery.

HMAC keys must be shared across nodes for coordinated counters, generated/stored by the operator, rotated deliberately; rotation resets limiter identity and can briefly relax enforcement. Pseudonymous keys remain sensitive. Keep retention short, no raw credentials in logs, do not export account/source labels. Metrics are cumulative low-cardinality counters and an instantaneous in-flight gauge, not a consistent transaction snapshot.

## Threats and remaining limitations

Distributed low-and-slow attacks, residential proxy rotation, valid stolen credentials, shared NAT harm, IPv6 address rotation, fixed-window boundary bursts, state-capacity denial of service, Redis restarts/eviction/failover loss, inconsistent policy/secret rollout, blocked/slow clients before admission, applications that release permits early, external tasks ignoring cancellation and application integration errors remain risks. No CAPTCHA or TLS/device attestation is invented. Per-source and per-pair counters alone cannot protect a globally targeted account across many sources.

Before a serious deployment: independent security review, representative load and false-positive evaluation, dependency scanning, real topology/ACL/TLS/failover tests, measured p50/p95/p99 under saturation, observability/alerts, canary shadow traffic, and operational ownership are release gates. This project does not satisfy those gates merely by passing local tests.

Guidance evaluated: [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html), [Redis scripting](https://redis.io/docs/latest/develop/programmability/eval-intro/), [Redis eviction](https://redis.io/docs/latest/develop/reference/eviction/). OWASP's defense-in-depth, generic-error, MFA and lockout-denial-of-service guidance motivates the boundary above; this is not a compliance claim.
