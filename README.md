# Gatekeeper Admission

**Java 21 admission controls immediately before password verification.** A small reusable library with authentication outcome feedback, bounded state, a per-process password-work budget, explicit proxy trust and shadow mode.

**Experimental 0.1.** Tested locally; not security-audited or validated at large-site scale. It is not a bot detector, identity provider, CAPTCHA, WAF or authentication system. An `ALLOW` result only permits the application to check credentials.

## Start here

- **Core:** `java/src/main/java/dev/gatekeeper/` — dependency-free local admission API.
- **Spring:** wrapper around a synchronous Spring Security `AuthenticationManager`, with contract tests and a real `DaoAuthenticationProvider`/BCrypt test. No full Spring Boot login deployment, auto-configured filter or reactive adapter is validated.
- **Redis:** optional experimental shared rate/failure counters. Tested against standalone Redis 8.0.5, including two JVMs. Concurrency remains local to each process. Cluster/Sentinel/failover deployments are not validated or supported by this release.
- **Working example:** real Java HTTP endpoint and dashboard using the library, with a synthetic account and real password verification.
- **Original simulation:** separate Python dashboard in `demo/`; its simulated fingerprints/challenges are not used by the library.

See [architecture, alternatives and threat model](docs/architecture.md) before adopting this component. Established gateways and libraries already solve general rate limiting; Gatekeeper focuses on the integration around password work and feedback.

## Build and test

Requires JDK 21+, Maven 3.9+, and `redis-server` on PATH for isolated integration tests. Tests start their own ephemeral loopback Redis, with persistence disabled, and stop it afterward. Existing Redis instances are not modified.

```sh
git clone https://github.com/MazenHassani/gatekeeper-login-defense-lab.git
cd gatekeeper-login-defense-lab
mvn -f java/pom.xml verify
./java/run-example.sh
```

Open **http://127.0.0.1:8766**. This loopback-only example uses a public synthetic fixture (`demo` / `local-example-only`), does not create sessions, and must not be exposed as a production login service. The dashboard calls a real application verifier; there are no simulated gate decisions. Limits can deny a subsequent correct password until expiry.

The built JAR is `java/target/gatekeeper-admission-0.1.0-SNAPSHOT.jar`. It has not been published to Maven Central. Install locally with `mvn -f java/pom.xml install`, then use:

```xml
<dependency>
  <groupId>dev.gatekeeper</groupId>
  <artifactId>gatekeeper-admission</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Spring Security and Jedis dependencies are optional. Local-only consumers do not need either; integrations must provide the corresponding dependencies in their application. This release is built/tested with Spring Security 7.0.8 and Jedis 7.5.3.

## Embed in a Java application

Create one shared gate per protected authentication resource, not one per request:

```java
import dev.gatekeeper.*;
import java.net.InetAddress;
import java.time.Duration;

var policy = new Policy(60, 5, Duration.ofSeconds(60), 4, Policy.Mode.SHADOW);
var gate = new Gatekeeper(policy, new BoundedMemoryStore(20_000));

// source: original transport peer or explicitly trusted proxy resolution.
// canonicalAccount: exactly the application's canonical username normalization.
try (var attempt = gate.admit(source, canonicalAccount)) {
    if (!attempt.allowed()) {
        // Return a generic temporary-unavailability response. Never disclose account existence.
        return;
    }
    boolean valid = applicationChecksPassword(); // Gatekeeper never receives the password.
    attempt.complete(valid ? Gatekeeper.Outcome.SUCCESS : Gatekeeper.Outcome.INVALID_CREDENTIALS);
    if (valid) {
        // Application continues its own MFA/session/authorization flow.
    }
}
```

These last lines are integration pseudocode; a complete runnable application is in [`java/example/ExampleServer.java`](java/example/ExampleServer.java). Always close the permit after the authentication work has actually stopped. Closing on timeout while an external task continues hashing defeats the concurrency bound. Forgotten permits fail closed by exhausting the budget; there is no unsafe automatic permit expiry. An exception/unreported close counts as `ERROR`, releases the permit, and does not invent a credential failure.

The memory store has a hard entry cap and one expiry-index node per retained entry. Its hash table is preallocated at construction to avoid table resizing on admission threads, so choose capacity with startup memory headroom. Each admission checks at most 32 expiry candidates plus its two requested keys, with O(log N) index operations. A full store denies new identities without evicting live state or scanning the whole map. This bounds maintenance work, not JVM/GC or end-to-end latency.

Defaults are not tuned for your traffic: choose limits through shadow traffic, monitoring and false-positive review. Fixed windows permit boundary bursts; no account-wide lockout is applied. Legitimate users behind shared sources can still be denied. Success does not reset failed history; expiration provides recovery.

## Spring integration

The compiled/tested [`SpringAuthenticationGate`](java/src/main/java/dev/gatekeeper/SpringAuthenticationGate.java) wraps your existing synchronous `AuthenticationManager`:

```java
var guarded = new SpringAuthenticationGate(gate, authenticationManager);
var request = UsernamePasswordAuthenticationToken.unauthenticated(canonicalUsername, password);
Authentication result = guarded.authenticate(trustedClientAddress, request);
```

Your application must route every relevant password authentication path through this wrapper, preserve Spring's equivalent unknown-user password work, map failures to generic responses, and retain its own MFA/session/security-context handling. This is not a drop-in Spring Boot starter or a provider for every authentication flow. Infrastructure/provider exceptions remain application errors, not bad-password history.

For forwarding headers, use [`ClientAddress.resolve`](java/src/main/java/dev/gatekeeper/ClientAddress.java) with the **original socket peer**, a joined X-Forwarded-For chain, and an explicit set of trusted proxy IP literals. Untrusted peers' headers are ignored. Parsing is bounded to 8 hops/1,024 characters, uses no DNS, and rejects malformed trusted chains. No proxy is trusted by default. Do not pass a remote address already rewritten by a framework's blanket forwarding middleware. Restrict origin access and configure trusted proxies to append/replace headers consistently. IPv6 addresses are exact addresses, not subnet reputation.

## Optional shared Redis state

Supply your application-owned bounded Jedis `RedisClient` with short connect/read/pool deadlines and an explicit stable random HMAC key of 32–64 bytes shared by all coordinating nodes:

```java
var store = new RedisAdmissionStore(redisClient, "login-v1", 10_000);
var gate = new Gatekeeper(policy, store, sharedHmacKey);
```

Use the same namespace, rate/failure policy, capacity and key on every node. An accidental random local key with a shared store is rejected. A policy mismatch in a populated shard fails closed. Secret mismatch/rotation cannot be detected automatically and changes counter identity; treat key rollout as a policy migration.

The store atomically updates source and source+account state in one of 16 source-selected shards. Each shard has a hard entry cap, two Redis data structures and one policy marker. Live entries are not evicted to admit new identities. Cleanup removes at most 32 stale entries per operation; capacity pressure can temporarily deny even with stale entries pending cleanup. Redis server time selects generation windows so delayed feedback cannot poison a newer generation. This is distributed rate/failure state, **not distributed concurrency**, and does not limit global traffic from many different sources.

**Required deployment assumptions:** dedicated Redis with `noeviction`, memory headroom, protected networking, ACLs and TLS where appropriate. Runtime code never changes server configuration. Eviction/restarts/failover can lose enforcement state. The provided `RedisClients.loopback` factory is for local testing/examples only; it has an 8-connection fail-fast pool and 200 ms connect/read deadlines. Production client configuration/topology is owned by the application and requires its own tests. Do not use a default unbounded/waiting client pool.

Timeouts may have committed state: Gatekeeper does not retry uncertain mutations or automatically fall back to local-only enforcement. Store errors/capacity deny admission even in shadow mode. Outcome-recording failure is counted and the local permit is released; failed history may be missing. Availability trade-offs and rollout/rollback requirements are detailed in [architecture](docs/architecture.md).

## Observability and operating limits

`gate.metrics()` exports cumulative low-cardinality evaluated/admitted/denied/would-deny, capacity, store error, busy, credential outcome counters and a local in-flight gauge. Snapshots are not transactionally consistent during concurrent activity. Do not add raw usernames, IPs or request IDs as metric labels. The example exposes a loopback-only Prometheus text endpoint at `/metrics`; applications should secure their own observability endpoints.

Shadow mode bypasses only source/pair policy denials. Capacity, store failure, invalid input and the local semaphore remain enforced. Shadow results do not prove protection or acceptable false-positive rates. Use edge connection/body/request limits; this component runs too late to solve network floods, slow clients or distributed low-rate attacks.

[Security boundaries and reporting](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Local test and latency evidence](docs/testing.md)

## Original simulation

```sh
cd demo
python3 -m unittest -v
python3 server.py
```

Open http://127.0.0.1:8765. That independent educational simulation has a 200-attempt cap and no arbitrary targets. Its historical measured results do not describe the Java library's detection effectiveness or production throughput.

Development: [personal GitLab](https://gitlab.com/mazen.hassani/gatekeeper-login-defense-lab) · Public source: [GitHub](https://github.com/MazenHassani/gatekeeper-login-defense-lab).
