# Contributing

Use JDK 21+, Maven 3.9+ and a local `redis-server` executable. Run `mvn -f java/pom.xml verify`; integration tests create isolated ephemeral loopback Redis instances and exercise multiple JVMs. Run `cd demo && python3 -m unittest -v` for the separate simulation.

Changes to trust, policy, stores, time or permit lifecycle need invariant and failure tests. Document availability and false-positive consequences. Never claim production suitability from a local benchmark. Do not commit secrets, dependency JARs, target directories, real credentials or user traffic. Keep communication/social drafts outside the source repository.

Before adding distributed topology support, provide actual topology, partition/failover, timeout and saturation tests. Avoid automatic retries of uncertain mutations and cross-shard atomicity claims.
