# Security

Gatekeeper 0.1 is experimental. It has no independent audit, production traffic evidence, or validated large-site/failover deployment. Do not treat it as a complete authentication or bot defense system.

The application must authenticate credentials, perform equivalent unknown-user verification, manage MFA/sessions, protect endpoints with TLS/CSRF controls, normalize usernames, derive trusted transport identity, cap input/connection resources, and keep admission permits alive until password work stops.

Keep Redis on protected networks with ACLs, TLS and noeviction. Coordinate namespace/policy/HMAC keys across nodes. Restart, eviction, failover, clock changes or secret rotation can weaken/reset history. A local concurrency budget does not become a global budget when rate state is shared. No automatic fail-open behavior is provided; failure can deny legitimate users.

Core metrics contain no identities. HMAC keys and pseudonymous Redis state remain sensitive; choose short retention and controlled access. No password should be sent to Gatekeeper or logged in examples.

For suspected vulnerabilities, contact the maintainer privately through their GitHub profile before publishing exploit details or secrets in an issue. This project has no guaranteed response SLA. Only current source is maintained; no stable release support policy exists yet.
