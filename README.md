# Gatekeeper / Login Defense Lab

A personal portfolio experiment: compare expensive password verification on every login attempt with a cheap risk gate that admits, challenges or rejects first. Real PBKDF2 computation, synthetic identities, and a dashboard that exposes legitimate-user friction alongside saved work.

## Run locally

Requires Python 3.10+ and a modern browser. No packages, accounts, secrets, paid services, database or build step.

```sh
cd gatekeeper
python3 -m unittest -v
python3 server.py
```

Open **http://127.0.0.1:8765** in Chrome. Click **Run comparison**. Stop with Ctrl+C. Use the exact loopback address, since Host and Origin validation deliberately reject aliases. The server has no externally configurable bind address. Do not expose it through a tunnel or deploy it as a real authentication system.

For a reproducible CLI experiment:

```sh
python3 lab.py > results/mixed-seed42.json
python3 benchmark.py
```

The second command runs all three scenarios at seeds 42, 7 and 101, each capped at 120 attempts. Workload counts and decisions reproduce on the tested Python version; timings vary. Full synthetic event records are in `results/`.

## What is implemented

- Vanilla HTML/CSS/JavaScript dashboard and Python standard-library HTTP server.
- Seeded, in-process workload; no network traffic is generated for individual login attempts. No arbitrary URLs or targets are accepted.
- Baseline performs one PBKDF2-HMAC-SHA256 verification for each attempt.
- Protected path calculates risk from simulated device recognition, simulated suspicious fingerprint, and previous failed password checks for a synthetic source.
- Risk = 45 for suspicious fingerprint + 25 for unknown device + min(15 × source failures, 45). Below 40: allow; 40–84: simulated challenge; 85+: reject. Thresholds are illustrative choices, not trained or validated security rules.
- A successful challenge only admits a password check. **Every accepted login requires successful password verification**, compared using `hmac.compare_digest`.
- The dashboard reports gate decisions, verification counts, measured hash time, legitimate accepted/challenged/blocked counts, and an event ledger. Failure outcomes are generic. Detailed risk signals appear only in this synthetic educational dashboard, never a recommended client-facing login response.

## Measured example

Recorded on Python 3.14.4 / Linux, mixed scenario, seed 42, 120 attempts. See `results/mixed-seed42.json` for the raw record.

| Metric | Baseline | Protected |
|---|---:|---:|
| Password verifications | 120 | 41 |
| Measured hash time | 960.02 ms | 327.75 ms |
| Legitimate attempts accepted | 29 / 29 | 29 / 29 |
| Legitimate attempts challenged | 0 | 9 |
| Legitimate attempts blocked | 0 | 0 |

79 password verifications (65.8%) were avoided **in this synthetic workload**. Gate decisions: 30 allow, 58 challenge, 32 reject. Some challenged requests still perform verification. A zero blocked count in one run does not establish safety; other seeded scenarios expose blocked legitimate users. This is not a throughput benchmark, internet attack test, or production effectiveness claim.

Methodology: identical generated rows and fresh state per pipeline, sequential execution with baseline first, real PBKDF2 cost at 60,000 iterations, `perf_counter` wall-clock measurement. Hash timing excludes challenge latency and network cost. No warmup, randomized execution order or statistical confidence interval; scheduling, thermal behavior and baseline-first ordering can bias timings. Verification counts are the principal comparison. The iteration count and fixed salt/password are educational fixtures, not a production password storage recommendation.

## Threat model and limitations

**Question:** Can early admission decisions reduce password hashing under a burst of invalid synthetic logins while keeping friction visible?

**Modeled adversary:** repeated invalid passwords, suspicious or unknown simulated devices, and synthetic sources shared with legitimate users. All bot rows use an incorrect password. Legitimate rows use the correct password. This simplifies the data and does not model an attacker with valid stolen credentials.

**Trust boundaries:** synthetic workload → gate → password verifier. Ground-truth `legitimate` labels are used only to generate the workload and calculate metrics; the gate never reads that label. Challenge success probabilities and fingerprint distributions are assumptions, not measured detection rates. There is no real TLS fingerprint collection, device attestation, browser instrumentation, CAPTCHA provider, challenge token, session creation, real user database, or actual login endpoint.

**Evasion and harm:** fingerprints and device signals can be spoofed; distributed low-rate traffic can evade source counters. Shared-source reputation can challenge or deny innocent users. Counters reset per run and have no decay because this models a short burst, not long-lived policy. Account lockouts can themselves become a denial-of-service mechanism; this lab does not implement account lockout. A production design needs carefully scoped throttling, recovery paths, MFA/passkeys, accessible challenge alternatives, monitoring, privacy review and validated thresholds.

**Local safety:** one synchronous server processes experiments serially, caps each at 200 attempts and rejects unknown request fields. Host and same-origin checks reduce browser-driven misuse; body size is capped at 512 bytes. These are local demo guards, not production hardening. A local process can repeatedly call the server, and slow clients can monopolize its single worker. No raw passwords are logged or returned. Results retain synthetic request metadata only. The server's normal access log contains paths/status codes only.

## Attribution and background

Inspired by [calculusphile’s Instagram reel](https://www.instagram.com/reel/DejYAGbxOAM/). This is an independent educational implementation of the broad early-risk-assessment idea, not a transcript or reproduction of the creator's code or branding.

Further reading: [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) and [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html).

## Publication

Develop on personal GitLab; showcase on personal GitHub. No employer code or infrastructure is used. The intended repositories are [GitLab development](https://gitlab.com/mazen.hassani/gatekeeper-login-defense-lab) and [GitHub showcase](https://github.com/MazenHassani/gatekeeper-login-defense-lab). `LINKEDIN_POST.md` contains a reviewable draft with link placeholders.
