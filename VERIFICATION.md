# Verification record

Verified 2026-11-03 in the selected local environment.

- Python 3.14.4, Linux; no third-party runtime packages.
- `python3 -m unittest -v`: 12 tests passed. Covers wrong-password rejection, challenge failures avoiding hash work, challenge success still requiring a correct password, shared-source harm, seeded bounded workloads, accounting, origin/host guards, oversized requests and unknown target fields/routes.
- `node --check static/app.js`: passed.
- `python3 -m compileall -q .`: passed.
- Chrome desktop: opened http://127.0.0.1:8765, ran the default experiment through the actual UI, observed 79/120 checks avoided, 29/29 legitimate accepted, 9 challenged, 0 blocked, and populated ledger. Screenshot: `results/dashboard.jpg`. Browser hash timings were approximately 979 → 328 ms; the independently saved CLI record is 960.02 → 327.75 ms. This variation is expected.
- Ran all 9 scenario/seed combinations; raw records in `results/scenarios.json`.

| Scenario | Seed | Checks avoided / 120 | Legitimate | Challenged | Blocked |
|---|---:|---:|---:|---:|---:|
| Mixed | 42 | 79 | 29 | 9 | 0 |
| Mixed | 7 | 80 | 28 | 1 | 0 |
| Mixed | 101 | 78 | 27 | 5 | 1 |
| Mostly legitimate | 42 | 16 | 101 | 3 | 0 |
| Mostly legitimate | 7 | 17 | 95 | 9 | 0 |
| Mostly legitimate | 101 | 15 | 100 | 7 | 1 |
| Bot heavy | 42 | 98 | 10 | 3 | 0 |
| Bot heavy | 7 | 101 | 6 | 0 | 0 |
| Bot heavy | 101 | 105 | 2 | 0 | 0 |

Browser verification was desktop only; responsive CSS is included but mobile layout was not independently verified. Server binding initially failed in the restricted shell; a reviewed escalation successfully started the loopback-only server. No unresolved runtime blocker.

