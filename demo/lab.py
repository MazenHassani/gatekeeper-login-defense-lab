"""A bounded, in-process authentication cost experiment. No traffic generator."""
from collections import Counter
from dataclasses import dataclass
import hashlib
import hmac
import random
import time

ITERATIONS = 60_000  # Demo cost only; not production password policy.
SALT = b'gatekeeper-synthetic-demo'
PASSWORD = b'local-demo-password'
EXPECTED = hashlib.pbkdf2_hmac('sha256', PASSWORD, SALT, ITERATIONS)
SCENARIOS = {'mixed': 0.75, 'mostly-legitimate': 0.15, 'bot-heavy': 0.95}

@dataclass(frozen=True)
class Attempt:
    identity: str
    source: str
    legitimate: bool
    known_device: bool
    suspicious_fingerprint: bool
    challenge_passes: bool
    correct_password: bool


def workload(scenario='mixed', count=120, seed=42):
    if scenario not in SCENARIOS or type(count) is not int or not 1 <= count <= 200 or type(seed) is not int or not 0 <= seed <= 1_000_000:
        raise ValueError('Unknown scenario or invalid count/seed')
    rng = random.Random(seed)
    rows = []
    for i in range(count):
        legit = rng.random() >= SCENARIOS[scenario]
        rows.append(Attempt(f'user-{i % 24:02}', f'source-{i % 12:02}', legit,
                            legit and rng.random() < .85,
                            rng.random() < (.03 if legit else .7),
                            rng.random() < (.97 if legit else .08), legit))
    return rows


def decision(row, failures):
    # Simulated signals: no TLS inspection or actual device attestation.
    risk = (45 if row.suspicious_fingerprint else 0) + (0 if row.known_device else 25) + min(failures * 15, 45)
    return ('reject' if risk >= 85 else 'challenge' if risk >= 40 else 'allow'), risk


def run_pipeline(rows, protected):
    failures = Counter()
    counts = Counter()
    events = []
    verification_ms = 0.0
    started = time.perf_counter()
    for row in rows:
        action, risk = decision(row, failures[row.source]) if protected else ('allow', 0)
        counts[action] += 1
        admitted = action == 'allow' or (action == 'challenge' and row.challenge_passes)
        accepted = False
        if admitted:
            before = time.perf_counter()
            candidate = hashlib.pbkdf2_hmac('sha256', PASSWORD if row.correct_password else b'wrong-password', SALT, ITERATIONS)
            accepted = hmac.compare_digest(candidate, EXPECTED)
            verification_ms += (time.perf_counter() - before) * 1000
            counts['verifications'] += 1
            if not accepted:
                failures[row.source] += 1
        if row.legitimate:
            counts['legitimate'] += 1
            counts['legitimate_accepted'] += int(accepted)
            counts['legitimate_challenged'] += int(action == 'challenge')
            counts['legitimate_blocked'] += int(not accepted)
        else:
            counts['bot_attempts'] += 1
        events.append({'identity': row.identity, 'source': row.source, 'legitimate': row.legitimate,
                       'decision': action, 'risk': risk, 'verified': admitted, 'accepted': accepted})
    return {'counts': dict(counts), 'verification_ms': round(verification_ms, 2),
            'elapsed_ms': round((time.perf_counter() - started) * 1000, 2), 'events': events}


def experiment(scenario='mixed', count=120, seed=42):
    rows = workload(scenario, count, seed)
    baseline = run_pipeline(rows, False)
    protected = run_pipeline(rows, True)
    avoided = count - protected['counts'].get('verifications', 0)
    return {'scenario': scenario, 'count': count, 'seed': seed, 'iterations': ITERATIONS,
            'baseline': baseline, 'protected': protected,
            'avoided': avoided, 'avoided_percent': round(100 * avoided / count, 1)}

if __name__ == '__main__':
    import json
    print(json.dumps(experiment(), indent=2))
