I turned a login-defense reel into a small engineering experiment: Gatekeeper, a local lab comparing a naive authentication pipeline with a cheap risk gate before password verification.

The question was simple: how much password-hashing work can we avoid, and how much friction do legitimate users experience?

For one reproducible synthetic workload (120 attempts, seed 42), the protected pipeline performed 41 password verifications instead of 120 — 65.8% fewer. All 29 legitimate attempts were accepted, but 9 were challenged. Other seeds and traffic mixes expose why friction needs to be measured too.

The dashboard makes those tradeoffs visible, with allow/challenge/reject decisions, a request ledger, measured hashing time and legitimate-user outcomes. Every successful login still requires password verification.

Built with Python's standard library and vanilla JavaScript. No real accounts, external attack traffic or paid services. Fingerprint signals and challenges are explicitly simulated; these results are an educational experiment, not evidence of production bot detection.

Inspired by calculusphile's reel: https://www.instagram.com/reel/DejYAGbxOAM/

Code / GitHub: https://github.com/MazenHassani/gatekeeper-login-defense-lab
Development / GitLab: https://gitlab.com/mazen.hassani/gatekeeper-login-defense-lab

#SecurityEngineering #Python #Authentication #BuildInPublic
