Imagine a login page receiving thousands of attempts from bots at the same time.

Checking each password takes work. That’s intentional: password hashing is designed to be slow. But under a flood of fake attempts, that work can put pressure on the server before real users get a chance to log in.

I built a small lab called Gatekeeper to explore one approach: check a few inexpensive signals first, then decide whether to allow, challenge or reject a request before doing the password check.

The dashboard lets you change the traffic and see how many password checks are avoided, alongside how many legitimate users get challenged or blocked. It’s a simulation, so it’s useful for exploring the trade-off, not measuring how a real system would perform.

Code: https://github.com/MazenHassani/gatekeeper-login-defense-lab
