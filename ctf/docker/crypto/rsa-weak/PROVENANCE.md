# Weak-RSA challenge provenance

- Origin: implemented for T3MP3ST issue #193 after decomposition of proposal #163.
- License: AGPL-3.0-or-later, matching the repository.
- Construction: two deliberately small, close primes in `challenge.py`; the solver factors the modulus, derives the private exponent, and decrypts the numeric answer.
- Reproduction: `python3 ctf/docker/crypto/rsa-weak/solve.py` must print `424242`.
- Expected public tuple: `n=1000036000099`, `e=65537`, `ciphertext=598195729194`.
- Sensitive-data review: all primes, plaintext, ciphertext, answer, and flag are synthetic constants created for this lab. No acquired data, production secret, key, credential, or user identifier is present.
- Artifact policy: no generated key or binary is committed. The reviewed Python source is the complete generator and solution evidence.
- Container trust: the Dockerfile pins the official Python multi-platform OCI index digest. There are no package-manager or third-party runtime dependencies. The challenge service has only an internal network; a separately constrained path allow-list gateway owns the loopback host binding.
- Verification date: 2026-09-03.

This construction is intentionally insecure and must never be copied into production cryptography.
