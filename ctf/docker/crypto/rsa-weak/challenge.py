"""Deterministic, intentionally weak RSA training values.

The primes are deliberately close and tiny. Never use this construction for
real cryptography. The answer and flag are synthetic CTF-only values.
"""

P = 1_000_003
Q = 1_000_033
PUBLIC_EXPONENT = 65_537
ANSWER = 424_242
FLAG = "T3MP3ST{close_primes_are_factorable}"


def public_challenge() -> dict[str, int | str]:
    modulus = P * Q
    return {
        "algorithm": "RSA",
        "construction": "intentionally weak close primes",
        "n": modulus,
        "e": PUBLIC_EXPONENT,
        "ciphertext": pow(ANSWER, PUBLIC_EXPONENT, modulus),
    }
