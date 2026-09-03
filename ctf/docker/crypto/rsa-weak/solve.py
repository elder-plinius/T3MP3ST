"""Deterministic offline solver used as executable solution evidence."""

from math import isqrt

from challenge import ANSWER, P, Q, PUBLIC_EXPONENT, public_challenge


def factor_close_primes(modulus: int) -> tuple[int, int]:
    candidate = isqrt(modulus)
    while candidate > 1:
        if modulus % candidate == 0:
            return candidate, modulus // candidate
        candidate -= 1
    raise ValueError("modulus was not factorable")


def solve() -> int:
    challenge = public_challenge()
    p, q = factor_close_primes(int(challenge["n"]))
    phi = (p - 1) * (q - 1)
    private_exponent = pow(PUBLIC_EXPONENT, -1, phi)
    return pow(int(challenge["ciphertext"]), private_exponent, int(challenge["n"]))


if __name__ == "__main__":
    assert {P, Q} == set(factor_close_primes(P * Q))
    assert solve() == ANSWER
    print(ANSWER)
