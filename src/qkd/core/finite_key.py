"""
Finite-key length for BB84 (Tomamichel, Lim, Gisin, Renner, Nat. Commun. 3, 634, 2012).

After sifting, Alice and Bob reveal k sample bits to estimate the error rate and
keep n bits. With observed sample error rate Q, the error rate on the n kept bits
is at most Q + mu, except with probability eps_sec, where

    mu = sqrt( (n + k) / (n k)  *  (k + 1) / k  *  ln(2 / eps_sec) )

and an eps_sec-secret, eps_cor-correct key of length

    l = n (1 - h(Q + mu)) - leak_EC - log2( 2 / (eps_sec^2 eps_cor) )

can be extracted by two-universal hashing (h is the binary entropy). The channel
here is noiseless, so there is no error correction, but correctness still has to
be checked: the key confirmation tag in step 4b plays the role of the
verification hash, and we charge its log2(2 / eps_cor) bits as leak_EC.

Every value is computed the same way on both peers from public data (n, k, Q),
so they agree on l without sending it.

This module is pure Python and imports nothing from qiskit.
"""

from __future__ import annotations

import math


def binary_entropy(x: float) -> float:
    """h(x) = -x log2 x - (1 - x) log2 (1 - x), with h(x) = 1 for x >= 0.5."""
    if x <= 0.0:
        return 0.0
    if x >= 0.5:
        return 1.0
    return -x * math.log2(x) - (1 - x) * math.log2(1 - x)


def deviation(n: int, k: int, eps_sec: float) -> float:
    """
    mu: how far the error rate on the n kept bits may exceed the sample's.

    Returns infinity when either set is empty, so callers treat the key as
    having no secure bits.
    """
    if n <= 0 or k <= 0:
        return math.inf
    return math.sqrt((n + k) / (n * k) * (k + 1) / k * math.log(2 / eps_sec))


def secure_key_length(n: int, k: int, qber: float, eps_sec: float, eps_cor: float,
                      reconciliation_bits: int = 0) -> int:
    """
    Number of bits that can be extracted from the n kept bits, floored, never negative.

    n: kept sifted bits (sample removed); k: sample size; qber: observed error
    rate on the sample; reconciliation_bits: parity bits disclosed by error correction
    (Cascade), 0 when there is none. leak_EC is those bits plus the log2(2 / eps_cor)
    bits of the correctness check (the key confirmation tag).
    """
    mu = deviation(n, k, eps_sec)
    if math.isinf(mu):
        return 0
    leak_ec = reconciliation_bits + math.log2(2 / eps_cor)
    length = n * (1 - binary_entropy(qber + mu)) - leak_ec - math.log2(2 / (eps_sec ** 2 * eps_cor))
    return max(0, math.floor(length))
