"""
Shared helpers for the paper-eval v2 harnesses (scripts/paper/), current protocol
(commit 3c2f5f9: finite-key gate, Toeplitz PA, key-confirmation tag, encrypted metadata).

Read-only with respect to src/: these scripts import the real use cases and the test
support module, run them, and record numbers. Nothing here edits the package.
"""

from __future__ import annotations

import math
import os
import socket
import statistics
import sys
import threading
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))  # make `tests.invariants.support` importable

from qkd.core import pqc  # noqa: E402
from qkd.usecases.common import KeyConfirmationError, KeyExchangeResult, PeerAuthError  # noqa: E402
from qkd.usecases.receive_file import ReceiveResult  # noqa: E402

try:
    from cryptography.exceptions import InvalidTag  # noqa: E402
except Exception:  # pragma: no cover
    class InvalidTag(Exception):
        ...

RESULTS = ROOT / "experiments" / "results" / "paper-v2"
RESULTS.mkdir(parents=True, exist_ok=True)

# The runner (runner/alice.py, runner/bob.py) maps internal results to four outcome
# strings. NOTE: QBER-threshold abort, finite-key-bound abort, AND KeyConfirmationError
# all map to "aborted_qber"; the stopping CHECK is recorded separately (stopping_check).
OUTCOME_COMPLETED = "completed"
OUTCOME_ABORTED_QBER = "aborted_qber"
OUTCOME_ABORTED_AUTH = "aborted_auth"
OUTCOME_FAILED = "failed"


def keypair() -> tuple[bytes, bytes]:
    """A fresh ML-DSA-65 identity (public_key, seed)."""
    return pqc.sig_keygen()


def run_parallel(*fns: Callable[[], Any], timeout: float = 900) -> list[Any]:
    """Run each callable in its own thread; return results in order (exceptions captured by caller)."""
    results: list[Any] = [None] * len(fns)

    def run(i: int, fn: Callable[[], Any]) -> None:
        results[i] = fn()

    threads = [threading.Thread(target=run, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout)
    return results


def guarded(fn: Callable[[socket.socket], Any], sock: socket.socket) -> Callable[[], Any]:
    """Run a socket leg; return its result or the exception it raised; shut the socket in finally."""

    def run() -> Any:
        try:
            return fn(sock)
        except Exception as exc:  # noqa: BLE001 - recorded, not raised
            return exc
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    return run


def _kx_of(res: Any) -> KeyExchangeResult | None:
    """Pull the KeyExchangeResult out of either side's return value."""
    if isinstance(res, KeyExchangeResult):
        return res
    if isinstance(res, ReceiveResult):
        return res.key_exchange
    return None


def stopping_check(a_res: Any, b_res: Any) -> str:
    """
    The check that stopped a run, in protocol order:
      threshold | finite_key | tag | signature | gcm | none | error_other | abort_other

    Determined in-process from both sides' results/exceptions, because the runner's
    outcome name collapses threshold/finite_key/tag into the single 'aborted_qber'.
    """
    for r in (a_res, b_res):
        kx = _kx_of(r)
        if kx is not None and kx.aborted:
            reason = (kx.abort_reason or "").lower()
            # Order matters: the finite-key abort reason also contains the substring
            # "qber" (it reports the observed QBER), so test "finite-key" FIRST.
            if "finite-key" in reason:
                return "finite_key"
            if "qber" in reason:
                return "threshold"
            return "abort_other"
    excs = [r for r in (a_res, b_res) if isinstance(r, Exception)]
    if any(isinstance(e, KeyConfirmationError) for e in excs):
        return "tag"
    if any(isinstance(e, PeerAuthError) for e in excs):
        return "signature"
    if any(isinstance(e, InvalidTag) for e in excs):
        return "gcm"
    if excs:
        return "error_other"
    return "none"


def runner_outcome(res: Any) -> str:
    """Replicate runner/alice.py and runner/bob.py exception->outcome mapping for one side."""
    if isinstance(res, KeyConfirmationError):
        return OUTCOME_ABORTED_QBER
    if isinstance(res, PeerAuthError):
        return OUTCOME_ABORTED_AUTH
    if isinstance(res, Exception):
        return OUTCOME_FAILED
    kx = _kx_of(res)
    if kx is not None and kx.aborted:
        return OUTCOME_ABORTED_QBER
    return OUTCOME_COMPLETED


def runner_exit(res: Any) -> int:
    """The process exit code the runner would return: 0 on completed, 1 otherwise."""
    return 0 if runner_outcome(res) == OUTCOME_COMPLETED else 1


def eve_leg(run: Callable[[], Any], eve_a: socket.socket, eve_b: socket.socket) -> Any:
    """
    Run an Eve-in-the-middle leg and shut BOTH relay sockets on return.

    run_eavesdrop (unlike support.proxy) does not shut its own sockets. In the current
    protocol a peer can abort at the key-confirmation tag (step 4b) after the other peer
    has sent its finished: that peer is then blocked in recv for the finished that never
    comes. Shutting the relay sockets here unblocks it with a ConnectionError instead of
    letting run_parallel hang on the join.
    """
    try:
        return run()
    finally:
        for s in (eve_a, eve_b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float, float]:
    """Point estimate and 95% Wilson score interval for k successes in n trials."""
    if n == 0:
        return (float("nan"), float("nan"), float("nan"))
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (p, max(0.0, centre - half), min(1.0, centre + half))


def median_iqr(xs: list[float]) -> tuple[float, float, float, float]:
    """Return (median, q1, q3, iqr). IQR via the inclusive method; single-value safe."""
    xs = sorted(xs)
    if not xs:
        return (float("nan"),) * 4
    med = statistics.median(xs)
    if len(xs) < 2:
        return (med, xs[0], xs[0], 0.0)
    q = statistics.quantiles(xs, n=4, method="inclusive")
    return (med, q[0], q[2], q[2] - q[0])


def loadavg() -> tuple[float, float, float]:
    return os.getloadavg()
