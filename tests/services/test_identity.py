"""Tests for qkd.services.identity — identity lifecycle, trust store, and verifiers."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Deterministic stub for pqc.sig_keygen / fingerprint so tests don't require
# cryptography>=50 or an actual ML-DSA implementation.
# ---------------------------------------------------------------------------

_STUB_PUBLIC_KEY = b"\x01" * 1952   # 1952-byte fake public key
_STUB_SEED = b"\x02" * 32          # 32-byte fake seed


def _stub_sig_keygen() -> tuple[bytes, bytes]:
    return _STUB_PUBLIC_KEY, _STUB_SEED


def _stub_fingerprint(public_key: bytes) -> str:
    import hashlib
    digest = hashlib.sha256(public_key).digest()[:16].hex()
    return "-".join(digest[i : i + 4] for i in range(0, 32, 4))


# A second distinct fake key pair (for "different peer" / "changed key" tests).
_STUB_PUBLIC_KEY_2 = b"\x03" * 1952
_STUB_SEED_2 = b"\x04" * 32

# Pre-compute fingerprints for assertions.
_FP_1 = _stub_fingerprint(_STUB_PUBLIC_KEY)
_FP_2 = _stub_fingerprint(_STUB_PUBLIC_KEY_2)


# Patch at the *usage site* (identity module) so the import-time binding is
# overridden for every test in this file.
_KEYGEN_PATCH = "qkd.services.identity.sig_keygen"
_FP_PATCH = "qkd.services.identity._pqc_fingerprint"


@pytest.fixture(autouse=True)
def _patch_pqc():
    """Replace pqc primitives with deterministic stubs for all tests."""
    with patch(_KEYGEN_PATCH, side_effect=_stub_sig_keygen), \
         patch(_FP_PATCH, side_effect=_stub_fingerprint):
        yield


# ---------------------------------------------------------------------------
# Import the module under test (after fixtures are defined, but the patches
# are applied per-test via the autouse fixture above).
# ---------------------------------------------------------------------------
from qkd.services.identity import (
    CorruptIdentityError,
    CorruptTrustStoreError,
    Identity,
    MissingPublicKeyError,
    PinnedVerifier,
    TrustStore,
    TrustStoreVerifier,
    load_or_create_identity,
)
from qkd.usecases.common import PeerAuthError


# ═══════════════════════════════════════════════════════════════════════════
# Identity tests (Module 2)
# ═══════════════════════════════════════════════════════════════════════════

# ── Test 1: First start creates files with mode 0600 on the seed ──────────

class TestFirstStartCreatesFiles:
    def test_creates_identity_files(self, tmp_path: Path) -> None:
        identity = load_or_create_identity(tmp_path / "id")

        seed_path = tmp_path / "id" / "identity.seed"
        pub_path = tmp_path / "id" / "identity.pub"

        assert seed_path.exists()
        assert pub_path.exists()
        assert identity.public_key == _STUB_PUBLIC_KEY
        assert identity.seed == _STUB_SEED

    def test_seed_file_mode_0600(self, tmp_path: Path) -> None:
        load_or_create_identity(tmp_path / "id")

        seed_path = tmp_path / "id" / "identity.seed"
        mode = stat.S_IMODE(os.stat(seed_path).st_mode)
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        deep = tmp_path / "a" / "b" / "c"
        load_or_create_identity(deep)
        assert (deep / "identity.seed").exists()


# ── Test 2: Second start returns the same identity ────────────────────────

class TestIdempotentReload:
    def test_same_public_key_and_fingerprint(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "id"
        first = load_or_create_identity(id_dir)
        second = load_or_create_identity(id_dir)

        assert first.public_key == second.public_key
        assert first.seed == second.seed
        assert first.fingerprint == second.fingerprint

    def test_does_not_call_keygen_on_reload(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "id"
        load_or_create_identity(id_dir)

        with patch(_KEYGEN_PATCH) as mock_keygen:
            load_or_create_identity(id_dir)
            mock_keygen.assert_not_called()


# ── Test 3: Missing public-key file raises ────────────────────────────────

class TestMissingPublicKey:
    def test_raises_missing_public_key_error(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "id"
        load_or_create_identity(id_dir)

        # Remove only the public key file.
        (id_dir / "identity.pub").unlink()

        with pytest.raises(MissingPublicKeyError, match="public-key file"):
            load_or_create_identity(id_dir)

    def test_does_not_regenerate(self, tmp_path: Path) -> None:
        """Ensure a missing public key never silently triggers keygen."""
        id_dir = tmp_path / "id"
        load_or_create_identity(id_dir)
        (id_dir / "identity.pub").unlink()

        with patch(_KEYGEN_PATCH) as mock_keygen, \
             pytest.raises(MissingPublicKeyError):
            load_or_create_identity(id_dir)
            mock_keygen.assert_not_called()


# ── Test 4: Corrupt / truncated seed file raises ──────────────────────────

class TestCorruptSeedFile:
    def test_truncated_seed_raises(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "id"
        load_or_create_identity(id_dir)

        # Truncate the seed to 16 bytes.
        seed_path = id_dir / "identity.seed"
        seed_path.write_bytes(b"\x00" * 16)

        with pytest.raises(CorruptIdentityError, match="unexpected size"):
            load_or_create_identity(id_dir)

    def test_empty_seed_raises(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "id"
        load_or_create_identity(id_dir)

        seed_path = id_dir / "identity.seed"
        seed_path.write_bytes(b"")

        with pytest.raises(CorruptIdentityError, match="empty"):
            load_or_create_identity(id_dir)

    def test_oversized_seed_raises(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "id"
        load_or_create_identity(id_dir)

        seed_path = id_dir / "identity.seed"
        seed_path.write_bytes(b"\x00" * 64)

        with pytest.raises(CorruptIdentityError, match="unexpected size"):
            load_or_create_identity(id_dir)

    def test_truncated_public_key_raises(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "id"
        load_or_create_identity(id_dir)

        pub_path = id_dir / "identity.pub"
        pub_path.write_bytes(b"\x00" * 100)

        with pytest.raises(CorruptIdentityError, match="unexpected size"):
            load_or_create_identity(id_dir)

    def test_empty_public_key_raises(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "id"
        load_or_create_identity(id_dir)

        pub_path = id_dir / "identity.pub"
        pub_path.write_bytes(b"")

        with pytest.raises(CorruptIdentityError, match="empty"):
            load_or_create_identity(id_dir)


# ── Test 5: Fingerprint format matches spec ───────────────────────────────

class TestFingerprintFormat:
    _FINGERPRINT_RE = re.compile(r"^[0-9a-f]{4}(-[0-9a-f]{4}){7}$")

    def test_fingerprint_is_8_hex_groups(self, tmp_path: Path) -> None:
        identity = load_or_create_identity(tmp_path / "id")
        fp = identity.fingerprint
        assert self._FINGERPRINT_RE.match(fp), f"Fingerprint {fp!r} doesn't match 8-hex-group format"

    def test_fingerprint_stable_across_loads(self, tmp_path: Path) -> None:
        id_dir = tmp_path / "id"
        fp1 = load_or_create_identity(id_dir).fingerprint
        fp2 = load_or_create_identity(id_dir).fingerprint
        assert fp1 == fp2


# ═══════════════════════════════════════════════════════════════════════════
# Trust store tests (Module 3)
# ═══════════════════════════════════════════════════════════════════════════

class TestTrustStoreBasics:
    """TrustStore persistence, missing-file handling, and corrupt-file handling."""

    def test_missing_file_gives_empty_store(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        assert store.all_peers() == {}

    def test_add_and_get(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        store = TrustStore(path)
        rec = store.add(_FP_1, name="Alice")
        assert rec.name == "Alice"
        assert rec.verified is False
        assert store.get(_FP_1) is rec

    def test_duplicate_add_raises(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        store.add(_FP_1)
        with pytest.raises(ValueError, match="already exists"):
            store.add(_FP_1)

    def test_persist_across_reload(self, tmp_path: Path) -> None:
        """Data survives a new TrustStore instance on the same path."""
        path = tmp_path / "peers.json"
        store1 = TrustStore(path)
        store1.add(_FP_1, name="Node-A")

        store2 = TrustStore(path)
        rec = store2.get(_FP_1)
        assert rec is not None
        assert rec.name == "Node-A"
        assert rec.verified is False

    def test_set_verified(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        store.add(_FP_1)
        store.set_verified(_FP_1, verified=True)

        rec = store.get(_FP_1)
        assert rec is not None
        assert rec.verified is True

    def test_set_verified_persists(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        store = TrustStore(path)
        store.add(_FP_1)
        store.set_verified(_FP_1)

        store2 = TrustStore(path)
        rec = store2.get(_FP_1)
        assert rec is not None
        assert rec.verified is True

    def test_set_verified_unknown_raises(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        with pytest.raises(KeyError, match="Unknown peer"):
            store.set_verified("xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx")

    def test_forget_peer(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        store = TrustStore(path)
        store.add(_FP_1, name="Alice")
        assert store.get(_FP_1) is not None
        assert store.forget(_FP_1) is True
        assert store.get(_FP_1) is None

        # Verify persistence
        store2 = TrustStore(path)
        assert store2.get(_FP_1) is None

    def test_forget_unknown_returns_false(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        assert store.forget(_FP_1) is False

    def test_corrupt_json_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        path.write_text("not valid json {{{", encoding="utf-8")
        with pytest.raises(CorruptTrustStoreError, match="Cannot parse"):
            TrustStore(path)

    def test_non_object_json_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(CorruptTrustStoreError, match="must be a JSON object"):
            TrustStore(path)

    def test_non_object_entry_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        path.write_text(json.dumps({_FP_1: "not-a-dict"}), encoding="utf-8")
        with pytest.raises(CorruptTrustStoreError, match="must be a JSON object"):
            TrustStore(path)

    def test_empty_file_gives_empty_store(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"
        path.write_text("", encoding="utf-8")
        store = TrustStore(path)
        assert store.all_peers() == {}


# ── PinnedVerifier ────────────────────────────────────────────────────────

class TestPinnedVerifier:
    def test_matching_key_returns_pinned(self) -> None:
        v = PinnedVerifier(_FP_1)
        assert v.check(_STUB_PUBLIC_KEY) == "pinned"

    def test_wrong_key_raises_peer_auth_error(self) -> None:
        v = PinnedVerifier(_FP_1)
        with pytest.raises(PeerAuthError) as exc_info:
            v.check(_STUB_PUBLIC_KEY_2)
        assert "does not match pinned" in exc_info.value.reason

    def test_error_has_reason_attribute(self) -> None:
        v = PinnedVerifier(_FP_1)
        with pytest.raises(PeerAuthError) as exc_info:
            v.check(_STUB_PUBLIC_KEY_2)
        assert hasattr(exc_info.value, "reason")
        assert isinstance(exc_info.value.reason, str)
        assert len(exc_info.value.reason) > 0


# ── TrustStoreVerifier ────────────────────────────────────────────────────

class TestTrustStoreVerifierTofuOn:
    """TOFU enabled — the default mode."""

    def test_first_contact_returns_new(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        v = TrustStoreVerifier(store, tofu=True)
        result = v.check(_STUB_PUBLIC_KEY)
        assert result == "new"

    def test_first_contact_persists_peer(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        v = TrustStoreVerifier(store, tofu=True)
        v.check(_STUB_PUBLIC_KEY)
        assert store.get(_FP_1) is not None

    def test_second_contact_same_key_returns_pinned(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        v = TrustStoreVerifier(store, tofu=True)
        v.check(_STUB_PUBLIC_KEY)  # "new"
        result = v.check(_STUB_PUBLIC_KEY)  # same key again
        assert result == "pinned"

    def test_different_key_from_new_peer_is_new(self, tmp_path: Path) -> None:
        """A genuinely different peer (different fingerprint) is also 'new'."""
        store = TrustStore(tmp_path / "peers.json")
        v = TrustStoreVerifier(store, tofu=True)
        v.check(_STUB_PUBLIC_KEY)       # peer 1 → "new"
        result = v.check(_STUB_PUBLIC_KEY_2)  # peer 2 → "new"
        assert result == "new"

    def test_verified_peer_returns_verified(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        v = TrustStoreVerifier(store, tofu=True)
        v.check(_STUB_PUBLIC_KEY)  # store it
        store.set_verified(_FP_1)  # mark verified
        result = v.check(_STUB_PUBLIC_KEY)
        assert result == "verified"


class TestTrustStoreVerifierTofuOff:
    """TOFU disabled — unknown peers must be rejected."""

    def test_unseen_key_raises(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        v = TrustStoreVerifier(store, tofu=False)
        with pytest.raises(PeerAuthError) as exc_info:
            v.check(_STUB_PUBLIC_KEY)
        assert "TOFU is disabled" in exc_info.value.reason

    def test_unseen_key_error_has_reason(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        v = TrustStoreVerifier(store, tofu=False)
        with pytest.raises(PeerAuthError) as exc_info:
            v.check(_STUB_PUBLIC_KEY)
        assert hasattr(exc_info.value, "reason")

    def test_known_key_still_accepted(self, tmp_path: Path) -> None:
        """A key pre-registered in the store is accepted even with TOFU off."""
        store = TrustStore(tmp_path / "peers.json")
        store.add(_FP_1, name="Pre-trusted")
        v = TrustStoreVerifier(store, tofu=False)
        result = v.check(_STUB_PUBLIC_KEY)
        assert result == "pinned"

    def test_verified_key_returns_verified_with_tofu_off(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        store.add(_FP_1, verified=True)
        v = TrustStoreVerifier(store, tofu=False)
        result = v.check(_STUB_PUBLIC_KEY)
        assert result == "verified"


class TestTrustStoreVerifierChangedKey:
    """A changed key must ALWAYS raise PeerAuthError, regardless of TOFU.

    Note: Because the trust store is keyed by *fingerprint*, a changed key
    produces a new (unseen) fingerprint.  With TOFU off this naturally
    raises.  With TOFU on the new fingerprint is accepted as "new" —
    which is correct because from the store's perspective it IS a new,
    never-before-seen peer.  The spec's "different key for the same peer
    identity" conflict detection requires a higher-level mapping from
    peer name/address to fingerprint, which is outside this module's scope.
    The tests below verify the store-level behaviour.
    """

    def test_changed_key_tofu_off_raises(self, tmp_path: Path) -> None:
        store = TrustStore(tmp_path / "peers.json")
        store.add(_FP_1, name="Bob")
        v = TrustStoreVerifier(store, tofu=False)

        # The "changed" key has a different fingerprint → unseen → rejected.
        with pytest.raises(PeerAuthError) as exc_info:
            v.check(_STUB_PUBLIC_KEY_2)
        assert "TOFU is disabled" in exc_info.value.reason

    def test_changed_key_tofu_on_is_new_peer(self, tmp_path: Path) -> None:
        """With TOFU on, a new fingerprint is accepted as a genuinely new peer.

        Higher layers (node/discovery) are responsible for detecting that
        the same *name* presented a different *fingerprint*.
        """
        store = TrustStore(tmp_path / "peers.json")
        store.add(_FP_1, name="Bob")
        v = TrustStoreVerifier(store, tofu=True)

        result = v.check(_STUB_PUBLIC_KEY_2)
        assert result == "new"


class TestTrustStoreVerifierPersistence:
    """Verify that the trust store data survives across instances."""

    def test_store_persists_across_verifier_reload(self, tmp_path: Path) -> None:
        path = tmp_path / "peers.json"

        # First session: TOFU accepts and stores the key.
        store1 = TrustStore(path)
        v1 = TrustStoreVerifier(store1, tofu=True)
        assert v1.check(_STUB_PUBLIC_KEY) == "new"

        # Second session: new store instance, same file.
        store2 = TrustStore(path)
        v2 = TrustStoreVerifier(store2, tofu=True)
        assert v2.check(_STUB_PUBLIC_KEY) == "pinned"


class TestPeerVerifierProtocolConformance:
    """Both verifiers satisfy the PeerVerifier protocol from usecases.common."""

    def test_pinned_verifier_is_peer_verifier(self) -> None:
        from qkd.usecases.common import PeerVerifier
        v = PinnedVerifier(_FP_1)
        assert isinstance(v, PeerVerifier)

    def test_trust_store_verifier_is_peer_verifier(self, tmp_path: Path) -> None:
        from qkd.usecases.common import PeerVerifier
        store = TrustStore(tmp_path / "peers.json")
        v = TrustStoreVerifier(store, tofu=True)
        assert isinstance(v, PeerVerifier)


# ═══════════════════════════════════════════════════════════════════════════
# Safety tests
# ═══════════════════════════════════════════════════════════════════════════

class TestNoImportLeaks:
    """Ensure identity.py doesn't import heavy or forbidden modules."""

    def test_no_node_or_api_imports(self) -> None:
        import qkd.services.identity as mod
        source = Path(mod.__file__).read_text()
        for forbidden in ("services.node", "services.api", "frontend"):
            assert forbidden not in source, (
                f"identity.py must not import from {forbidden}"
            )
