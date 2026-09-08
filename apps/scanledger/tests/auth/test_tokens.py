from datetime import UTC, datetime, timedelta

from falcoria_scanledger.auth import tokens


def test_generate_token_default_length_and_alphabet() -> None:
    token = tokens.generate_token()
    assert len(token) == 60
    assert token.isalnum()


def test_generate_token_custom_length() -> None:
    assert len(tokens.generate_token(16)) == 16


def test_generate_token_is_random() -> None:
    assert tokens.generate_token() != tokens.generate_token()


def test_hash_token_is_stable_sha256_hex() -> None:
    assert tokens.hash_token("abc") == tokens.hash_token("abc")
    assert len(tokens.hash_token("abc")) == 64
    assert tokens.hash_token("abc") != tokens.hash_token("abd")


def test_expiry_from_none_means_no_expiry() -> None:
    assert tokens.expiry_from(None) is None


def test_expiry_from_offsets_the_given_now() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert tokens.expiry_from(3600, now=now) == now + timedelta(hours=1)


def test_is_expired_none_never_expires() -> None:
    assert tokens.is_expired(None) is False


def test_is_expired_at_boundaries() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert tokens.is_expired(now - timedelta(seconds=1), now=now) is True
    assert tokens.is_expired(now, now=now) is True
    assert tokens.is_expired(now + timedelta(seconds=1), now=now) is False
