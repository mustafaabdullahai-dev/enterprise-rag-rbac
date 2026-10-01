"""Authentication tests: password hashing, token signing, tampering, revocation."""

from __future__ import annotations

import pytest

from enterprise_rag.security.auth import (
    AuthError,
    TokenService,
    hash_password,
    verify_password,
)


def test_password_hash_roundtrip():
    encoded = hash_password("correct horse battery staple", iterations=1000)
    assert encoded.startswith("pbkdf2_sha256$1000$")
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong", encoded)
    assert not verify_password("", encoded)


def test_password_hashes_are_salted():
    a = hash_password("same-password", iterations=500)
    b = hash_password("same-password", iterations=500)
    assert a != b, "identical passwords must not produce identical hashes"
    assert verify_password("same-password", a) and verify_password("same-password", b)


def test_verify_rejects_malformed_hash():
    assert not verify_password("x", "not-a-hash")


def test_token_issue_and_verify():
    from enterprise_rag.security.identity import demo_users

    service = TokenService("unit-test-secret", ttl_minutes=5)
    user = demo_users()[0]
    token, claims = service.issue(user)
    decoded = service.verify(token)
    assert decoded.subject == user.username
    assert decoded.token_id == claims.token_id
    assert set(decoded.roles) == set(user.role_names)


def test_tampered_token_signature_is_rejected():
    from enterprise_rag.security.identity import demo_users

    service = TokenService("unit-test-secret", ttl_minutes=5)
    token, _ = service.issue(demo_users()[0])
    prefix, payload, signature = token.split(".")
    forged = f"{prefix}.{payload}.{signature[:-3]}aaa"
    with pytest.raises(AuthError):
        service.verify(forged)


def test_token_signed_with_another_secret_is_rejected():
    from enterprise_rag.security.identity import demo_users

    issued = TokenService("secret-a", ttl_minutes=5).issue(demo_users()[0])[0]
    with pytest.raises(AuthError):
        TokenService("secret-b", ttl_minutes=5).verify(issued)


def test_expired_token_is_rejected():
    from enterprise_rag.security.identity import demo_users

    clock = {"now": 1_000_000.0}
    service = TokenService("unit-test-secret", ttl_minutes=1, clock=lambda: clock["now"])
    token, _ = service.issue(demo_users()[0])
    clock["now"] += 120  # 2 minutes later
    with pytest.raises(AuthError, match="expired"):
        service.verify(token)


def test_revoked_token_is_rejected():
    from enterprise_rag.security.identity import demo_users

    service = TokenService("unit-test-secret", ttl_minutes=5)
    token, _ = service.issue(demo_users()[0])
    assert service.verify(token)  # valid before logout
    service.revoke(token)
    with pytest.raises(AuthError, match="revoked"):
        service.verify(token)


def test_malformed_token_rejected():
    with pytest.raises(AuthError):
        TokenService("s", ttl_minutes=1).verify("garbage")
    with pytest.raises(AuthError):
        TokenService("s", ttl_minutes=1).verify("erag.abc.def")
