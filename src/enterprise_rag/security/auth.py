"""Authentication: PBKDF2 password hashing and signed, expiring bearer tokens.

Tokens are HMAC-SHA256 signed JSON payloads (a minimal, dependency-free JWT)
with server-side revocation support and a hard expiry.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from enterprise_rag.security.identity import Department, User

PBKDF2_ITERATIONS = 240_000
TOKEN_PREFIX = "erag"
_HASH_ALGO = "pbkdf2_sha256"


class AuthError(Exception):
    """Raised when authentication fails or a token is unusable."""

    def __init__(self, message: str, *, status_code: int = 401) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256: ``algo$iterations$salt$hash``."""
    if not password:
        raise ValueError("Password must not be empty.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_HASH_ALGO}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time verification of ``password`` against a stored hash."""
    if not encoded or not password:
        return False
    try:
        algo, iterations_s, salt_hex, digest_hex = encoded.split("$")
        if algo != _HASH_ALGO:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations_s)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


# --------------------------------------------------------------------------- #
# Token encoding helpers
# --------------------------------------------------------------------------- #
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """Decoded token payload."""

    subject: str
    department: str
    roles: tuple[str, ...]
    clearance: int
    issued_at: int
    expires_at: int
    token_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sub": self.subject,
            "dept": self.department,
            "roles": list(self.roles),
            "clr": self.clearance,
            "iat": self.issued_at,
            "exp": self.expires_at,
            "jti": self.token_id,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> TokenClaims:
        return cls(
            subject=str(payload["sub"]),
            department=str(payload.get("dept", "")),
            roles=tuple(payload.get("roles", [])),
            clearance=int(payload.get("clr", 1)),
            issued_at=int(payload["iat"]),
            expires_at=int(payload["exp"]),
            token_id=str(payload["jti"]),
        )


class TokenService:
    """Issues and verifies signed bearer tokens."""

    def __init__(
        self,
        secret: str,
        ttl_minutes: int = 120,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not secret:
            raise ValueError("SECRET_KEY must not be empty.")
        self._secret = secret.encode("utf-8")
        self._ttl_seconds = max(1, ttl_minutes) * 60
        self._clock = clock
        self._revoked: dict[str, int] = {}

    # ------------------------------------------------------------- issuing
    def issue(self, user: User) -> tuple[str, TokenClaims]:
        """Create a signed token for ``user``; returns ``(token, claims)``."""
        now = int(self._clock())
        claims = TokenClaims(
            subject=user.username,
            department=user.department.value,
            roles=tuple(sorted(user.role_names)),
            clearance=user.clearance,
            issued_at=now,
            expires_at=now + self._ttl_seconds,
            token_id=secrets.token_urlsafe(12),
        )
        payload = _b64encode(json.dumps(claims.to_dict(), sort_keys=True).encode("utf-8"))
        signature = _b64encode(
            hmac.new(self._secret, payload.encode("ascii"), hashlib.sha256).digest()
        )
        return f"{TOKEN_PREFIX}.{payload}.{signature}", claims

    # ---------------------------------------------------------- verifying
    def verify(self, token: str) -> TokenClaims:
        """Validate signature, expiry and revocation; return the claims."""
        if not token or token.count(".") != 2:
            raise AuthError("Malformed bearer token.")
        prefix, payload, signature = token.split(".")
        if prefix != TOKEN_PREFIX:
            raise AuthError("Unsupported token type.")

        expected = _b64encode(
            hmac.new(self._secret, payload.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(expected, signature):
            raise AuthError("Invalid token signature.")

        try:
            claims = TokenClaims.from_dict(json.loads(_b64decode(payload)))
        except (ValueError, KeyError, TypeError) as exc:  # pragma: no cover - corrupt token
            raise AuthError("Unreadable token payload.") from exc

        now = int(self._clock())
        if claims.expires_at <= now:
            raise AuthError("Token has expired.")
        self._purge(now)
        if claims.token_id in self._revoked:
            raise AuthError("Token has been revoked.")
        return claims

    # ---------------------------------------------------------- revoking
    def revoke(self, token: str) -> str | None:
        """Revoke a single token (logout). Returns the token id if revocable."""
        try:
            claims = self.verify(token)
        except AuthError:
            return None
        self._revoked[claims.token_id] = claims.expires_at
        return claims.token_id

    def revoked_count(self) -> int:
        self._purge(int(self._clock()))
        return len(self._revoked)

    def _purge(self, now: int) -> None:
        for jti in [jti for jti, exp in self._revoked.items() if exp <= now]:
            self._revoked.pop(jti, None)

    @staticmethod
    def department_of(claims: TokenClaims) -> Department:
        """Best-effort department reconstruction from claims."""
        try:
            return Department(claims.department)
        except ValueError:  # pragma: no cover - unknown department in token
            return Department.SECURITY


__all__ = [
    "AuthError",
    "PBKDF2_ITERATIONS",
    "TokenClaims",
    "TokenService",
    "hash_password",
    "verify_password",
]
