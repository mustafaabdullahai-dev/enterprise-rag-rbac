"""FastAPI dependencies: authentication, role gates, context access."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from enterprise_rag.context import AppContext
from enterprise_rag.security.auth import AuthError
from enterprise_rag.security.identity import User

BEARER_PREFIX = "Bearer "


def get_context(request: Request) -> AppContext:
    """The process-wide application context (built during startup)."""
    context: AppContext | None = getattr(request.app.state, "context", None)
    if context is None:  # pragma: no cover - startup misconfiguration
        raise HTTPException(status_code=503, detail="Application context is not ready.")
    return context


def _extract_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing bearer token.")
    if not authorization.startswith(BEARER_PREFIX):
        raise HTTPException(
            status_code=401, detail="Authorization header must be 'Bearer <token>'."
        )
    token = authorization[len(BEARER_PREFIX) :].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer token.")
    return token


def get_current_user(
    context: Annotated[AppContext, Depends(get_context)],
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    """Validate the bearer token and return the current principal."""
    try:
        return context.verify_token(_extract_token(authorization))
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


def get_raw_token(authorization: Annotated[str | None, Header()] = None) -> str:
    return _extract_token(authorization)


def require_roles(*roles: str) -> Callable[[User], User]:
    """Dependency factory: 403 unless the principal holds one of ``roles``."""

    def dependency(user: Annotated[User, Depends(get_current_user)]) -> User:
        if not user.has_role(*roles):
            raise HTTPException(
                status_code=403,
                detail={
                    "message": "Your account does not have this capability.",
                    "required_roles": sorted(roles),
                },
            )
        return user

    return dependency


CurrentUser = Annotated[User, Depends(get_current_user)]
ContextDep = Annotated[AppContext, Depends(get_context)]
RawToken = Annotated[str, Depends(get_raw_token)]

__all__ = [
    "ContextDep",
    "CurrentUser",
    "get_context",
    "get_current_user",
    "RawToken",
    "require_roles",
]
