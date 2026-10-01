"""Authentication endpoints: login, logout, current principal."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from enterprise_rag.api.deps import ContextDep, CurrentUser, RawToken
from enterprise_rag.security.auth import AuthError

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64, examples=["sara.ahmed"])
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict[str, object]


@router.post("/login", response_model=LoginResponse, summary="Exchange credentials for a token")
def login(payload: LoginRequest, context: ContextDep) -> LoginResponse:
    try:
        user, token = context.authenticate(payload.username.strip(), payload.password)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    return LoginResponse(
        token=token,
        expires_in=context.settings.token_ttl_minutes * 60,
        user=user.public(),
    )


@router.post("/logout", summary="Revoke the current token")
def logout(context: ContextDep, token: RawToken) -> dict[str, object]:
    return {"revoked": context.logout(token)}


@router.get("/me", summary="Current principal, roles and clearance")
def me(user: CurrentUser, context: ContextDep) -> dict[str, object]:
    return {
        **user.public(),
        "capabilities": {
            "admin": context.user_is_admin(user),
            "compliance": context.user_is_compliance(user),
        },
        "visible_classifications": [
            c
            for c in ("public", "internal", "confidential", "restricted")
            if user.clearance >= {"public": 1, "internal": 2, "confidential": 3, "restricted": 4}[c]
        ],
        "visible_documents": len(context.authorizer.visible_doc_ids(user, context.catalog.acls())),
    }


@router.get("/demo-users", summary="Demo accounts (development convenience)")
def demo_users(context: ContextDep) -> dict[str, object]:
    hints = context.login_hint()
    if not hints:
        raise HTTPException(status_code=404, detail="Demo users are disabled in this environment.")
    return {
        "enabled": True,
        "users": [
            {
                "username": username,
                "password": password,
                **(
                    context.user_store.get(username).public()
                    if context.user_store.get(username)
                    else {}
                ),
            }
            for username, password in hints.items()
        ],
    }
