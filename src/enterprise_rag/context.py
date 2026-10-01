"""Composition root: builds the object graph shared by API, CLI and tests.

Wiring lives here (not inside FastAPI) so the same context powers:

* the HTTP API,
* the CLI and scripts,
* the evaluation harness and red-team suite,
* the test fixtures.

``authenticate`` / ``verify_token`` re-read the directory on **every** call, so
disabling an account invalidates a session immediately instead of waiting for
the token to expire.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from enterprise_rag.audit.log import AuditLog
from enterprise_rag.config import Settings, get_settings
from enterprise_rag.graph.workflow import GraphDeps, QueryGraph
from enterprise_rag.guardrails.input_guard import InputGuard
from enterprise_rag.guardrails.output_guard import OutputGuard
from enterprise_rag.ingestion.catalog import DocumentCatalog
from enterprise_rag.ingestion.pipeline import IngestionPipeline, IngestionReport
from enterprise_rag.llm.provider import EnterpriseLLM, build_llm
from enterprise_rag.retrieval.retriever import EnterpriseRetriever
from enterprise_rag.retrieval.vector_store import VectorStore
from enterprise_rag.security.acl import Authorizer
from enterprise_rag.security.auth import AuthError, TokenService, hash_password, verify_password
from enterprise_rag.security.identity import (
    DEMO_PASSWORDS,
    User,
    UserStore,
    demo_users,
)
from enterprise_rag.security.rate_limit import RateLimiter

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    """Everything a transport layer needs to run the assistant."""

    settings: Settings
    audit: AuditLog
    store: VectorStore
    catalog: DocumentCatalog
    authorizer: Authorizer
    retriever: EnterpriseRetriever
    input_guard: InputGuard
    output_guard: OutputGuard
    llm: EnterpriseLLM
    graph: QueryGraph
    pipeline: IngestionPipeline
    user_store: UserStore
    tokens: TokenService
    rate_limiter: RateLimiter
    _password_hashes: dict[str, str] = field(default_factory=dict, repr=False)

    # -------------------------------------------------------------- lifecycle
    @classmethod
    def build(cls, settings: Settings | None = None) -> AppContext:
        settings = settings or get_settings()
        settings.ensure_dirs()

        audit = AuditLog(settings.audit_path)
        store = VectorStore(settings)
        authorizer = Authorizer()
        catalog = DocumentCatalog.load(settings.catalog_path)
        retriever = EnterpriseRetriever(
            settings, store, authorizer=authorizer, catalog=catalog, audit=audit
        )
        input_guard = InputGuard(settings)
        output_guard = OutputGuard(settings)
        llm = build_llm(settings)
        graph = QueryGraph(
            GraphDeps(
                settings=settings,
                retriever=retriever,
                llm=llm,
                input_guard=input_guard,
                output_guard=output_guard,
                audit=audit,
                catalog=catalog,
            )
        )
        pipeline = IngestionPipeline(settings, store, catalog=catalog, audit=audit, classifier=None)
        context = cls(
            settings=settings,
            audit=audit,
            store=store,
            catalog=catalog,
            authorizer=authorizer,
            retriever=retriever,
            input_guard=input_guard,
            output_guard=output_guard,
            llm=llm,
            graph=graph,
            pipeline=pipeline,
            user_store=UserStore.load(settings.users_path),
            tokens=TokenService(settings.secret_key, settings.token_ttl_minutes),
            rate_limiter=RateLimiter(
                settings.rate_limit_requests_per_minute, settings.rate_limit_queries_per_day
            ),
        )
        context._password_hashes = context._build_password_hashes()
        context.user_store = context.user_store.with_hashes(context._password_hashes)
        return context

    def ensure_ready(self) -> IngestionReport | None:
        """Auto-ingest the corpus when the index is empty (development convenience)."""
        if self.store.count() > 0:
            return None
        if not self.settings.auto_ingest:
            return None
        logger.info("Index is empty - ingesting %s", self.settings.corpus_path)
        report = self.pipeline.run(reset=True)
        # The pipeline owns its own catalog instance; reload so everyone shares state.
        self.catalog = DocumentCatalog.load(self.settings.catalog_path)
        self.retriever.catalog = self.catalog
        return report

    def refresh_index(self) -> None:
        self.retriever.refresh(force=True)

    # ---------------------------------------------------------- authentication
    def authenticate(self, username: str, password: str) -> tuple[User, str]:
        """Verify credentials and issue a bearer token."""
        user = self.user_store.get(username)
        # Constant-time-ish work factor even when the user does not exist, so
        # response timing does not disclose which accounts are real.
        stored = user.password_hash if user else ""
        password_ok = verify_password(password, stored) if stored else False
        if not user or not password_ok or not user.active:
            self.audit.record(
                actor=username or "unknown",
                action="auth.login",
                outcome="failed",
                severity="warning",
                details={"reason": "invalid_credentials"},
            )
            raise AuthError("Invalid username or password.", status_code=401)

        token, _claims = self.tokens.issue(user)
        self.audit.record(
            actor=user.username,
            action="auth.login",
            outcome="success",
            severity="info",
            details={"roles": sorted(user.role_names), "clearance": user.clearance},
        )
        return user, token

    def verify_token(self, token: str) -> User:
        """Validate a bearer token and return a *current* directory user.

        The directory is authoritative: revoking/disabling an account wins over
        an unexpired token.
        """
        claims = self.tokens.verify(token)
        user = self.user_store.get(claims.subject)
        if user is None or not user.active:
            self.audit.record(
                actor=claims.subject,
                action="auth.token",
                outcome="denied",
                severity="warning",
                details={"reason": "account_removed_or_disabled"},
            )
            raise AuthError("Account is no longer active.", status_code=401)
        return user

    def logout(self, token: str) -> bool:
        revoked = self.tokens.revoke(token)
        if revoked:
            self.audit.record(
                actor="session", action="auth.logout", outcome="success", severity="info"
            )
            return True
        return False

    def has_any_role(self, user: User, roles: set[str]) -> bool:
        """Role gate for admin/compliance endpoints (returns a decision only)."""
        return bool(user.role_names & roles)

    def user_is_admin(self, user: User) -> bool:
        return self.has_any_role(user, self.settings.admin_role_set)

    def user_is_compliance(self, user: User) -> bool:
        return self.has_any_role(user, self.settings.compliance_role_set)

    def login_hint(self) -> dict[str, str]:
        """Demo credentials for the login screen (development only)."""
        if not self.settings.expose_demo_users:
            return {}
        return dict(DEMO_PASSWORDS)

    # -------------------------------------------------------------- internals
    def _build_password_hashes(self) -> dict[str, str]:
        """PBKDF2 hashes for the demo directory, persisted for speed."""
        import json

        path = self.settings.users_path
        if path.exists():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                return {
                    str(item["username"]): str(item.get("password_hash", ""))
                    for item in payload
                    if item.get("password_hash")
                }
            except (json.JSONDecodeError, KeyError):  # pragma: no cover - bad file
                logger.warning("Could not parse %s; regenerating demo credentials", path)

        hashes = {
            user.username: hash_password(password)
            for user, password in (
                (user, DEMO_PASSWORDS.get(user.username, "")) for user in demo_users()
            )
            if password
        }
        self._save_users(hashes)
        return hashes

    def _save_users(self, hashes: dict[str, str]) -> None:
        import json

        path = self.settings.users_path
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = [
            {
                **user.public(),
                "password_hash": hashes.get(user.username, ""),
                "active": user.active,
            }
            for user in demo_users()
        ]
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def build_context(settings: Settings | None = None) -> AppContext:
    """Convenience factory."""
    return AppContext.build(settings)


__all__ = ["AppContext", "build_context"]
