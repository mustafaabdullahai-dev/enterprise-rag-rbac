"""Identity model: departments, capability roles, clearance levels, and users.

The model deliberately separates three orthogonal concepts, which is what makes
real enterprise authorization work:

* ``department`` - the org unit a person belongs to (who they sit with).
* ``roles``      - capability grants, which may cross departments (e.g.
                   ``compliance_officer`` can audit HR *and* Finance).
* ``clearance``  - the maximum data classification the person may ever read.

A document is readable only when *both* an ownership grant (role/department)
*and* a sufficient clearance are present. Absence of a grant denies by default.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Department(str, Enum):
    """Organisational units that own documents."""

    ENGINEERING = "engineering"
    HR = "hr"
    FINANCE = "finance"
    LEGAL = "legal"
    SALES = "sales"
    EXECUTIVE = "executive"
    SECURITY = "security"


class Role(str, Enum):
    """Capability roles (grants), independent of department."""

    EMPLOYEE = "employee"
    MANAGER = "manager"
    HR_BUSINESS_PARTNER = "hr_business_partner"
    FINANCE_ANALYST = "finance_analyst"
    LEGAL_COUNSEL = "legal_counsel"
    COMPLIANCE_OFFICER = "compliance_officer"
    EXECUTIVE = "executive"
    PLATFORM_ADMIN = "platform_admin"


class Classification(str, Enum):
    """Data classification levels, ordered from least to most sensitive."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def min_clearance(self) -> int:
        """Minimum clearance level required to read data at this classification."""
        return _MIN_CLEARANCE[self]

    @property
    def rank(self) -> int:
        return self.min_clearance

    @classmethod
    def levels_visible_to(cls, clearance: int) -> list[str]:
        """Classification values a user with ``clearance`` may ever read."""
        return [c.value for c in cls if clearance >= c.min_clearance]


_MIN_CLEARANCE: dict[Classification, int] = {
    Classification.PUBLIC: 1,
    Classification.INTERNAL: 2,
    Classification.CONFIDENTIAL: 3,
    Classification.RESTRICTED: 4,
}

MAX_CLEARANCE = 4


@dataclass(frozen=True, slots=True)
class User:
    """An authenticated principal."""

    username: str
    display_name: str
    department: Department
    roles: frozenset[Role] = field(default_factory=frozenset)
    clearance: int = 1
    title: str = ""
    active: bool = True
    password_hash: str = ""

    @property
    def role_names(self) -> frozenset[str]:
        return frozenset(r.value for r in self.roles)

    def has_role(self, *roles: str | Role) -> bool:
        wanted = {r.value if isinstance(r, Role) else str(r) for r in roles}
        return bool(wanted & self.role_names)

    def public(self) -> dict[str, Any]:
        """Serialise without the password hash (safe for API responses/logs)."""
        return {
            "username": self.username,
            "display_name": self.display_name,
            "department": self.department.value,
            "roles": sorted(self.role_names),
            "clearance": self.clearance,
            "title": self.title,
        }


# --------------------------------------------------------------------------- #
# Demo directory. Synthetic people only - no real PII anywhere in this project.
# --------------------------------------------------------------------------- #
DEMO_PASSWORDS: dict[str, str] = {
    "amina.yusuf": "intern-demo",
    "bilal.khan": "engineer-demo",
    "sara.ahmed": "hr-demo",
    "david.okafor": "finance-demo",
    "hina.saleem": "sales-demo",
    "lena.martinez": "exec-demo",
    "omar.rahim": "compliance-demo",
    "admin.ops": "admin-demo",
}


def demo_users() -> list[User]:
    """Built-in directory used when ``data/users.json`` is absent."""
    return [
        User(
            username="amina.yusuf",
            display_name="Amina Yusuf",
            department=Department.ENGINEERING,
            roles=frozenset({Role.EMPLOYEE}),
            clearance=1,
            title="Engineering Intern",
        ),
        User(
            username="bilal.khan",
            display_name="Bilal Khan",
            department=Department.ENGINEERING,
            roles=frozenset({Role.EMPLOYEE, Role.MANAGER}),
            clearance=2,
            title="Senior Backend Engineer",
        ),
        User(
            username="sara.ahmed",
            display_name="Sara Ahmed",
            department=Department.HR,
            roles=frozenset({Role.EMPLOYEE, Role.HR_BUSINESS_PARTNER}),
            clearance=4,
            title="HR Business Partner",
        ),
        User(
            username="david.okafor",
            display_name="David Okafor",
            department=Department.FINANCE,
            roles=frozenset({Role.EMPLOYEE, Role.FINANCE_ANALYST}),
            clearance=3,
            title="Finance Analyst",
        ),
        User(
            username="lena.martinez",
            display_name="Lena Martinez",
            department=Department.EXECUTIVE,
            roles=frozenset({Role.EMPLOYEE, Role.EXECUTIVE}),
            clearance=4,
            title="Chief Financial Officer",
        ),
        User(
            username="hina.saleem",
            display_name="Hina Saleem",
            department=Department.SALES,
            roles=frozenset({Role.EMPLOYEE, Role.MANAGER}),
            clearance=2,
            title="Sales Manager",
        ),
        User(
            username="omar.rahim",
            display_name="Omar Rahim",
            department=Department.LEGAL,
            roles=frozenset({Role.EMPLOYEE, Role.LEGAL_COUNSEL, Role.COMPLIANCE_OFFICER}),
            clearance=4,
            title="Compliance Officer",
        ),
        # Deliberately *not* granted content access: platform admins operate the
        # service, they do not read restricted business data (least privilege /
        # segregation of duties).
        User(
            username="admin.ops",
            display_name="Ops Admin",
            department=Department.SECURITY,
            roles=frozenset({Role.PLATFORM_ADMIN}),
            clearance=2,
            title="Platform Administrator",
        ),
    ]


class UserStore:
    """In-memory directory backed by a JSON file, with a demo fallback."""

    def __init__(self, users: list[User] | None = None) -> None:
        self._users: dict[str, User] = {}
        for user in users if users is not None else demo_users():
            self._users[user.username] = user

    # ------------------------------------------------------------- loading
    @classmethod
    def load(cls, path: Path | None) -> UserStore:
        """Load users from ``path``; fall back to the built-in demo directory."""
        if path is None or not Path(path).exists():
            return cls(demo_users())

        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        users: list[User] = []
        for item in raw:
            users.append(
                User(
                    username=item["username"],
                    display_name=item.get("display_name", item["username"]),
                    department=Department(item["department"]),
                    roles=frozenset(Role(r) for r in item.get("roles", [])),
                    clearance=int(item.get("clearance", 1)),
                    title=item.get("title", ""),
                    active=bool(item.get("active", True)),
                    password_hash=item.get("password_hash", ""),
                )
            )
        return cls(users)

    # ------------------------------------------------------------ accessors
    def get(self, username: str) -> User | None:
        return self._users.get(username)

    def list(self) -> list[User]:
        return sorted(self._users.values(), key=lambda u: u.username)

    def upsert(self, user: User) -> None:
        self._users[user.username] = user

    def with_hashes(self, hashes: dict[str, str]) -> UserStore:
        """Return a copy of the store with password hashes attached."""
        patched: list[User] = []
        for user in self.list():
            digest = hashes.get(user.username, user.password_hash)
            if digest == user.password_hash:
                patched.append(user)
                continue
            patched.append(
                User(
                    username=user.username,
                    display_name=user.display_name,
                    department=user.department,
                    roles=user.roles,
                    clearance=user.clearance,
                    title=user.title,
                    active=user.active,
                    password_hash=digest,
                )
            )
        return UserStore(patched)

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._users)

    def __contains__(self, username: object) -> bool:
        return username in self._users


__all__ = [
    "Classification",
    "DEMO_PASSWORDS",
    "Department",
    "MAX_CLEARANCE",
    "Role",
    "User",
    "UserStore",
    "demo_users",
]
