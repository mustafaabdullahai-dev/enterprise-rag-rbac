"""Unit tests for the policy decision point (deny-by-default authorization)."""

from __future__ import annotations

import pytest

from enterprise_rag.security.acl import ANY_STAFF, DocumentACL
from enterprise_rag.security.identity import Classification, Department, Role, User


def _user(dept: str, roles: list[str], clearance: int, *, active: bool = True) -> User:
    return User(
        username=f"u.{dept}.{clearance}",
        display_name="Test User",
        department=Department(dept),
        roles=frozenset(Role(r) for r in roles),
        clearance=clearance,
        active=active,
    )


def _acl(**kwargs) -> DocumentACL:
    defaults = dict(
        doc_id="doc-1",
        title="Doc",
        department="hr",
        classification=Classification.RESTRICTED,
        allowed_roles=frozenset({"hr_business_partner"}),
        allowed_departments=frozenset({"hr"}),
    )
    defaults.update(kwargs)
    return DocumentACL(**defaults)  # type: ignore[arg-type]


def test_public_document_is_readable_by_everyone(authorizer):
    acl = _acl(classification=Classification.PUBLIC, allowed_roles=frozenset({ANY_STAFF}))
    intern = _user("engineering", ["employee"], 1)
    assert authorizer.authorize(intern, acl).allowed
    assert authorizer.authorize(intern, acl).rule == "ACL-01"


def test_clearance_below_requirement_is_denied_by_rule_acl_02(authorizer):
    # Role IS granted, but clearance 2 < confidential requirement (3).
    acl = _acl(
        classification=Classification.CONFIDENTIAL,
        allowed_roles=frozenset({"manager"}),
        allowed_departments=frozenset({"engineering"}),
    )
    engineer = _user("engineering", ["manager"], 2)
    decision = authorizer.authorize(engineer, acl)
    assert not decision.allowed
    assert decision.rule == "ACL-02"
    assert decision.required_clearance == 3


def test_missing_grant_is_denied_by_rule_acl_05(authorizer):
    acl = _acl()
    finance = _user("finance", ["finance_analyst"], 4)
    decision = authorizer.authorize(finance, acl)
    assert not decision.allowed
    assert decision.rule == "ACL-05"


def test_role_grant_wins_when_clearance_is_sufficient(authorizer):
    acl = _acl()
    hr = _user("hr", ["hr_business_partner"], 4)
    decision = authorizer.authorize(hr, acl)
    assert decision.allowed
    assert decision.rule in {"ACL-03", "ACL-04"}


def test_department_grant_without_matching_role(authorizer):
    acl = _acl(
        allowed_roles=frozenset(),
        allowed_departments=frozenset({"hr"}),
        classification=Classification.RESTRICTED,
    )
    hr_member = _user("hr", ["employee"], 4)
    assert authorizer.authorize(hr_member, acl).allowed


def test_all_staff_grant(authorizer):
    acl = _acl(classification=Classification.INTERNAL, allowed_roles=frozenset({ANY_STAFF}))
    employee = _user("sales", ["employee"], 2)
    assert authorizer.authorize(employee, acl).allowed


def test_all_staff_grant_still_needs_clearance(authorizer):
    """A grant alone is not enough: clearance 1 cannot read internal documents."""
    acl = _acl(classification=Classification.INTERNAL, allowed_roles=frozenset({ANY_STAFF}))
    intern = _user("sales", ["employee"], 1)
    decision = authorizer.authorize(intern, acl)
    assert not decision.allowed
    assert decision.rule == "ACL-02"


def test_disabled_account_is_always_denied(authorizer):
    acl = _acl(classification=Classification.PUBLIC, allowed_roles=frozenset({ANY_STAFF}))
    suspended = _user("hr", ["hr_business_partner"], 4, active=False)
    decision = authorizer.authorize(suspended, acl)
    assert not decision.allowed
    assert decision.rule == "ACL-00"


def test_platform_admin_is_not_a_content_grant(authorizer):
    """Segregation of duties: operating the service is not reading the data."""
    acl = _acl()
    admin = _user("security", ["platform_admin"], 4)
    assert not authorizer.authorize(admin, acl).allowed


def test_chroma_where_only_returns_permitted_classifications(authorizer):
    clearance_2 = _user("engineering", ["employee"], 2)
    where = authorizer.chroma_where(clearance_2)
    inner = where["$and"][0]["classification"]
    values = set(inner["$in"]) if "$in" in inner else {inner["$eq"]}
    assert values == {"public", "internal"}


def test_metadata_roundtrip_preserves_acl():
    original = _acl(canary="CANARY-XYZ", contains_pii=True, pii_types=("PII-001",))
    metadata = original.to_metadata()
    rebuilt = DocumentACL.from_metadata(metadata)
    assert rebuilt.classification is original.classification
    assert rebuilt.allowed_roles == original.allowed_roles
    assert rebuilt.allowed_departments == original.allowed_departments
    assert rebuilt.canary == original.canary
    assert rebuilt.contains_pii is True


def test_filter_metadata_splits_allowed_and_denied(authorizer):
    hr = _user("hr", ["hr_business_partner"], 4)
    allowed_meta = _acl(doc_id="ok").to_metadata()
    denied_meta = _acl(
        doc_id="nope", allowed_roles=frozenset(), allowed_departments=frozenset()
    ).to_metadata()
    allowed, denied = authorizer.filter_metadata(hr, [allowed_meta, denied_meta])
    assert [m["doc_id"] for m in allowed] == ["ok"]
    assert [m["doc_id"] for m, _ in denied] == ["nope"]


@pytest.mark.parametrize(
    ("clearance", "expected"),
    [
        (1, ["public"]),
        (2, ["public", "internal"]),
        (4, ["public", "internal", "confidential", "restricted"]),
    ],
)
def test_classification_visibility_by_clearance(clearance, expected):
    from enterprise_rag.security.identity import Classification as C

    assert C.levels_visible_to(clearance) == expected
