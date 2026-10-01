"""Sensitivity classification: manifest authority, path policy, PII escalation."""

from __future__ import annotations

import pytest

from enterprise_rag.ingestion.classifier import SensitivityClassifier
from enterprise_rag.security.identity import Classification


@pytest.fixture(scope="module")
def classifier(settings) -> SensitivityClassifier:
    return SensitivityClassifier.from_file(settings)


def _classify(classifier, settings, relative: str):
    document = _fake_document(relative, settings)
    return classifier.classify(document, relative)


def _fake_document(relative: str, settings, text: str = "Ordinary policy text."):
    from enterprise_rag.ingestion.loaders import LoadedDocument, LoadedUnit

    name = relative.rsplit("/", 1)[-1]
    return LoadedDocument(
        doc_id=relative.replace("/", "-").replace(".", "-"),
        title=name.replace("_", " ").title(),
        source_path=str(settings.corpus_path / relative),
        doc_format=relative.rsplit(".", 1)[-1],
        units=(LoadedUnit(ref="section:1", text=text, metadata={"unit": "section"}),),
    )


def test_public_folder_grants_everyone(classifier, settings):
    outcome = _classify(classifier, settings, "public/press_release.md")
    assert outcome.acl.classification is Classification.PUBLIC
    assert outcome.source == "path-policy"
    assert outcome.acl.grants_any_staff


def test_hr_folder_defaults_to_restricted(classifier, settings):
    outcome = _classify(classifier, settings, "hr/anything.md")
    assert outcome.acl.classification is Classification.RESTRICTED
    assert "hr_business_partner" in outcome.acl.allowed_roles


def test_unknown_path_is_not_public(classifier, settings):
    outcome = _classify(classifier, settings, "misc/unlabelled.md")
    assert outcome.acl.classification is Classification.INTERNAL
    assert not outcome.acl.grants_any_staff


def test_manifest_overrides_path_policy(classifier, settings):
    outcome = _classify(classifier, settings, "hr/salary_bands_fy2026.csv")
    assert outcome.source == "manifest"
    assert outcome.acl.classification is Classification.RESTRICTED
    assert "executive" in outcome.acl.allowed_roles


def test_manifest_glob_entries_are_honoured(classifier, settings):
    outcome = _classify(classifier, settings, "finance/some_other.csv")
    assert outcome.source == "manifest"
    assert outcome.acl.classification is Classification.CONFIDENTIAL


def test_content_inspection_escalates_misplaced_pii(classifier, settings):
    text = (
        "Employee E1002 payroll_ref PR-88213 bank PK36SCBL0000001123456702 "
        "mobile +1-202-555-0117 annual_salary_usd 112000"
    )
    outcome = classifier.classify(
        _fake_document("public/legacy_headcount_export.csv", settings, text),
        "public/legacy_headcount_export.csv",
    )
    assert outcome.escalated
    assert outcome.acl.classification is Classification.RESTRICTED
    assert "PII-005" in outcome.acl.pii_types  # IBAN


def test_public_contact_details_do_not_escalate(classifier, settings):
    outcome = classifier.classify(
        _fake_document(
            "public/contact.md", settings, "Reach us at hello@northwind.test or +1-202-555-0100."
        ),
        "public/contact.md",
    )
    assert not outcome.escalated
    assert outcome.acl.classification is Classification.PUBLIC


def test_unlabelled_file_with_pii_is_restricted_not_public(classifier, settings):
    outcome = classifier.classify(
        _fake_document("misc/salaries.csv", settings, "account 12345678 payroll PR-1"),
        "misc/salaries.csv",
    )
    assert outcome.acl.classification is not Classification.PUBLIC


def test_confidential_documents_receive_a_canary(classifier, settings):
    outcome = _classify(classifier, settings, "finance/q3_fy2026_budget.csv")
    assert outcome.acl.canary
    assert outcome.acl.canary.startswith("CANARY-")
    # Stable across runs: derived from doc id + secret key.
    again = _classify(classifier, settings, "finance/q3_fy2026_budget.csv")
    assert again.acl.canary == outcome.acl.canary


def test_public_documents_have_no_canary(classifier, settings):
    assert _classify(classifier, settings, "public/handbook.md").acl.canary is None


def test_classification_output_is_explainable(classifier, settings):
    payload = _classify(classifier, settings, "hr/salary_bands_fy2026.csv").as_dict()
    assert payload["classification"] == "restricted"
    assert payload["reason"]
    assert payload["source"] == "manifest"
    assert payload["allowed_roles"]
