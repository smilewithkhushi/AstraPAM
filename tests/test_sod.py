from datetime import datetime

from core import roles
from core.schemas import BankUser


def test_user007_flagged_sod001_critical():
    user = roles.BANK_USERS["user_007"]
    conflicts = roles.scan_sod_conflicts(user)
    assert any(c.rule_id == "SOD-001" and c.severity == "critical" for c in conflicts)


def test_clean_teller_has_no_conflicts():
    assert roles.scan_sod_conflicts(roles.BANK_USERS["user_001"]) == []


def test_effective_entitlements_merges_extra():
    ents = roles.effective_entitlements(roles.BANK_USERS["user_007"])
    assert "ISSUE_LOU" in ents and "APPROVE_LOU" in ents


def test_no_base_role_holds_both_issue_and_approve_lou():
    for role in roles.ROLES.values():
        assert not ({"ISSUE_LOU", "APPROVE_LOU"} <= role.entitlements), (
            f"{role.role_id} violates SoD design invariant"
        )


def test_it_admin_has_no_financial_entitlements():
    financial = {"ISSUE_LOU", "APPROVE_LOU", "CBS_DEBIT", "CBS_CREDIT",
                 "CBS_TRANSFER", "APPROVE_TRANSFER", "APPROVE_PAYMENT"}
    assert roles.ROLES["T5_IT_ADMIN"].entitlements.isdisjoint(financial)


def test_scan_all_conflicts_finds_user007():
    flagged = {c.user_id for c in roles.scan_all_conflicts()}
    assert "user_007" in flagged


def test_scan_all_conflicts_excludes_clean_users():
    flagged = {c.user_id for c in roles.scan_all_conflicts()}
    clean = {"user_001", "user_002", "user_003", "user_004", "user_005", "user_006", "user_008"}
    assert clean.isdisjoint(flagged)


def test_privilege_creep_detected_on_synthetic_user():
    user = BankUser(
        user_id="test_user", name="Test", role_id="T4_MANAGER",
        branch_sol="SOL001", created_at=datetime(2024, 1, 1),
        extra_entitlements={"APPROVE_LOU"},
    )
    conflicts = roles.scan_sod_conflicts(user)
    assert any(c.rule_id == "SOD-001" for c in conflicts)
