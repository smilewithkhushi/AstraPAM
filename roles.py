"""Role/tier definitions, seeded bank users, SoD matrix, and lookup helpers.

Pure data + lookup functions. No I/O. No auth.

Tiers map to Finacle's work-class model:
  T1 Teller → T2 Senior Clerk → T3 Officer → T4 Manager → T5 IT Admin + NHI

Design invariant enforced in data:
  • No single role holds both ISSUE_LOU and APPROVE_LOU.
  • T5 IT_ADMIN holds zero financial entitlements.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from schemas import BankUser, Role, SoDConflict, SoDSeverity

_now = datetime.utcnow


# ── role definitions ───────────────────────────────────────────────────────────

ROLES: dict[str, Role] = {
    "T1_TELLER": Role(
        role_id="T1_TELLER",
        name="Teller",
        work_class="CLERK",
        tier="T1",
        entitlements={"CBS_READ", "CBS_DEBIT", "CBS_CREDIT"},
        input_limit=Decimal("50000"),
        auth_limit=None,
    ),
    "T2_SENIOR_CLERK": Role(
        role_id="T2_SENIOR_CLERK",
        name="Senior Clerk",
        work_class="CLERK",
        tier="T2",
        entitlements={"CBS_READ", "CBS_DEBIT", "CBS_CREDIT", "CBS_TRANSFER", "CREATE_VENDOR"},
        input_limit=Decimal("500000"),
        auth_limit=None,
    ),
    "T3_OFFICER": Role(
        role_id="T3_OFFICER",
        name="Branch Officer",
        work_class="OFFICER",
        tier="T3",
        entitlements={
            "CBS_READ", "CBS_DEBIT", "CBS_CREDIT", "CBS_TRANSFER",
            "APPROVE_LOU", "APPROVE_TRANSFER", "APPROVE_PAYMENT", "APPROVE_ELEVATION",
        },
        input_limit=Decimal("2000000"),
        auth_limit=Decimal("5000000"),
    ),
    "T4_MANAGER": Role(
        role_id="T4_MANAGER",
        name="Branch Manager",
        work_class="MANAGER",
        tier="T4",
        # ISSUE_LOU here; APPROVE_LOU is on T3 — separation is the policy
        entitlements={
            "CBS_READ", "CBS_DEBIT", "CBS_CREDIT", "CBS_TRANSFER",
            "ISSUE_LOU", "APPROVE_TRANSFER", "REQUEST_ELEVATION",
        },
        input_limit=Decimal("10000000"),
        auth_limit=Decimal("20000000"),
    ),
    "T5_IT_ADMIN": Role(
        role_id="T5_IT_ADMIN",
        name="IT Administrator",
        work_class="IT_ADMIN",
        tier="T5",
        # Zero financial entitlements — enforced by design
        entitlements={"MANAGE_USERS", "SYSTEM_CONFIG", "AUDIT_READ", "APPROVE_ELEVATION"},
        input_limit=None,
        auth_limit=None,
    ),
    "NHI_SERVICE": Role(
        role_id="NHI_SERVICE",
        name="Service Account",
        work_class="SERVICE",
        tier="NHI",
        entitlements={"CBS_READ", "AUDIT_READ"},
        input_limit=None,
        auth_limit=None,
    ),
}


# ── seeded users (~8 across all tiers) ────────────────────────────────────────
# user_007 = PNB archetype: T4_MANAGER (carries ISSUE_LOU) + extra APPROVE_LOU
# → toxic pair that SoD detection catches in Phase 7.

BANK_USERS: dict[str, BankUser] = {
    "user_001": BankUser(
        user_id="user_001", name="Priya Sharma", role_id="T1_TELLER",
        branch_sol="SOL001", status="ACTIVE",
        created_at=datetime(2023, 1, 15),
        last_login_at=datetime(2024, 11, 20),
        extra_entitlements=set(),
    ),
    "user_002": BankUser(
        user_id="user_002", name="Rahul Verma", role_id="T1_TELLER",
        branch_sol="SOL002", status="ACTIVE",
        created_at=datetime(2022, 6, 10),
        last_login_at=datetime(2024, 12, 5),
        extra_entitlements=set(),
    ),
    "user_003": BankUser(
        user_id="user_003", name="Anjali Nair", role_id="T2_SENIOR_CLERK",
        branch_sol="SOL001", status="ACTIVE",
        created_at=datetime(2021, 3, 20),
        last_login_at=datetime(2024, 12, 10),
        extra_entitlements=set(),
    ),
    "user_004": BankUser(
        user_id="user_004", name="Suresh Iyer", role_id="T3_OFFICER",
        branch_sol="SOL002", status="ACTIVE",
        created_at=datetime(2020, 8, 5),
        last_login_at=datetime(2024, 12, 12),
        extra_entitlements=set(),
    ),
    "user_005": BankUser(
        user_id="user_005", name="Meera Pillai", role_id="T3_OFFICER",
        branch_sol="SOL003", status="ACTIVE",
        created_at=datetime(2019, 11, 1),
        last_login_at=datetime(2024, 12, 8),
        extra_entitlements=set(),
    ),
    "user_006": BankUser(
        user_id="user_006", name="Vikram Singh", role_id="T4_MANAGER",
        branch_sol="SOL001", status="ACTIVE",
        created_at=datetime(2018, 4, 15),
        last_login_at=datetime(2024, 12, 11),
        extra_entitlements=set(),
    ),
    # PNB archetype: role gives ISSUE_LOU; extra_entitlements adds APPROVE_LOU
    # → one person can both issue and self-approve LoUs (the Nirav Modi enabler)
    "user_007": BankUser(
        user_id="user_007", name="Gokulnath Shetty", role_id="T4_MANAGER",
        branch_sol="SOL003", status="ACTIVE",
        created_at=datetime(2017, 3, 10),
        last_login_at=datetime(2024, 12, 1),
        extra_entitlements={"APPROVE_LOU"},  # privilege creep added over time
    ),
    "user_008": BankUser(
        user_id="user_008", name="svc-batch-proc", role_id="NHI_SERVICE",
        branch_sol="SOL000", status="ACTIVE",
        created_at=datetime(2023, 6, 1),
        last_login_at=None,
        extra_entitlements=set(),
    ),
}


# ── SoD matrix ─────────────────────────────────────────────────────────────────
# Each tuple: (entitlement_a, entitlement_b, rule_id, severity)
# The pair is toxic regardless of order.

SOD_MATRIX: list[tuple[str, str, str, str]] = [
    ("ISSUE_LOU",         "APPROVE_LOU",       "SOD-001", "critical"),  # PNB combination
    ("MANAGE_USERS",      "APPROVE_TRANSFER",  "SOD-002", "critical"),
    ("CREATE_VENDOR",     "APPROVE_PAYMENT",   "SOD-003", "high"),
    ("REQUEST_ELEVATION", "APPROVE_ELEVATION", "SOD-004", "high"),
]


# ── lookup functions ───────────────────────────────────────────────────────────

def get_role(role_id: str) -> Role | None:
    return ROLES.get(role_id)


def get_user(user_id: str) -> BankUser | None:
    return BANK_USERS.get(user_id)


def get_all_users() -> list[BankUser]:
    return list(BANK_USERS.values())


def effective_entitlements(user: BankUser) -> set[str]:
    """Union of role entitlements and any extra entitlements (privilege creep)."""
    role = get_role(user.role_id)
    base = role.entitlements if role else set()
    return base | user.extra_entitlements


def scan_sod_conflicts(user: BankUser) -> list[SoDConflict]:
    """Return all SoD violations for the given user."""
    ents = effective_entitlements(user)
    conflicts: list[SoDConflict] = []
    for ent_a, ent_b, rule_id, severity in SOD_MATRIX:
        if ent_a in ents and ent_b in ents:
            conflicts.append(SoDConflict(
                user_id=user.user_id,
                entitlement_a=ent_a,
                entitlement_b=ent_b,
                rule_id=rule_id,
                severity=severity,  # type: ignore[arg-type]
                detected_at=_now(),
            ))
    return conflicts


def scan_all_conflicts() -> list[SoDConflict]:
    """Scan every seeded user and return all SoD conflicts."""
    result: list[SoDConflict] = []
    for user in BANK_USERS.values():
        result.extend(scan_sod_conflicts(user))
    return result
