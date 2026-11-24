"""Tests for each detector's AWS mechanic, plus the two required negative
controls against the bundled demo dataset.

Principals are built directly from `Statement`/`Principal` dataclasses so
each test isolates exactly the permission shape it's checking, independent
of JSON parsing (which `parser.py` already documents and `test_demo_file_*`
exercises end-to-end).
"""

from __future__ import annotations

from pathlib import Path

from detectors import (
    assume_role_chain,
    attach_policy_to_self,
    create_policy_version,
    pass_role_lambda,
    put_inline_policy,
)
from models import Principal, Statement
from parser import load_principals

SAMPLE_FILE = Path(__file__).resolve().parent.parent / "samples" / "demo_principals.json"

USER_ARN = "arn:aws:iam::111111111111:user/test-user"
OTHER_ARN = "arn:aws:iam::111111111111:user/other-user"
ADMIN_ROLE_ARN = "arn:aws:iam::111111111111:role/admin-role"
OTHER_POLICY_ARN = "arn:aws:iam::111111111111:policy/NotMine"
OWN_POLICY_ARN = "arn:aws:iam::111111111111:policy/MyPolicy"


def admin_role(arn: str = ADMIN_ROLE_ARN, name: str = "admin-role") -> Principal:
    return Principal(
        name=name,
        type="role",
        arn=arn,
        statements=[
            Statement(effect="Allow", actions=["*"], resources=["*"], source="attached:Admin")
        ],
    )


# --- AttachPolicy-ToSelf ------------------------------------------------


def test_attach_policy_to_self_detects_self_scoped_attach():
    principal = Principal(
        name="test-user",
        type="user",
        arn=USER_ARN,
        statements=[
            Statement(
                effect="Allow",
                actions=["iam:AttachUserPolicy"],
                resources=[USER_ARN],
                source="attached:SelfService",
            )
        ],
    )

    findings = attach_policy_to_self.detect([principal])

    assert len(findings) == 1
    assert findings[0].technique == "AttachPolicy-ToSelf"
    assert findings[0].severity == "CRITICAL"


def test_attach_policy_to_self_ignores_unrelated_action():
    principal = Principal(
        name="readonly",
        type="user",
        arn=USER_ARN,
        statements=[
            Statement(
                effect="Allow",
                actions=["s3:GetObject"],
                resources=["*"],
                source="attached:ReadOnly",
            )
        ],
    )

    assert attach_policy_to_self.detect([principal]) == []


# --- PutInlinePolicy-Self ------------------------------------------------


def test_put_inline_policy_detects_self_scoped_put():
    principal = Principal(
        name="ci-deploy",
        type="role",
        arn=USER_ARN,
        statements=[
            Statement(
                effect="Allow",
                actions=["iam:PutRolePolicy"],
                resources=[USER_ARN],
                source="attached:Deploy",
            )
        ],
    )

    findings = put_inline_policy.detect([principal])

    assert len(findings) == 1
    assert findings[0].technique == "PutInlinePolicy-Self"


# --- PassRole+Lambda ------------------------------------------------


def test_pass_role_lambda_requires_all_three_permissions():
    # Has PassRole on an admin role, but no lambda:CreateFunction - the AND
    # across all three permissions must hold, not PassRole alone.
    principal = Principal(
        name="svc-partial",
        type="user",
        arn=USER_ARN,
        statements=[
            Statement(
                effect="Allow",
                actions=["iam:PassRole"],
                resources=[ADMIN_ROLE_ARN],
                source="attached:Partial",
            ),
            Statement(
                effect="Allow",
                actions=["lambda:InvokeFunction"],
                resources=["*"],
                source="attached:Partial",
            ),
        ],
    )

    findings = pass_role_lambda.detect([principal, admin_role()])

    assert findings == []


def test_pass_role_lambda_detects_full_chain():
    principal = Principal(
        name="svc-data-pipeline",
        type="user",
        arn=USER_ARN,
        statements=[
            Statement(
                effect="Allow",
                actions=["iam:PassRole"],
                resources=[ADMIN_ROLE_ARN],
                source="attached:Deploy",
            ),
            Statement(
                effect="Allow",
                actions=["lambda:CreateFunction"],
                resources=["*"],
                source="attached:Deploy",
            ),
            Statement(
                effect="Allow",
                actions=["lambda:InvokeFunction"],
                resources=["*"],
                source="attached:Deploy",
            ),
        ],
    )

    findings = pass_role_lambda.detect([principal, admin_role()])

    assert len(findings) == 1
    assert findings[0].technique == "PassRole+Lambda"


# --- CreatePolicyVersion-SetDefault ------------------------------------------------


def test_create_policy_version_requires_self_or_unrestricted():
    principal = Principal(
        name="app-admin-bot",
        type="user",
        arn=USER_ARN,
        statements=[
            Statement(
                effect="Allow",
                actions=["iam:CreatePolicyVersion"],
                resources=[OTHER_POLICY_ARN],
                source="attached:Editable",
            )
        ],
        attached_managed_policy_arns=[OWN_POLICY_ARN],
    )

    assert create_policy_version.detect([principal]) == []


def test_create_policy_version_detects_self_attached_policy():
    principal = Principal(
        name="app-admin-bot",
        type="user",
        arn=USER_ARN,
        statements=[
            Statement(
                effect="Allow",
                actions=["iam:CreatePolicyVersion"],
                resources=[OWN_POLICY_ARN],
                source="attached:Editable",
            )
        ],
        attached_managed_policy_arns=[OWN_POLICY_ARN],
    )

    findings = create_policy_version.detect([principal])

    assert len(findings) == 1
    assert findings[0].technique == "CreatePolicyVersion-SetDefault"


# --- AssumeRole-Chain ------------------------------------------------


def test_assume_role_chain_requires_mutual_trust():
    # Broad AssumeRole grant on the caller's side, but the target role's
    # trust policy does not name the caller back - this is exactly the
    # security-auditor mechanic and must NOT produce a finding.
    caller = Principal(
        name="broad-caller",
        type="user",
        arn=USER_ARN,
        statements=[
            Statement(
                effect="Allow",
                actions=["sts:AssumeRole"],
                resources=["*"],
                source="attached:Broad",
            )
        ],
    )
    target = admin_role()  # trust_statements left empty - no one is trusted

    assert assume_role_chain.detect([caller, target]) == []


def test_assume_role_chain_detects_multi_hop_path():
    mid_role_arn = "arn:aws:iam::111111111111:role/mid-role"

    start = Principal(
        name="start-user",
        type="user",
        arn=USER_ARN,
        statements=[
            Statement(
                effect="Allow",
                actions=["sts:AssumeRole"],
                resources=[mid_role_arn],
                source="attached:Ops",
            )
        ],
    )
    mid = Principal(
        name="mid-role",
        type="role",
        arn=mid_role_arn,
        statements=[
            Statement(
                effect="Allow",
                actions=["sts:AssumeRole"],
                resources=[ADMIN_ROLE_ARN],
                source="attached:Escalation",
            )
        ],
        trust_statements=[
            Statement(
                effect="Allow",
                actions=["sts:AssumeRole"],
                resources=["*"],
                source="trust",
                principals=[USER_ARN],
            )
        ],
    )
    target = admin_role()
    target.trust_statements = [
        Statement(
            effect="Allow",
            actions=["sts:AssumeRole"],
            resources=["*"],
            source="trust",
            principals=[mid_role_arn],
        )
    ]

    findings = assume_role_chain.detect([start, mid, target])

    # Two findings: the 2-hop path from start-user, AND mid-role's own
    # 1-hop path (mid-role is itself a non-admin principal with a direct
    # mutually-trusted edge to admin-role) - same shape as the real sample's
    # intern-analyst / ops-deploy-role pair.
    assert len(findings) == 2
    by_principal = {f.principal_name: f for f in findings}
    assert by_principal["start-user"].chain == ["start-user", "mid-role", "admin-role"]
    assert by_principal["mid-role"].chain == ["mid-role", "admin-role"]


# --- Cross-cutting: already-admin filter ------------------------------------------------


def test_already_admin_is_filtered_from_all_detectors():
    # A principal that is already admin trivially matches every other
    # technique's pattern too (of course an admin can attach a policy to
    # itself) - every detector must skip it as noise, not an escalation.
    principal = Principal(
        name="already-admin",
        type="user",
        arn=USER_ARN,
        statements=[
            Statement(effect="Allow", actions=["*"], resources=["*"], source="attached:Admin"),
            Statement(
                effect="Allow",
                actions=["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreatePolicyVersion"],
                resources=[USER_ARN],
                source="attached:Admin",
            ),
        ],
        attached_managed_policy_arns=[OWN_POLICY_ARN],
    )

    assert attach_policy_to_self.detect([principal]) == []
    assert put_inline_policy.detect([principal]) == []
    assert create_policy_version.detect([principal]) == []
    assert pass_role_lambda.detect([principal]) == []
    assert assume_role_chain.detect([principal]) == []


# --- Negative controls against the bundled demo dataset ------------------------------------------------


def _findings_by_principal(name: str):
    principals = load_principals(str(SAMPLE_FILE))
    all_findings = []
    for detector in (
        attach_policy_to_self,
        put_inline_policy,
        pass_role_lambda,
        create_policy_version,
        assume_role_chain,
    ):
        all_findings.extend(detector.detect(principals))
    return [f for f in all_findings if f.principal_name == name]


def test_readonly_bob_negative_control():
    assert _findings_by_principal("readonly-bob") == []


def test_security_auditor_negative_control():
    assert _findings_by_principal("security-auditor") == []


def test_demo_file_produces_exactly_six_findings():
    principals = load_principals(str(SAMPLE_FILE))
    all_findings = []
    for detector in (
        attach_policy_to_self,
        put_inline_policy,
        pass_role_lambda,
        create_policy_version,
        assume_role_chain,
    ):
        all_findings.extend(detector.detect(principals))

    assert len(all_findings) == 6
    assert {(f.principal_name, f.technique) for f in all_findings} == {
        ("dev-alice", "AttachPolicy-ToSelf"),
        ("ci-deploy", "PutInlinePolicy-Self"),
        ("svc-data-pipeline", "PassRole+Lambda"),
        ("app-admin-bot", "CreatePolicyVersion-SetDefault"),
        ("intern-analyst", "AssumeRole-Chain"),
        ("ops-deploy-role", "AssumeRole-Chain"),
    }
