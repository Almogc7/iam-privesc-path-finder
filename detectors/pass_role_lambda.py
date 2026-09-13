"""Detects: iam:PassRole (covering an admin-equivalent role) + Lambda create/invoke.

AWS mechanic: a Lambda function executes with whatever execution role is
attached to it at creation time - the *caller's* own permissions don't
matter once the function runs, only the role it was given. `iam:PassRole`
is the permission that lets a caller hand a role to a service (here,
Lambda) without needing any permissions of that role themselves. So a
principal that can (a) PassRole an admin-equivalent role, (b) create a
Lambda function with that role attached, and (c) invoke the function it
just created, can run arbitrary admin-privileged code - full escalation,
even though the caller never held admin permissions directly.
"""

from __future__ import annotations

from typing import List

from models import Finding, Principal

CREATE_ACTIONS = ["lambda:CreateFunction"]
INVOKE_ACTIONS = ["lambda:InvokeFunction"]


def detect(principals: List[Principal]) -> List[Finding]:
    findings: List[Finding] = []

    admin_roles = [p for p in principals if p.type == "role" and p.has_admin_policy()]
    if not admin_roles:
        return findings

    for principal in principals:
        if principal.has_admin_policy():
            continue  # already admin; passing another admin role isn't an escalation

        passrole_stmts = principal.actions_matching("iam:PassRole")
        if not passrole_stmts:
            continue

        can_create = any(principal.can_do(a) for a in CREATE_ACTIONS)
        can_invoke = any(principal.can_do(a) for a in INVOKE_ACTIONS)
        if not (can_create and can_invoke):
            continue

        for role in admin_roles:
            if role.arn == principal.arn:
                continue
            if not any(s.covers_resource(role.arn) for s in passrole_stmts):
                continue

            findings.append(
                Finding(
                    principal_name=principal.name,
                    principal_arn=principal.arn,
                    technique="PassRole+Lambda",
                    severity="CRITICAL",
                    permissions_involved=[
                        "iam:PassRole",
                        "lambda:CreateFunction",
                        "lambda:InvokeFunction",
                    ],
                    explanation=(
                        f"{principal.name} can pass the admin-equivalent role "
                        f"{role.name} to a new Lambda function it creates, then "
                        "invoke that function. The function executes with "
                        f"{role.name}'s permissions, not {principal.name}'s - "
                        "giving it admin-equivalent code execution without ever "
                        "holding admin permissions directly."
                    ),
                )
            )

    return findings
