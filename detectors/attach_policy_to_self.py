"""Detects: iam:AttachUserPolicy / iam:AttachRolePolicy scoped to self.

AWS mechanic: attaching a managed policy is a separate permission from
*having* permissions. If a principal can call AttachUserPolicy /
AttachRolePolicy against its own ARN (or the resource scope is unrestricted),
it can attach AWS's own `AdministratorAccess` managed policy to itself —
no other permission is required. This is one of the most direct
priv-esc primitives because it needs no crafted policy JSON, just the
attach call pointed at a well-known managed policy ARN.
"""

from __future__ import annotations

from typing import List

from models import Finding, Principal

ATTACH_ACTIONS = ["iam:AttachUserPolicy", "iam:AttachRolePolicy"]


def detect(principals: List[Principal]) -> List[Finding]:
    findings: List[Finding] = []

    for principal in principals:
        if principal.has_admin_policy():
            continue  # already admin; self-attaching more admin isn't an escalation

        for action in ATTACH_ACTIONS:
            matches = [
                s
                for s in principal.actions_matching(action)
                if s.covers_resource(principal.arn) or s.covers_resource("*")
            ]
            if not matches:
                continue

            findings.append(
                Finding(
                    principal_name=principal.name,
                    principal_arn=principal.arn,
                    technique="AttachPolicy-ToSelf",
                    severity="CRITICAL",
                    permissions_involved=[action],
                    explanation=(
                        f"{principal.name} can call {action} against its own "
                        f"identity (resource scope covers {principal.arn} or *). "
                        "It can attach the AWS-managed 'AdministratorAccess' "
                        "policy to itself directly, with no other permissions "
                        "required."
                    ),
                )
            )
            break  # one finding per principal for this technique is enough

    return findings
