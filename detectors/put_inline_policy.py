"""Detects: iam:PutUserPolicy / iam:PutRolePolicy scoped to self.

AWS mechanic: PutUserPolicy/PutRolePolicy writes (or overwrites) an inline
policy directly on a user or role. Unlike attaching a managed policy, this
needs no pre-existing policy to point at and isn't versioned — one API call
grants whatever statement the attacker writes, e.g.
`{"Effect": "Allow", "Action": "*", "Resource": "*"}`. If the principal can
call this against its own ARN (or the resource scope is unrestricted), it
can self-grant admin in a single step.
"""

from __future__ import annotations

from typing import List

from models import Finding, Principal

PUT_POLICY_ACTIONS = ["iam:PutUserPolicy", "iam:PutRolePolicy"]


def detect(principals: List[Principal]) -> List[Finding]:
    findings: List[Finding] = []

    for principal in principals:
        if principal.has_admin_policy():
            continue  # already admin; self-granting more admin isn't an escalation

        for action in PUT_POLICY_ACTIONS:
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
                    technique="PutInlinePolicy-Self",
                    severity="CRITICAL",
                    permissions_involved=[action],
                    explanation=(
                        f"{principal.name} can call {action} against its own "
                        f"identity (resource scope covers {principal.arn} or *). "
                        "It can write an inline policy granting itself "
                        "'Action: *, Resource: *' directly - no attach step "
                        "and no policy versioning to work around."
                    ),
                )
            )
            break

    return findings
