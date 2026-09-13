"""Detects: iam:CreatePolicyVersion with the ability to set the new version default.

AWS mechanic: a customer-managed policy can have up to 5 versions, and
exactly one is "default" - the one actually enforced. `CreatePolicyVersion`
takes a `SetAsDefault` parameter in the *same* API call, so there is no
separate permission required to make the new version take effect. A
principal that can call CreatePolicyVersion on a policy - especially one
already attached to itself - can overwrite that policy's live permissions
entirely, e.g. to `{"Effect": "Allow", "Action": "*", "Resource": "*"}`,
with a single API call and no need to touch any other policy or role.
"""

from __future__ import annotations

from typing import List

from models import Finding, Principal

ACTION = "iam:CreatePolicyVersion"


def detect(principals: List[Principal]) -> List[Finding]:
    findings: List[Finding] = []

    for principal in principals:
        if principal.has_admin_policy():
            continue  # already admin; rewriting a policy isn't an escalation

        stmts = principal.actions_matching(ACTION)
        if not stmts:
            continue

        self_policy_arns = [
            arn
            for arn in principal.attached_managed_policy_arns
            if any(s.covers_resource(arn) for s in stmts)
        ]
        unrestricted = any(s.covers_resource("*") for s in stmts)

        if not (self_policy_arns or unrestricted):
            continue

        if self_policy_arns:
            target_desc = (
                f"its own attached polic{'y' if len(self_policy_arns) == 1 else 'ies'} "
                f"({', '.join(self_policy_arns)})"
            )
        else:
            target_desc = "any customer-managed policy (unrestricted resource scope)"

        findings.append(
            Finding(
                principal_name=principal.name,
                principal_arn=principal.arn,
                technique="CreatePolicyVersion-SetDefault",
                severity="CRITICAL",
                permissions_involved=[ACTION],
                explanation=(
                    f"{principal.name} can call {ACTION} against {target_desc}. "
                    "CreatePolicyVersion accepts SetAsDefault in the same call, "
                    "so it can overwrite the policy's live permissions with "
                    "'Action: *, Resource: *' in a single step - no separate "
                    "permission is needed to activate the new version."
                ),
            )
        )

    return findings
