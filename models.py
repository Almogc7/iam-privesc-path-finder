"""Data structures shared by the parser, detectors, and report renderer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Statement:
    """One policy statement, normalized to always-a-list fields.

    AWS lets `action`/`resource`/`principal` be either a single string or a
    list; normalizing here means every detector can just iterate a list
    without re-checking the type.
    """

    effect: str  # "Allow" or "Deny"
    actions: List[str]
    resources: List[str]
    source: str  # e.g. "attached:SelfServicePolicy" or "inline:ops-inline" or "trust"
    principals: Optional[List[str]] = None  # only set on trust-policy statements

    def allows_action(self, action_pattern: str) -> bool:
        """True if this Allow statement covers an action matching the pattern.

        Uses fnmatch-style wildcards because IAM actions are matched the same
        way AWS itself matches them (e.g. "iam:*" covers "iam:AttachUserPolicy").
        """
        import fnmatch

        if self.effect != "Allow":
            return False
        return any(
            fnmatch.fnmatch(action_pattern.lower(), a.lower()) for a in self.actions
        )

    def covers_resource(self, resource_pattern: str) -> bool:
        """True if this statement's resource scope matches the given pattern.

        Used to check things like "does this policy's resource scope cover
        the principal's own ARN" (self-targeting) or "*" (unrestricted).
        """
        import fnmatch

        return any(
            fnmatch.fnmatch(resource_pattern.lower(), r.lower())
            for r in self.resources
        )

    def covers_principal(self, principal_arn: str) -> bool:
        """True if this trust-statement's Principal block covers the given ARN.

        Only meaningful on trust-policy statements (where `principals` is
        set). Used to check "does this role's trust policy actually let
        that specific caller assume it" — a wide AssumeRole grant on the
        caller's side isn't enough on its own; AWS also requires the
        target role's trust policy to name (or wildcard) the caller.
        """
        import fnmatch

        if not self.principals:
            return False
        return any(
            fnmatch.fnmatch(principal_arn.lower(), p.lower()) for p in self.principals
        )


@dataclass
class Principal:
    """An IAM user or role, with its permissions and (for roles) trust policy."""

    name: str
    type: str  # "user" or "role"
    arn: str
    statements: List[Statement] = field(default_factory=list)  # attached + inline
    trust_statements: List[Statement] = field(default_factory=list)  # roles only
    attached_managed_policy_arns: List[str] = field(default_factory=list)

    def actions_matching(self, pattern: str) -> List[Statement]:
        """Statements that Allow an action matching `pattern` (e.g. 'iam:*Policy')."""
        return [s for s in self.statements if s.allows_action(pattern)]

    def can_do(self, action: str, resource: str = "*") -> bool:
        """Whether this principal has an Allow statement covering action+resource.

        Note: this is intentionally simple allow-matching, not a full IAM
        policy evaluation engine — no explicit-deny precedence, no condition
        keys. See README "out of scope" for why that's an acceptable v1 cut.
        """
        return any(
            s.allows_action(action) and s.covers_resource(resource)
            for s in self.statements
        )

    def has_admin_policy(self) -> bool:
        """True if this principal already has Action:* / Resource:* (e.g. AdministratorAccess).

        Used both to flag already-admin principals and as the "target" check
        for detectors like AssumeRole-chain (is the role at the end of the
        chain admin-equivalent?).
        """
        return any(
            s.allows_action("*") and s.covers_resource("*") for s in self.statements
        )


@dataclass
class Finding:
    """One detected privilege-escalation path, ready for report rendering."""

    principal_name: str
    principal_arn: str
    technique: str
    severity: str  # "CRITICAL" or "HIGH"
    permissions_involved: List[str]
    explanation: str
    chain: Optional[List[str]] = None  # populated for multi-hop findings (AssumeRole)
