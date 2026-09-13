"""Detects: sts:AssumeRole chains leading to an admin-equivalent role.

AWS mechanic: privilege isn't just what a principal directly holds - it's
the transitive closure of every role it can assume, and every role *that*
role can assume, and so on. A principal only needs two things to hop onto a
role: (1) its own policy must Allow sts:AssumeRole with a resource scope
covering that role's ARN, AND (2) the target role's *trust policy* must
separately name (or wildcard) that caller as a trusted Principal - both
sides have to agree, which is exactly what a real AssumeRole call checks.
This detector builds that directed graph and runs a breadth-first search
from every non-admin principal, so it reports the shortest hop-chain to an
admin-equivalent role - the classic "A can assume B can assume Admin" path.

No third-party graph library is used: at the scale of a single account's
IAM principals (dozens to low hundreds of nodes), plain BFS over an
adjacency dict is simpler to read and just as fast. A library like
networkx would earn its keep at org-wide, cross-account scale, or if this
grew centrality/visualization features - noted as future work.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, List

from models import Finding, Principal


def _build_adjacency(principals: List[Principal]) -> Dict[str, List[str]]:
    """arn -> list of role ARNs that principal can actually assume.

    Only counts an edge when BOTH sides agree: the caller's own policy
    allows sts:AssumeRole against that resource, AND the target role's
    trust policy allows that specific caller (or a wildcard).
    """
    adjacency: Dict[str, List[str]] = {}

    for caller in principals:
        assume_stmts = caller.actions_matching("sts:AssumeRole")
        if not assume_stmts:
            continue

        targets = []
        for role in principals:
            if role.type != "role" or role.arn == caller.arn:
                continue
            if not any(s.covers_resource(role.arn) for s in assume_stmts):
                continue
            if not any(
                t.allows_action("sts:AssumeRole") and t.covers_principal(caller.arn)
                for t in role.trust_statements
            ):
                continue
            targets.append(role.arn)

        if targets:
            adjacency[caller.arn] = targets

    return adjacency


def detect(principals: List[Principal]) -> List[Finding]:
    findings: List[Finding] = []
    by_arn = {p.arn: p for p in principals}
    adjacency = _build_adjacency(principals)

    for start in principals:
        if start.has_admin_policy():
            continue  # already admin directly; not an escalation path

        visited = {start.arn}
        queue = deque([[start.arn]])
        found_path = None

        while queue and found_path is None:
            path = queue.popleft()
            current_arn = path[-1]
            for next_arn in adjacency.get(current_arn, []):
                if next_arn in visited:
                    continue
                visited.add(next_arn)
                new_path = path + [next_arn]
                if by_arn[next_arn].has_admin_policy():
                    found_path = new_path
                    break
                queue.append(new_path)

        if found_path is None:
            continue

        chain_names = [by_arn[arn].name for arn in found_path]
        hops = len(found_path) - 1
        findings.append(
            Finding(
                principal_name=start.name,
                principal_arn=start.arn,
                technique="AssumeRole-Chain",
                severity="HIGH",
                permissions_involved=["sts:AssumeRole"],
                explanation=(
                    f"{start.name} can reach the admin-equivalent role "
                    f"{chain_names[-1]} via {hops} AssumeRole hop"
                    f"{'s' if hops != 1 else ''}: {' -> '.join(chain_names)}. "
                    "Each hop is mutually agreed (caller's AssumeRole grant + "
                    "target role's trust policy), so this is a real, "
                    "exploitable path, not just a theoretical permission."
                ),
                chain=chain_names,
            )
        )

    return findings
