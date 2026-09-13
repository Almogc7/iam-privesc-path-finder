"""Loads the combined synthetic IAM dataset (JSON) into Principal objects.

Expected input shape (see samples/demo_principals.json for a full example):

{
  "principals": [
    {
      "name": "dev-alice",
      "type": "user",                       # "user" or "role"
      "arn": "arn:aws:iam::111111111111:user/dev-alice",
      "attached_policies": [
        {
          "policy_name": "SelfServicePolicy",
          "policy_arn": "arn:aws:iam::111111111111:policy/SelfServicePolicy",  # optional; needed for CreatePolicyVersion detection
          "statements": [
            {"effect": "Allow", "action": "iam:AttachUserPolicy", "resource": "*"}
          ]
        }
      ],
      "inline_policies": [
        {
          "policy_name": "extra-inline",
          "statements": [ ... same statement shape ... ]
        }
      ],
      "trust_policy": {                      # only meaningful for type == "role"
        "statements": [
          {
            "effect": "Allow",
            "action": "sts:AssumeRole",
            "principal": "arn:aws:iam::111111111111:user/dev-alice"
          }
        ]
      }
    }
  ]
}

`action`, `resource`, and `principal` may each be a single string or a list —
this loader normalizes both to lists so detectors never have to check.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Union

from models import Principal, Statement


def _as_list(value: Union[str, List[str], None]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _parse_statements(
    raw_statements: List[Dict[str, Any]], source: str, is_trust: bool = False
) -> List[Statement]:
    statements = []
    for raw in raw_statements:
        statements.append(
            Statement(
                effect=raw.get("effect", "Allow"),
                actions=_as_list(raw.get("action")),
                resources=_as_list(raw.get("resource")) or ["*"],
                source=source,
                principals=_as_list(raw.get("principal")) if is_trust else None,
            )
        )
    return statements


def _parse_principal(raw: Dict[str, Any]) -> Principal:
    statements: List[Statement] = []
    attached_managed_policy_arns: List[str] = []

    for policy in raw.get("attached_policies", []):
        statements.extend(
            _parse_statements(
                policy.get("statements", []), source=f"attached:{policy['policy_name']}"
            )
        )
        if "policy_arn" in policy:
            attached_managed_policy_arns.append(policy["policy_arn"])

    for policy in raw.get("inline_policies", []):
        statements.extend(
            _parse_statements(
                policy.get("statements", []), source=f"inline:{policy['policy_name']}"
            )
        )

    trust_statements: List[Statement] = []
    trust_policy = raw.get("trust_policy")
    if trust_policy:
        trust_statements = _parse_statements(
            trust_policy.get("statements", []), source="trust", is_trust=True
        )

    return Principal(
        name=raw["name"],
        type=raw["type"],
        arn=raw["arn"],
        statements=statements,
        trust_statements=trust_statements,
        attached_managed_policy_arns=attached_managed_policy_arns,
    )


def load_principals(input_path: str) -> List[Principal]:
    """Loads one JSON file, or every *.json file in a directory, into Principals.

    Multiple files (if a directory is given) are merged into a single
    principal list — lets a demo dataset be split across files later without
    changing any detector code.
    """
    path = Path(input_path)
    if path.is_dir():
        json_files = sorted(path.glob("*.json"))
    else:
        json_files = [path]

    principals: List[Principal] = []
    for json_file in json_files:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for raw_principal in data.get("principals", []):
            principals.append(_parse_principal(raw_principal))

    return principals
