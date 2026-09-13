"""Registry of all detection rules.

Each detector module exposes a `detect(principals) -> List[Finding]`
function. Adding a technique means adding one module here and one line
below — no shared detector risks getting tangled with another's logic.
"""

from . import (
    assume_role_chain,
    attach_policy_to_self,
    create_policy_version,
    pass_role_lambda,
    put_inline_policy,
)

DETECTORS = [
    attach_policy_to_self,
    put_inline_policy,
    pass_role_lambda,
    create_policy_version,
    assume_role_chain,
]
