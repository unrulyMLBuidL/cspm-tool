# escalation.py
# ============================================================
# Privilege escalation path detection.
# Checks attached IAM policies for permission combinations that
# allow a principal to escalate their own privileges.
#
# Limitation: checks within a single policy document only.
# Cross-policy escalation (permissions spread across multiple
# policies on the same user/role) requires per-entity permission
# aggregation and is not implemented here.
# ============================================================

from dataclasses import dataclass
from typing import Any
from modules.analyzer import Severity, Finding

# ── Escalation path definitions ──────────────────────────────
# Each path is a dict with:
#   id          → rule identifier
#   name        → short human label
#   required    → list of permission sets; ALL sets must be satisfied
#                 each set is a list of actions where ANY one is sufficient
#                 e.g. [["iam:PassRole"], ["lambda:CreateFunction", "lambda:InvokeFunction"]]
#                 means: needs iam:PassRole AND (lambda:CreateFunction OR lambda:InvokeFunction)
#   description → what the attacker can do
#   severity    → Severity enum value

ESCALATION_PATHS = [
    {
        'id':       'ESC-001',
        'name':     'Policy version manipulation',
        'required': [['iam:CreatePolicyVersion']],
        'description': (
            "Allows rewriting any existing IAM policy to grant full admin access. "
            "An attacker can update a policy they have access to, inserting "
            "Action='*' Resource='*', then assume any role or act as any user."
        ),
        'severity': Severity.CRITICAL,
    },
    {
        'id':       'ESC-002',
        'name':     'Direct policy attachment',
        'required': [['iam:AttachUserPolicy', 'iam:AttachRolePolicy', 'iam:AttachGroupPolicy']],
        'description': (
            "Allows attaching any managed policy (including AdministratorAccess) "
            "to any user, role, or group. An attacker can attach AdministratorAccess "
            "to their own user or a role they control."
        ),
        'severity': Severity.CRITICAL,
    },
    {
        'id':       'ESC-003',
        'name':     'Lambda execution with PassRole',
        'required': [
            ['iam:PassRole'],
            ['lambda:CreateFunction', 'lambda:UpdateFunctionCode'],
            ['lambda:InvokeFunction'],
        ],
        'description': (
            "Allows creating or updating a Lambda function with a powerful execution role "
            "(via iam:PassRole), then invoking it. The Lambda runs as that role, "
            "so the attacker can execute arbitrary AWS API calls with the role's permissions."
        ),
        'severity': Severity.HIGH,
    },
    {
        'id':       'ESC-004',
        'name':     'EC2 instance with PassRole',
        'required': [
            ['iam:PassRole'],
            ['ec2:RunInstances'],
        ],
        'description': (
            "Allows launching an EC2 instance with a powerful IAM instance profile "
            "(via iam:PassRole). If the attacker can access the instance (via SSH or "
            "SSM), they inherit the instance profile's permissions."
        ),
        'severity': Severity.HIGH,
    },
    {
        'id':       'ESC-005',
        'name':     'Access key creation for other users',
        'required': [['iam:CreateAccessKey']],
        'description': (
            "Allows creating access keys for any IAM user, including admins. "
            "An attacker can generate credentials for a high-privilege user "
            "and use them to act as that user."
        ),
        'severity': Severity.HIGH,
    },
    {
        'id':       'ESC-006',
        'name':     'Console login profile creation',
        'required': [['iam:CreateLoginProfile', 'iam:UpdateLoginProfile']],
        'description': (
            "Allows setting or changing the console password for any IAM user. "
            "An attacker can create a console password for a high-privilege user "
            "that currently has no console access, then log in as that user."
        ),
        'severity': Severity.HIGH,
    },
]


# ── Helper ───────────────────────────────────────────────────

def _extract_allowed_actions(policy_document: dict) -> set:
    """
    Return a flat set of all actions allowed by this policy document.

    Handles:
    - Statement as a list or a single dict
    - Action as a string or a list
    - Skips Deny statements (they restrict, not grant)
    - Lowercases everything for case-insensitive matching
      (AWS IAM is case-insensitive for action names)
    """
    allowed = set()
    statements = policy_document.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get('Effect') != 'Allow':
            continue
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            allowed.add(action.lower())

    return allowed


def _policy_satisfies_path(allowed_actions: set, required: list) -> bool:
    """
    Check whether a set of allowed actions satisfies all requirements
    for an escalation path.

    `required` is a list of groups. ALL groups must be satisfied.
    A group is satisfied if ANY action in the group is present.

    Example:
      required = [["iam:PassRole"], ["lambda:CreateFunction", "lambda:InvokeFunction"]]
      → True if: "iam:passrole" in allowed
                 AND ("lambda:createfunction" in allowed OR "lambda:invokefunction" in allowed)
    """
    for group in required:
        # Lowercase the group entries to match our normalised allowed set
        if not any(action.lower() in allowed_actions for action in group):
            return False
    return True


# ── Main entry point ─────────────────────────────────────────

def check_escalation_paths(inventory: dict) -> list[Finding]:
    """
    Scan all attached IAM policies for privilege escalation paths.

    Args:
        inventory: the dict returned by iam_inventory.collect_inventory()

    Returns:
        list of Finding objects, one per (policy, escalation path) match.
        Sorted by severity descending.
    """
    findings = []
    account_id = inventory.get('account_id', 'unknown')
    policies   = inventory.get('iam_policies', [])

    for policy in policies:
        name       = policy['PolicyName']
        arn        = policy['Arn']
        attached   = policy['AttachedTo']
        document   = policy.get('Document', {})

        allowed_actions = _extract_allowed_actions(document)

        # No Allow actions at all — skip immediately
        if not allowed_actions:
            continue

        for path in ESCALATION_PATHS:
            if not _policy_satisfies_path(allowed_actions, path['required']):
                continue

            # Build the list of matched actions for the evidence field
            matched = []
            for group in path['required']:
                for action in group:
                    if action.lower() in allowed_actions:
                        matched.append(action)
                        break  # one match per group is enough

            findings.append(Finding(
                rule_id=path['id'],
                severity=path['severity'],
                title=f"{path['name']}: {name}",
                description=(
                    f"Policy '{name}' (attached to {attached} entity(s)) enables "
                    f"privilege escalation via {path['name']}. {path['description']}"
                ),
                remediation=(
                    f"Review policy '{name}' and remove the escalation-enabling "
                    f"permissions: {matched}. Apply least-privilege — grant only "
                    f"the specific resources and conditions these actions require."
                ),
                affected_resource=arn,
                region='global',
                raw_evidence={
                    'policy_name':    name,
                    'attached_to':    attached,
                    'matched_actions': matched,
                    'path_id':        path['id'],
                },
            ))

    findings.sort(key=lambda f: f.severity.value, reverse=True)
    return findings
