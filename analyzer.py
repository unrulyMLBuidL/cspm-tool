# analyzer.py
# ============================================================
# CSPM Analyzer — evaluates security findings from inventory data.
# This module never calls AWS APIs directly.
# All data comes from the output of inventory.py.
# ============================================================

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import json
import re
from datetime import datetime, timezone


# ── Severity ────────────────────────────────────────────────
# An Enum is used here (not plain strings) so we can:
#   1. Sort findings by severity numerically (CRITICAL=5 sorts above LOW=1)
#   2. Catch typos at definition time rather than at runtime
class Severity(Enum):
    CRITICAL = 5
    HIGH     = 4
    MEDIUM   = 3
    LOW      = 2
    INFO     = 1


# ── Finding ─────────────────────────────────────────────────
# A dataclass is used instead of a plain dict so that:
#   1. Every finding is guaranteed to have all required fields
#   2. IDE autocomplete works on finding.severity, finding.title, etc.
#   3. We can call dataclasses.asdict(finding) to serialize to JSON easily
#
# Field-by-field explanation:
#   rule_id           → a short stable identifier, e.g. "IAM-001"
#                       Used to uniquely identify a rule across reports/tickets.
#   severity          → a Severity enum value
#   title             → one-line human-readable name of the issue
#   description       → what the issue is and why it matters
#   remediation       → exact steps to fix it
#   affected_resource → which specific AWS resource triggered this finding
#                       e.g. "arn:aws:iam::123456789012:policy/MyPolicy"
#   region            → AWS region of the resource, or "global" for IAM/S3
#   raw_evidence      → the actual policy statement / API value that triggered
#                       the rule — useful for auditors and debugging
@dataclass
class Finding:
    rule_id:            str
    severity:           Severity
    title:              str
    description:        str
    remediation:        str
    affected_resource:  str
    region:             str = "global"
    raw_evidence:       Any = None  # can be a dict, list, or string


# ── PermissionAnalyzer ───────────────────────────────────────
# All security check methods live on this class.
# Constructor accepts the full inventory dict that inventory.py produces.
#
# Expected top-level structure of `inventory`
# (produced by iam_inventory.collect_inventory()):
# {
#   "account_id":   "178701499493",     ← from STS get_caller_identity
#   "generated_at": "2025-...",         ← UTC timestamp
#   "iam_users":    [ ... ],            ← from list_users()
#   "iam_roles":    [ ... ],            ← from list_roles()
#   "iam_policies": [ ... ],            ← from list_policies()
# }
# Keys to be added as iam_inventory.py grows:
#   "credential_report", "s3_buckets", "security_groups"


class PermissionAnalyzer:

    def __init__(self, inventory: dict):
        # Store the entire inventory so every check method can access it
        self.inventory = inventory

        # account_id is included in finding ARNs and log output
        self.account_id = inventory.get("account_id", "unknown")

        # Master list — every check method appends Finding objects here
        self.findings: list[Finding] = []

    # ── Internal helper ──────────────────────────────────────
    def _add_finding(self, **kwargs) -> None:
        """Construct a Finding from keyword args and append to self.findings."""
        # **kwargs lets us call _add_finding(rule_id=..., severity=..., ...)
        # without positional argument ordering mistakes
        self.findings.append(Finding(**kwargs))


    # ── IAM-001 : AdministratorAccess ───────────────────────
    def check_admin_access(self) -> None:
        """
        CIS AWS Foundations Benchmark 1.16
        Detect any attached IAM policy that grants full admin privileges.

        Two sub-checks:
          A) Policy is named 'AdministratorAccess' and is attached (AttachedTo > 0)
          B) Policy document contains Action '*' + Resource '*' in an Allow statement
             (catches custom policies that recreate admin access under another name)
        """
        # Pull the policy list from the inventory.
        # Each item is a dict with keys: PolicyName, PolicyId, Arn,
        # AttachedTo, DefaultVersionId, Document.
        policies = self.inventory.get('iam_policies', [])

        for policy in policies:
            name        = policy['PolicyName']
            arn         = policy['Arn']
            attached_to = policy['AttachedTo']   # int: number of entities using this policy
            document    = policy.get('Document', {})

            # ── Sub-check A: name match ──────────────────────
            # The AWS-managed AdministratorAccess policy has a well-known name.
            # If it's attached to anyone, that's an immediate CRITICAL finding.
            # We don't need to look at the document — the name alone is definitive.
            if name == 'AdministratorAccess' and attached_to > 0:
                self._add_finding(
                    rule_id='IAM-001-A',
                    severity=Severity.CRITICAL,
                    title='AdministratorAccess policy is attached',
                    description=(
                        f"The AWS-managed policy 'AdministratorAccess' is attached to "
                        f"{attached_to} IAM entity(s). This policy grants unrestricted "
                        f"access to every AWS service and resource in the account."
                    ),
                    remediation=(
                        "Detach AdministratorAccess from all users and roles. "
                        "Replace it with least-privilege policies scoped to specific "
                        "services and resources. Use IAM Access Analyzer to generate "
                        "a policy based on actual access patterns."
                    ),
                    affected_resource=arn,
                    region='global',
                    raw_evidence={
                        'policy_name': name,
                        'policy_arn':  arn,
                        'attached_to': attached_to,
                    }
                )
                # Already flagged by name — skip document scan for this policy
                # to avoid a duplicate finding for the same policy
                continue

            # ── Sub-check B: document scan ───────────────────
            # For every other attached policy, read the actual statements.
            # We're looking for Effect=Allow with Action=* AND Resource=* together.
            #
            # IAM policy documents have this structure:
            # {
            #   "Version": "2012-10-17",
            #   "Statement": [                  ← can be a list OR a single dict
            #       {
            #           "Effect":   "Allow",
            #           "Action":   "*",        ← can be a string OR a list
            #           "Resource": "*"         ← can be a string OR a list
            #       }
            #   ]
            # }

            # Normalise Statement to always be a list, never a bare dict.
            # AWS sometimes returns a single statement as a dict, not a list.
            statements = document.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                # Only Allow statements grant permissions.
                # Deny statements restrict them — never flag Deny.
                if stmt.get('Effect') != 'Allow':
                    continue

                # Action and Resource can each be a string or a list.
                # Normalise both to lists so we can use 'in' consistently.
                actions   = stmt.get('Action', [])
                resources = stmt.get('Resource', [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                # The dangerous combination: unrestricted action on every resource.
                # "*" in actions means "every AWS API call".
                # "*" in resources means "every resource in the account".
                # Together they are equivalent to AdministratorAccess.
                if '*' in actions and '*' in resources:
                    self._add_finding(
                        rule_id='IAM-001-B',
                        severity=Severity.CRITICAL,
                        title='Custom policy grants full admin privileges (Action:* + Resource:*)',
                        description=(
                            f"Policy '{name}' contains a statement with Action='*' and "
                            f"Resource='*', granting unrestricted access to all AWS services. "
                            f"It is attached to {attached_to} IAM entity(s)."
                        ),
                        remediation=(
                            "Replace the wildcard Action and Resource with specific, "
                            "least-privilege permissions. Use IAM Access Analyzer to "
                            "identify what permissions are actually needed."
                        ),
                        affected_resource=arn,
                        region='global',
                        raw_evidence={
                            'policy_name': name,
                            'policy_arn':  arn,
                            'attached_to': attached_to,
                            'statement':   stmt,
                        }
                    )
                    # One finding per policy is enough — stop scanning statements
                    break

    # ── IAM-002 : MFA Disabled for Console Users ────────────
    def check_mfa_disabled(self) -> None:
        """
        CIS AWS Foundations Benchmark 1.10
        Flag every IAM user who has console access (password enabled)
        but does not have MFA configured.

        Data source: inventory['credential_report']
        Each row is a dict from the IAM credential report CSV.
        """
        report = self.inventory.get('credential_report', [])

        for row in report:
            username = row.get('user', '')

            # Skip the root account row — root MFA is a separate check (IAM-003).
            # The root row has user == '<root_account>' in the CSV.
            if username == '<root_account>':
                continue

            # 'password_enabled' is a string: 'true', 'false', or 'not_supported'.
            # 'not_supported' only appears for the root row, which we already skipped.
            # We only care about users who CAN log into the console — password_enabled='true'.
            password_enabled = row.get('password_enabled', 'false')
            if password_enabled != 'true':
                # This is a programmatic-only user (no console password).
                # MFA doesn't apply — skip to avoid a false positive.
                continue

            # 'mfa_active' is a string: 'true' or 'false'.
            mfa_active = row.get('mfa_active', 'false')
            if mfa_active == 'false':
                # Console user with no MFA — this is the finding.
                # Build the ARN from account_id and username because the
                # credential report gives us the ARN directly in the 'arn' field.
                user_arn = row.get('arn', f"arn:aws:iam::{self.account_id}:user/{username}")

                self._add_finding(
                    rule_id='IAM-002',
                    severity=Severity.CRITICAL,
                    title=f'MFA not enabled for console user: {username}',
                    description=(
                        f"IAM user '{username}' has a console password but no MFA device "
                        f"configured. If this user's password is compromised, an attacker "
                        f"gains full console access with no additional barrier."
                    ),
                    remediation=(
                        f"Go to IAM → Users → {username} → Security credentials → "
                        f"Assign MFA device. Use a virtual MFA app (Google Authenticator, "
                        f"Authy) or a hardware FIDO key. Consider enforcing MFA via an "
                        f"IAM policy condition: aws:MultiFactorAuthPresent = true."
                    ),
                    affected_resource=user_arn,
                    region='global',
                    raw_evidence={
                        'username':         username,
                        'password_enabled': password_enabled,
                        'mfa_active':       mfa_active,
                    }
                )


    # ── IAM-003 : Root Account Usage ────────────────────────
    def check_root_account(self) -> None:
        """
        CIS AWS Foundations Benchmark 1.5, 1.6
        Three sub-checks on the root account row from the credential report:
          A) Root has an active access key        (CRITICAL — CIS 1.5)
          B) Root has no MFA                      (CRITICAL — CIS 1.6)
          C) Root has been used in the last 90 days (HIGH)
        """
        report = self.inventory.get('credential_report', [])

        # Find the root row — it is always user == '<root_account>'
        root_row = next((r for r in report if r.get('user') == '<root_account>'), None)

        if root_row is None:
            # Credential report didn't include a root row — unusual, skip.
            return

        root_arn = f"arn:aws:iam::{self.account_id}:root"

        # ── Sub-check A: active root access keys ────────────
        # Root access keys grant unlimited programmatic access with no
        # resource or action restrictions. They should never exist.
        # The credential report tracks two possible access keys per user.
        key1_active = root_row.get('access_key_1_active', 'false')
        key2_active = root_row.get('access_key_2_active', 'false')

        if key1_active == 'true' or key2_active == 'true':
            active_keys = []
            if key1_active == 'true':
                active_keys.append('access_key_1')
            if key2_active == 'true':
                active_keys.append('access_key_2')

            self._add_finding(
                rule_id='IAM-003-A',
                severity=Severity.CRITICAL,
                title='Root account has active access keys',
                description=(
                    f"The root account has {len(active_keys)} active access key(s): "
                    f"{', '.join(active_keys)}. Root access keys grant unlimited "
                    f"programmatic access and cannot be restricted by any IAM policy."
                ),
                remediation=(
                    "Delete all root access keys immediately via IAM → Security credentials "
                    "while logged in as root. Use IAM roles with least-privilege policies "
                    "for all programmatic access instead."
                ),
                affected_resource=root_arn,
                region='global',
                raw_evidence={
                    'access_key_1_active': key1_active,
                    'access_key_2_active': key2_active,
                }
            )

        # ── Sub-check B: root MFA ────────────────────────────
        # Without MFA, root is protected only by a password.
        # A compromised root password = total account loss.
        if root_row.get('mfa_active', 'false') == 'false':
            self._add_finding(
                rule_id='IAM-003-B',
                severity=Severity.CRITICAL,
                title='Root account does not have MFA enabled',
                description=(
                    "The root account has no MFA device configured. Root cannot be "
                    "restricted by IAM policies — a stolen password alone is sufficient "
                    "for complete account takeover."
                ),
                remediation=(
                    "Log in as root, go to IAM → Security credentials → Assign MFA device. "
                    "Use a hardware MFA key (YubiKey or similar) for root — not a virtual "
                    "app — because root MFA should be physically locked away."
                ),
                affected_resource=root_arn,
                region='global',
                raw_evidence={'mfa_active': root_row.get('mfa_active')}
            )

        # ── Sub-check C: recent root usage ───────────────────
        # Root should almost never be used. Routine root logins indicate
        # operational practices that bypass the IAM least-privilege model.
        # Threshold: any use in the last 90 days is flagged.
        last_used_str = root_row.get('password_last_used', 'N/A')

        if last_used_str not in ('N/A', 'no_information', ''):
            # Parse the ISO 8601 timestamp AWS provides, e.g. "2026-06-18T09:45:07Z"
            # We replace 'Z' with '+00:00' because Python's fromisoformat()
            # does not accept 'Z' as a UTC suffix before Python 3.11.
            last_used_dt = datetime.fromisoformat(
                last_used_str.replace('Z', '+00:00')
            )
            now = datetime.now(timezone.utc)
            days_since_use = (now - last_used_dt).days

            if days_since_use <= 90:
                self._add_finding(
                    rule_id='IAM-003-C',
                    severity=Severity.HIGH,
                    title=f'Root account was used {days_since_use} day(s) ago',
                    description=(
                        f"The root account was last used {days_since_use} day(s) ago "
                        f"({last_used_str}). Root should only be used for a small set of "
                        f"specific tasks that cannot be performed by any IAM user or role."
                    ),
                    remediation=(
                        "Audit what action required root login and determine if an IAM role "
                        "with appropriate permissions could perform it instead. "
                        "Valid root-only tasks include: changing account settings, "
                        "restoring a broken S3 bucket policy that locked out all IAM, "
                        "and closing the AWS account."
                    ),
                    affected_resource=root_arn,
                    region='global',
                    raw_evidence={
                        'password_last_used': last_used_str,
                        'days_since_use':     days_since_use,
                    }
                )

    # ── IAM-004 : Access Keys Older Than 90 Days ────────────
    def check_old_access_keys(self) -> None:
        """
        CIS AWS Foundations Benchmark 1.14
        Flag any active IAM access key that has not been rotated in 90+ days.

        Data source: inventory['credential_report']
        Checks access_key_1 and access_key_2 independently for each user.
        Skips inactive keys — an inactive key grants no access.
        Skips the root account row — root should have no access keys at all
        (that is covered by IAM-003-A).
        """
        report = self.inventory.get('credential_report', [])
        now    = datetime.now(timezone.utc)

        for row in report:
            username = row.get('user', '')

            if username == '<root_account>':
                continue

            # Check both possible access keys per user.
            # We iterate over a list of (active_field, rotated_field) pairs
            # so we don't repeat the same logic twice.
            key_pairs = [
                ('access_key_1_active', 'access_key_1_last_rotated'),
                ('access_key_2_active', 'access_key_2_last_rotated'),
            ]

            for active_field, rotated_field in key_pairs:
                # Only examine active keys — inactive keys cannot be used.
                if row.get(active_field) != 'true':
                    continue

                rotated_str = row.get(rotated_field, 'N/A')

                # 'N/A' means AWS has no rotation record — treat as never rotated.
                # This shouldn't happen for an active key, but handle it defensively.
                if rotated_str == 'N/A':
                    continue

                rotated_dt  = datetime.fromisoformat(rotated_str.replace('Z', '+00:00'))
                age_days    = (now - rotated_dt).days

                if age_days > 90:
                    user_arn  = row.get('arn', f"arn:aws:iam::{self.account_id}:user/{username}")
                    key_label = 'Key 1' if '1' in active_field else 'Key 2'

                    self._add_finding(
                        rule_id='IAM-004',
                        severity=Severity.HIGH,
                        title=f'Access key not rotated in {age_days} days: {username} ({key_label})',
                        description=(
                            f"IAM user '{username}' has an active access key ({key_label}) "
                            f"that was last rotated {age_days} days ago ({rotated_str}). "
                            f"Keys older than 90 days increase the window of exposure if "
                            f"the key was silently exfiltrated."
                        ),
                        remediation=(
                            f"Rotate the key: create a new key, update all systems using "
                            f"the old key, then deactivate and delete the old key. "
                            f"Use IAM → Users → {username} → Security credentials."
                        ),
                        affected_resource=user_arn,
                        region='global',
                        raw_evidence={
                            'username':       username,
                            'key':            key_label,
                            'last_rotated':   rotated_str,
                            'age_days':       age_days,
                        }
                    )

    # ── IAM-005 : Unused IAM Credentials ────────────────────
    def check_unused_users(self) -> None:
        """
        CIS AWS Foundations Benchmark 1.12
        Flag IAM users whose console password or active access keys
        have not been used in 90+ days.

        Sub-checks (independent — both can fire for the same user):
          A) Console password unused for 90+ days
          B) Active access key unused for 90+ days

        Data source: inventory['credential_report']
        """
        report   = self.inventory.get('credential_report', [])
        now      = datetime.now(timezone.utc)
        threshold = 90  # days

        for row in report:
            username = row.get('user', '')

            if username == '<root_account>':
                continue

            user_arn = row.get('arn', f"arn:aws:iam::{self.account_id}:user/{username}")

            # ── Sub-check A: console password unused ─────────
            # Only relevant if the user actually has a console password.
            if row.get('password_enabled') == 'true':
                last_used_str = row.get('password_last_used', 'N/A')

                if last_used_str == 'N/A':
                    # Password exists but has never been used — flag it.
                    self._add_finding(
                        rule_id='IAM-005-A',
                        severity=Severity.MEDIUM,
                        title=f'Console password never used: {username}',
                        description=(
                            f"IAM user '{username}' has a console password that has "
                            f"never been used. This account may be orphaned."
                        ),
                        remediation=(
                            f"Confirm whether '{username}' is still needed. "
                            f"If not, disable the console password or delete the user."
                        ),
                        affected_resource=user_arn,
                        region='global',
                        raw_evidence={
                            'username':         username,
                            'password_enabled': 'true',
                            'password_last_used': 'never',
                        }
                    )
                else:
                    # Password has been used — check how long ago.
                    last_used_dt = datetime.fromisoformat(last_used_str.replace('Z', '+00:00'))
                    days_inactive = (now - last_used_dt).days

                    if days_inactive > threshold:
                        self._add_finding(
                            rule_id='IAM-005-A',
                            severity=Severity.MEDIUM,
                            title=f'Console password unused for {days_inactive} days: {username}',
                            description=(
                                f"IAM user '{username}' has not logged into the console in "
                                f"{days_inactive} days (last used: {last_used_str}). "
                                f"Dormant console credentials are an unnecessary attack surface."
                            ),
                            remediation=(
                                f"Confirm whether '{username}' still needs console access. "
                                f"If not, deactivate the console password via "
                                f"IAM → Users → {username} → Security credentials."
                            ),
                            affected_resource=user_arn,
                            region='global',
                            raw_evidence={
                                'username':           username,
                                'password_last_used': last_used_str,
                                'days_inactive':      days_inactive,
                            }
                        )

            # ── Sub-check B: active access key unused ────────
            # Check both keys independently.
            key_pairs = [
                ('access_key_1_active', 'access_key_1_last_used_date', 'Key 1'),
                ('access_key_2_active', 'access_key_2_last_used_date', 'Key 2'),
            ]

            for active_field, last_used_field, key_label in key_pairs:
                if row.get(active_field) != 'true':
                    continue  # key is inactive — skip

                last_used_str = row.get(last_used_field, 'N/A')

                if last_used_str == 'N/A':
                    # Active key that has never been used — flag it.
                    self._add_finding(
                        rule_id='IAM-005-B',
                        severity=Severity.MEDIUM,
                        title=f'Active access key never used: {username} ({key_label})',
                        description=(
                            f"IAM user '{username}' has an active access key ({key_label}) "
                            f"that has never been used. Unused active keys are unnecessary "
                            f"credential exposure."
                        ),
                        remediation=(
                            f"Delete the unused key via "
                            f"IAM → Users → {username} → Security credentials."
                        ),
                        affected_resource=user_arn,
                        region='global',
                        raw_evidence={
                            'username':  username,
                            'key':       key_label,
                            'last_used': 'never',
                        }
                    )
                else:
                    last_used_dt  = datetime.fromisoformat(last_used_str.replace('Z', '+00:00'))
                    days_inactive = (now - last_used_dt).days

                    if days_inactive > threshold:
                        self._add_finding(
                            rule_id='IAM-005-B',
                            severity=Severity.MEDIUM,
                            title=f'Active access key unused for {days_inactive} days: {username} ({key_label})',
                            description=(
                                f"IAM user '{username}' has an active access key ({key_label}) "
                                f"unused for {days_inactive} days (last used: {last_used_str}). "
                                f"Dormant active keys are an unnecessary attack surface."
                            ),
                            remediation=(
                                f"Deactivate or delete the key via "
                                f"IAM → Users → {username} → Security credentials."
                            ),
                            affected_resource=user_arn,
                            region='global',
                            raw_evidence={
                                'username':     username,
                                'key':          key_label,
                                'last_used':    last_used_str,
                                'days_inactive': days_inactive,
                            }
                        )


    # ── IAM-006 : Wildcard Permissions ──────────────────────
    def check_wildcard_permissions(self) -> None:
        """
        CIS AWS Foundations Benchmark 1.16 (gap coverage below IAM-001-B)

        One finding per policy (not per statement) to avoid noise.

          A) Policy has any Allow statement with a wildcard Action → HIGH
          B) Policy has any Allow statement with Resource='*' and no wildcard Action → MEDIUM

        Skips statements already caught by IAM-001-B (Action=* AND Resource=*).
        Skips AdministratorAccess — already flagged by IAM-001-A.
        """
        policies = self.inventory.get('iam_policies', [])

        for policy in policies:
            name     = policy['PolicyName']
            arn      = policy['Arn']
            document = policy.get('Document', {})

            # AdministratorAccess is fully covered by IAM-001-A — skip it.
            if name == 'AdministratorAccess':
                continue

            statements = document.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]

            # Collect evidence across all statements before deciding to fire.
            wildcard_action_stmts   = []   # statements with wildcard Action
            wildcard_resource_stmts = []   # statements with Resource=* but specific Action

            for idx, stmt in enumerate(statements):
                if stmt.get('Effect') != 'Allow':
                    continue

                actions   = stmt.get('Action', [])
                resources = stmt.get('Resource', [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                has_wildcard_action   = any('*' in a for a in actions)
                has_wildcard_resource = '*' in resources

                # Skip full-admin statements — IAM-001-B already covers these.
                if has_wildcard_action and has_wildcard_resource:
                    continue

                if has_wildcard_action:
                    wildcard_action_stmts.append({
                        'statement_index':  idx,
                        'wildcard_actions': [a for a in actions if '*' in a],
                        'resources':        resources,
                    })
                elif has_wildcard_resource:
                    wildcard_resource_stmts.append({
                        'statement_index': idx,
                        'actions':         actions,
                    })

            # ── Sub-check A: one HIGH finding per policy with wildcard actions ──
            if wildcard_action_stmts:
                self._add_finding(
                    rule_id='IAM-006-A',
                    severity=Severity.HIGH,
                    title=f'Wildcard action(s) in policy: {name}',
                    description=(
                        f"Policy '{name}' has {len(wildcard_action_stmts)} Allow statement(s) "
                        f"with wildcard actions (e.g. 's3:*', 'iam:*'). "
                        f"This grants broader permissions than intended."
                    ),
                    remediation=(
                        "Replace wildcard actions with the specific API calls needed. "
                        "Use IAM Access Analyzer or CloudTrail to identify genuine usage."
                    ),
                    affected_resource=arn,
                    region='global',
                    raw_evidence={
                        'policy_name':       name,
                        'offending_statements': wildcard_action_stmts,
                    }
                )

            # ── Sub-check B: one MEDIUM finding per policy with wildcard resources ──
            if wildcard_resource_stmts:
                self._add_finding(
                    rule_id='IAM-006-B',
                    severity=Severity.MEDIUM,
                    title=f'Wildcard resource in policy: {name}',
                    description=(
                        f"Policy '{name}' has {len(wildcard_resource_stmts)} Allow statement(s) "
                        f"with Resource='*' and specific actions. "
                        f"Those actions apply to every resource in the account."
                    ),
                    remediation=(
                        "Replace Resource='*' with specific ARNs where possible. "
                        "Note: some read-only actions (e.g. s3:ListBuckets) legitimately "
                        "require Resource='*' — review each statement individually."
                    ),
                    affected_resource=arn,
                    region='global',
                    raw_evidence={
                        'policy_name':          name,
                        'offending_statements': wildcard_resource_stmts,
                    }
                )


    # ── Public entry point ───────────────────────────────────
    def analyze_all(self) -> list[Finding]:
        """
        Run every security check and return findings sorted by severity
        (most critical first).
        """
        self.check_admin_access()   # IAM-001: AdministratorAccess detection
        self.check_mfa_disabled()   # IAM-002: MFA Enabled/Disabled check
        self.check_root_account()   # IAM-003: Root account privilegdes check
        self.check_old_access_keys() # IAM-004: Old access key check > 90-days
        self.check_unused_users()   # IAM-005: Check unused users
        self.check_wildcard_permissions() # IAM-006 Wildcard permission

        # Sort findings: highest Severity.value first (CRITICAL=5 → top)
        self.findings.sort(key=lambda f: f.severity.value, reverse=True)
        return self.findings

    # ── Report formatter ─────────────────────────────────────
    def format_report(self, output_format: str = "text") -> str:
        """
        Format self.findings as either human-readable text or JSON.

        Args:
            output_format: "text" (default) or "json"

        Returns:
            A formatted string ready to print or write to a file.
        """
        if output_format == "json":
            # dataclasses don't serialize automatically, so we build dicts manually.
            # severity.name gives us the string "CRITICAL" instead of <Severity.CRITICAL: 5>
            serializable = [
                {
                    "rule_id":           f.rule_id,
                    "severity":          f.severity.name,
                    "title":             f.title,
                    "description":       f.description,
                    "remediation":       f.remediation,
                    "affected_resource": f.affected_resource,
                    "region":            f.region,
                    "raw_evidence":      f.raw_evidence,
                }
                for f in self.findings
            ]
            return json.dumps(serializable, indent=2, default=str)

        # ── Plain-text format ────────────────────────────────
        lines = []
        lines.append("=" * 70)
        lines.append("  CSPM SECURITY REPORT")
        lines.append(f"  Account: {self.account_id}")
        lines.append(f"  Total findings: {len(self.findings)}")
        lines.append("=" * 70)

        # Group by severity so the report reads CRITICAL → HIGH → ... → INFO
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW, Severity.INFO]:
            group = [f for f in self.findings if f.severity == sev]
            if not group:
                continue
            lines.append(f"\n[{sev.name}] — {len(group)} finding(s)")
            lines.append("-" * 70)
            
            # ANSI colour codes — only apply in text mode
            PURPLE = "\033[95m"
            GREEN  = "\033[92m"
            YELLOW = "\033[93m"
            RESET  = "\033[0m"

            for f in group:
                lines.append(f"  Rule       : {f.rule_id}")
                lines.append(f"  Title      : {f.title}")
                lines.append(f"  Resource   : {f.affected_resource}")
                lines.append(f"  Region     : {f.region}")
                lines.append("")
                lines.append(f"  {PURPLE}Description: {f.description}{RESET}")
                lines.append("")
                lines.append(f"  {GREEN}Remediation: {f.remediation}{RESET}")
                lines.append("")
                if f.raw_evidence:
                    evidence_str = json.dumps(f.raw_evidence, default=str)
                    if len(evidence_str) > 300:
                        evidence_str = evidence_str[:300] + "... [truncated]"
                    lines.append(f"  {YELLOW}Evidence   : {evidence_str}{RESET}")
                    lines.append("")
                lines.append("-" * 70)
                
                if f.raw_evidence:
                    evidence_str = json.dumps(f.raw_evidence, default=str)
                    if len(evidence_str) > 300:
                        evidence_str = evidence_str[:300] + "... [truncated]"
                    lines.append(f"  Evidence   : {evidence_str}")
                lines.append("")

        return "\n".join(lines)
