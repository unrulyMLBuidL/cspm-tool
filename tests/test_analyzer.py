# tests/test_analyzer.py
# ============================================================
# Unit tests for the PermissionAnalyzer security checks.
# No AWS credentials or network access required.
# Run: python3 -m pytest tests/ -v
# ============================================================

import pytest
from datetime import datetime, timezone, timedelta
from modules.analyzer import PermissionAnalyzer, Severity


# ── Shared fixture builder ───────────────────────────────────
def make_inventory(**overrides) -> dict:
    """
    Return a minimal valid inventory dict.
    Override any key by passing it as a keyword argument.
    """
    base = {
        'account_id':        '123456789012',
        'generated_at':      str(datetime.now(timezone.utc)),
        'iam_users':         [],
        'iam_roles':         [],
        'iam_policies':      [],
        'credential_report': [],
        's3_account_block':  {
            'BlockPublicAcls':       True,
            'IgnorePublicAcls':      True,
            'BlockPublicPolicy':     True,
            'RestrictPublicBuckets': True,
        },
        's3_buckets':        [],
        'security_groups':   [],
    }
    base.update(overrides)
    return base


# ── IAM-001-A : AdministratorAccess ─────────────────────────
def test_admin_access_fires():
    inventory = make_inventory(iam_policies=[{
        'PolicyName':       'AdministratorAccess',
        'PolicyId':         'ANPA000000000000001',
        'Arn':              'arn:aws:iam::aws:policy/AdministratorAccess',
        'AttachedTo':       2,
        'DefaultVersionId': 'v1',
        'Document': {
            'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]
        }
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert any(f.rule_id == 'IAM-001-A' for f in findings)


def test_admin_access_not_attached_does_not_fire():
    inventory = make_inventory(iam_policies=[{
        'PolicyName':       'AdministratorAccess',
        'PolicyId':         'ANPA000000000000001',
        'Arn':              'arn:aws:iam::aws:policy/AdministratorAccess',
        'AttachedTo':       0,   # not attached to anyone
        'DefaultVersionId': 'v1',
        'Document': {
            'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]
        }
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert not any(f.rule_id == 'IAM-001-A' for f in findings)


# ── IAM-002 : MFA disabled ───────────────────────────────────
def test_mfa_disabled_fires():
    inventory = make_inventory(credential_report=[{
        'user':             'alice',
        'arn':              'arn:aws:iam::123456789012:user/alice',
        'password_enabled': 'true',
        'mfa_active':       'false',
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert any(f.rule_id == 'IAM-002' for f in findings)


def test_mfa_enabled_does_not_fire():
    inventory = make_inventory(credential_report=[{
        'user':             'alice',
        'arn':              'arn:aws:iam::123456789012:user/alice',
        'password_enabled': 'true',
        'mfa_active':       'true',    # MFA is on
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert not any(f.rule_id == 'IAM-002' for f in findings)


def test_programmatic_user_no_mfa_does_not_fire():
    inventory = make_inventory(credential_report=[{
        'user':             'ci-bot',
        'arn':              'arn:aws:iam::123456789012:user/ci-bot',
        'password_enabled': 'false',   # no console access
        'mfa_active':       'false',
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert not any(f.rule_id == 'IAM-002' for f in findings)


# ── IAM-003-C : Root used recently ──────────────────────────
def test_root_used_recently_fires():
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
    inventory = make_inventory(credential_report=[{
        'user':               '<root_account>',
        'arn':                'arn:aws:iam::123456789012:root',
        'password_last_used': recent,
        'mfa_active':         'true',
        'access_key_1_active': 'false',
        'access_key_2_active': 'false',
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert any(f.rule_id == 'IAM-003-C' for f in findings)


def test_root_not_used_recently_does_not_fire():
    old = (datetime.now(timezone.utc) - timedelta(days=200)).strftime('%Y-%m-%dT%H:%M:%SZ')
    inventory = make_inventory(credential_report=[{
        'user':               '<root_account>',
        'arn':                'arn:aws:iam::123456789012:root',
        'password_last_used': old,
        'mfa_active':         'true',
        'access_key_1_active': 'false',
        'access_key_2_active': 'false',
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert not any(f.rule_id == 'IAM-003-C' for f in findings)


# ── IAM-004 : Old access keys ────────────────────────────────
def test_old_access_key_fires():
    old_date = (datetime.now(timezone.utc) - timedelta(days=100)).strftime('%Y-%m-%dT%H:%M:%SZ')
    inventory = make_inventory(credential_report=[{
        'user':                    'alice',
        'arn':                     'arn:aws:iam::123456789012:user/alice',
        'password_enabled':        'false',
        'mfa_active':              'false',
        'access_key_1_active':     'true',
        'access_key_1_last_rotated': old_date,
        'access_key_2_active':     'false',
        'access_key_2_last_rotated': 'N/A',
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert any(f.rule_id == 'IAM-004' for f in findings)


def test_new_access_key_does_not_fire():
    new_date = (datetime.now(timezone.utc) - timedelta(days=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
    inventory = make_inventory(credential_report=[{
        'user':                    'alice',
        'arn':                     'arn:aws:iam::123456789012:user/alice',
        'password_enabled':        'false',
        'mfa_active':              'false',
        'access_key_1_active':     'true',
        'access_key_1_last_rotated': new_date,
        'access_key_2_active':     'false',
        'access_key_2_last_rotated': 'N/A',
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert not any(f.rule_id == 'IAM-004' for f in findings)


# ── S3-001-A : Account block disabled ───────────────────────
def test_s3_account_block_disabled_fires():
    inventory = make_inventory(s3_account_block={
        'BlockPublicAcls':       False,
        'IgnorePublicAcls':      False,
        'BlockPublicPolicy':     False,
        'RestrictPublicBuckets': False,
    })
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert any(f.rule_id == 'S3-001-A' for f in findings)


def test_s3_account_block_enabled_does_not_fire():
    inventory = make_inventory(s3_account_block={
        'BlockPublicAcls':       True,
        'IgnorePublicAcls':      True,
        'BlockPublicPolicy':     True,
        'RestrictPublicBuckets': True,
    })
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert not any(f.rule_id == 'S3-001-A' for f in findings)


# ── EC2-001-A : SSH open to world ────────────────────────────
def test_ssh_open_to_world_fires():
    inventory = make_inventory(security_groups=[{
        'GroupId':   'sg-00000001',
        'GroupName': 'web-sg',
        'VpcId':     'vpc-00000001',
        'Region':    'us-east-1',
        'InboundRules': [{
            'IpProtocol': 'tcp',
            'FromPort':   22,
            'ToPort':     22,
            'IpRanges':   [{'CidrIp': '0.0.0.0/0'}],
            'Ipv6Ranges': [],
        }]
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert any(f.rule_id == 'EC2-001-A' for f in findings)


def test_ssh_scoped_to_ip_does_not_fire():
    inventory = make_inventory(security_groups=[{
        'GroupId':   'sg-00000002',
        'GroupName': 'web-sg',
        'VpcId':     'vpc-00000001',
        'Region':    'us-east-1',
        'InboundRules': [{
            'IpProtocol': 'tcp',
            'FromPort':   22,
            'ToPort':     22,
            'IpRanges':   [{'CidrIp': '10.0.0.0/8'}],   # private range only
            'Ipv6Ranges': [],
        }]
    }])
    analyzer = PermissionAnalyzer(inventory)
    findings = analyzer.analyze_all()
    assert not any(f.rule_id == 'EC2-001-A' for f in findings)
