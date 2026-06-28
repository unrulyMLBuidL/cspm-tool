# AWS CSPM Tool

A Cloud Security Posture Management (CSPM) tool for AWS, built in Python.
Scans IAM, S3, and EC2 for misconfigurations mapped to CIS AWS Foundations
Benchmark controls and outputs structured findings with remediation guidance.

Built from scratch as a learning project — not a wrapper around existing tools.

---

## What It Does

Most AWS accounts accumulate misconfigurations silently: admin policies attached
to the wrong roles, S3 buckets with public access enabled, root credentials used
regularly, access keys that never get rotated. None of these show up in your
application logs. A CSPM tool surfaces them before an attacker does.

This tool:
- Assumes a read-only IAM role in the target account (no persistent credentials stored)
- Collects IAM, S3, and EC2 resource data via boto3
- Runs security checks mapped to CIS controls
- Detects privilege escalation paths in attached policies
- Outputs a colour-coded terminal report and a Markdown file

---

## Architecture

<img width="271" height="591" alt="cspm-tool-architecture drawio" src="https://github.com/user-attachments/assets/90c00176-5abc-4563-87f8-434ff38c6a9a" />

---

## Setup

**Prerequisites:**
- Python 3.11+
- AWS CLI configured with credentials that can assume the audit role
- An IAM role in the target account with read-only permissions (see below)

**Install dependencies:**
```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

**Create the audit role:**

In the target AWS account, create an IAM role named `iam-readonly-audit-role`
with a trust policy allowing your caller identity to assume it, and attach
these managed policies:

- `SecurityAudit` (AWS managed)
- One inline policy with:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetAccountPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

**Set the role ARN as an environment variable:**
```bash
export AUDIT_ROLE_ARN="arn:aws:iam::YOUR_ACCOUNT_ID:role/iam-readonly-audit-role"
```

---

## Usage

```bash
python3 test_run_analyzer.py
```

Output:
- Colour-coded findings in the terminal (CRITICAL -> HIGH -> MEDIUM)
- `reports/report.md` — full Markdown report with remediation checklist

---

## Checks Implemented

| Rule ID | Severity | Description | CIS Control |
|---------|----------|-------------|-------------|
| IAM-001-A | CRITICAL | AdministratorAccess policy attached | 1.16 |
| IAM-001-B | CRITICAL | Custom policy grants full admin (Action:* + Resource:*) | 1.16 |
| IAM-002 | CRITICAL | MFA disabled for console users | 1.10 |
| IAM-003-A | CRITICAL | Root account has active access keys | 1.5 |
| IAM-003-B | CRITICAL | Root account has no MFA | 1.6 |
| IAM-003-C | HIGH | Root account used in last 90 days | 1.7 |
| IAM-004 | HIGH | Access key not rotated in 90+ days | 1.14 |
| IAM-005-A | MEDIUM | Console password unused 90+ days | 1.12 |
| IAM-005-B | MEDIUM | Active access key unused 90+ days | 1.12 |
| IAM-006-A | HIGH | Wildcard action in attached policy | 1.16 |
| IAM-006-B | MEDIUM | Wildcard resource in attached policy | 1.16 |
| S3-001-A | CRITICAL | Account-level S3 Public Access Block disabled | 2.1.5 |
| S3-001-B | HIGH | Bucket-level Public Access Block incomplete | 2.1.1 |
| S3-001-C | CRITICAL | Bucket ACL grants public access | 2.1.2 |
| S3-001-D | CRITICAL | Bucket policy allows public access | 2.1.2 |
| EC2-001-A | CRITICAL | Security group allows SSH/RDP from internet | 5.2 |
| EC2-001-B | HIGH | Security group allows unrestricted port access | 5.3 |
| ESC-001 | CRITICAL | iam:CreatePolicyVersion enables policy rewrite | — |
| ESC-002 | CRITICAL | iam:AttachUserPolicy enables policy attachment | — |
| ESC-003 | HIGH | iam:PassRole + Lambda enables privilege escalation | — |
| ESC-004 | HIGH | iam:PassRole + EC2 enables privilege escalation | — |
| ESC-005 | HIGH | iam:CreateAccessKey for other users | — |
| ESC-006 | HIGH | iam:CreateLoginProfile for other users | — |

---

## Limitations

- **Single-policy escalation only:** ESC checks look for dangerous permission
  combinations within a single policy. Cross-policy escalation (where dangerous
  permissions are split across multiple policies on the same entity) is not detected.
- **us-east-1 only:** EC2 security group checks run against the default region.
  Multi-region support requires iterating over all enabled regions.
- **Managed policies only:** Inline policies attached directly to users or roles
  are not scanned. These require per-entity API calls not currently in the inventory.
- **No real-time alerting:** This is a point-in-time scan. Run it on a schedule
  via cron or CI/CD for continuous coverage.

---

## Sample Output

See [`reports/sample_report.md`](reports/sample_report.md) for an example report.

---

## Project Structure

cspm_tool/

├── README.md

├── requirements.txt

├── test_run_analyzer.py    ← entry point

├── iam_inventory.py        ← AWS data collection

├── analyzer.py             ← security checks (IAM, S3, EC2)

├── escalation.py           ← privilege escalation detection

├── reporter.py             ← Markdown report generator

├── docs/

│   └── architecture.md     ← system architecture diagram

└── reports/

├── report.md           ← live output (gitignored — contains real account data)

└── sample_report.md    ← sanitised example committed to repo

---

## .gitignore Note

**Do not commit `reports/report.md` to version control.** It contains your real
AWS account ID and resource names. Only `reports/sample_report.md` (with
sanitised data) should be committed.

Add to `.gitignore`:
reports/report.md
