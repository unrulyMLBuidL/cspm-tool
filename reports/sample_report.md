# CSPM Security Report

> **Note:** This is a sanitised sample report for demonstration purposes.
> Account IDs, ARNs, and resource names have been replaced with placeholders.

**Account ID:** `123456789012`
**Scan time:** 2026-06-22T23:00:00+00:00
**Total findings:** 8

## Executive Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 1 |
| MEDIUM | 5 |

### Resources Scanned

| Resource Type | Count |
|---------------|-------|
| IAM Users | 1 |
| IAM Roles | 7 |
| IAM Policies (attached) | 8 |
| S3 Buckets | 3 |
| Security Groups | 1 |

---

## Findings by Severity

### CRITICAL — 2 finding(s)

#### IAM-001-A: AdministratorAccess policy is attached

- **Resource:** `arn:aws:iam::aws:policy/AdministratorAccess`
- **Region:** global

**Description:** The AWS-managed policy 'AdministratorAccess' is attached to 2
IAM entity(s). This policy grants unrestricted access to every AWS service and
resource in the account.

**Remediation:** Detach AdministratorAccess from all users and roles. Replace it
with least-privilege policies scoped to specific services and resources. Use IAM
Access Analyzer to generate a policy based on actual access patterns.

**Evidence:** `{"policy_name": "AdministratorAccess", "attached_to": 2}`

---

#### S3-001-A: S3 account-level Public Access Block is not fully enabled

- **Resource:** `arn:aws:s3:::* (account: 123456789012)`
- **Region:** global

**Description:** The account-level S3 Public Access Block has 4 flag(s) disabled.
This means individual buckets can be made public via ACL or bucket policy.

**Remediation:** Go to S3 → Block Public Access (account settings) and enable all
four flags. This is a single click in the console.

**Evidence:** `{"disabled_flags": ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]}`

---

### HIGH — 1 finding(s)

#### IAM-003-C: Root account was used recently

- **Resource:** `arn:aws:iam::123456789012:root`
- **Region:** global

**Description:** The root account was last used 2 day(s) ago. Root should only
be used for a small set of specific tasks that cannot be performed by any IAM
user or role.

**Remediation:** Audit what action required root login and determine if an IAM
role with appropriate permissions could perform it instead.

---

### MEDIUM — 5 finding(s)

#### IAM-006-B: Wildcard resource in policy: AWSOrganizationsServiceTrustPolicy

- **Resource:** `arn:aws:iam::aws:policy/aws-service-role/AWSOrganizationsServiceTrustPolicy`
- **Region:** global

**Description:** Policy has 1 Allow statement(s) with Resource='*' and specific
actions. Those actions apply to every resource in the account.

**Remediation:** Replace Resource='*' with specific ARNs where possible.

---

_[4 additional MEDIUM findings truncated in this sample — see live report for full output]_

---

## Remediation Checklist

1. **[CRITICAL] IAM-001-A** — AdministratorAccess policy is attached
   _Detach AdministratorAccess from all users and roles..._

2. **[CRITICAL] S3-001-A** — S3 account-level Public Access Block is not fully enabled
   _Go to S3 → Block Public Access (account settings) and enable all four flags..._

3. **[HIGH] IAM-003-C** — Root account used recently
   _Audit what action required root login..._

4. **[MEDIUM] IAM-006-B** — Wildcard resource policies (x5)
   _Replace Resource='*' with specific ARNs where possible..._
