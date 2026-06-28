# reporter.py
# ============================================================
# Markdown report generator.
# Accepts a flat list of Finding objects and the inventory dict.
# Writes a structured .md file to disk.
# ============================================================

import json
import os
from datetime import datetime, timezone
from modules.analyzer import Severity, Finding

def generate_report(findings: list[Finding], inventory: dict, output_path: str) -> None:
    """
    Write a Markdown security report to output_path.

    Args:
        findings:    flat list of Finding objects (analyzer + escalation combined)
        inventory:   the dict returned by collect_inventory()
        output_path: file path to write, e.g. 'reports/report.md'
    """
    account_id  = inventory.get('account_id', 'unknown')
    generated   = inventory.get('generated_at', str(datetime.now(timezone.utc)))
    lines       = []

    # ── Severity counts ──────────────────────────────────────
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    # ── Section 1: Executive Summary ────────────────────────
    lines.append("# CSPM Security Report")
    lines.append("")
    lines.append(f"**Account ID:** `{account_id}`  ")
    lines.append(f"**Scan time:** {generated}  ")
    lines.append(f"**Total findings:** {len(findings)}  ")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if counts[sev] > 0:
            lines.append(f"| {sev.name} | {counts[sev]} |")
    lines.append("")

    # Resources scanned — pull counts from inventory
    lines.append("### Resources Scanned")
    lines.append("")
    lines.append("| Resource Type | Count |")
    lines.append("|---------------|-------|")
    lines.append(f"| IAM Users | {len(inventory.get('iam_users', []))} |")
    lines.append(f"| IAM Roles | {len(inventory.get('iam_roles', []))} |")
    lines.append(f"| IAM Policies (attached) | {len(inventory.get('iam_policies', []))} |")
    lines.append(f"| S3 Buckets | {len(inventory.get('s3_buckets', []))} |")
    lines.append(f"| Security Groups | {len(inventory.get('security_groups', []))} |")
    lines.append("")

    # ── Section 2: Findings by Severity ─────────────────────
    lines.append("## Findings by Severity")
    lines.append("")

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue

        lines.append(f"### {sev.name} — {len(group)} finding(s)")
        lines.append("")

        for f in group:
            lines.append(f"#### {f.rule_id}: {f.title}")
            lines.append("")
            lines.append(f"- **Resource:** `{f.affected_resource}`")
            lines.append(f"- **Region:** {f.region}")
            lines.append("")
            lines.append(f"**Description:** {f.description}")
            lines.append("")
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
            if f.raw_evidence:
                evidence_str = json.dumps(f.raw_evidence, default=str)
                if len(evidence_str) > 300:
                    evidence_str = evidence_str[:300] + "... [truncated]"
                lines.append(f"**Evidence:** `{evidence_str}`")
                lines.append("")
            lines.append("---")
            lines.append("")

    # ── Section 3: Remediation Checklist ────────────────────
    lines.append("## Remediation Checklist")
    lines.append("")
    lines.append("Ordered by severity. Check off each item after resolving.")
    lines.append("")

    n = 1
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        for f in findings:
            if f.severity != sev:
                continue
            lines.append(f"{n}. **[{sev.name}] {f.rule_id}** — {f.title}  ")
            lines.append(f"   _{f.remediation}_")
            lines.append("")
            n += 1

    # ── Write to disk ────────────────────────────────────────
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as fh:
        fh.write('\n'.join(lines))

    print(f"Report written to: {output_path}")
