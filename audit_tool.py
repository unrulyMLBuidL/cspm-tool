# audit_tool.py
# ============================================================
# Main entry point for the CSPM tool.
# Run: python3 audit_tool.py
# Requires: AUDIT_ROLE_ARN environment variable set
# ============================================================

from modules.inventory   import collect_inventory
from modules.analyzer    import PermissionAnalyzer
from modules.escalation  import check_escalation_paths
from modules.reporter    import generate_report


def main():
    print("Starting CSPM scan...\n")

    # Step 1: Collect inventory from AWS
    inventory_data = collect_inventory()

    # Step 2: Run security checks
    analyzer     = PermissionAnalyzer(inventory_data)
    findings     = analyzer.analyze_all()
    esc_findings = check_escalation_paths(inventory_data)

    # Step 3: Merge and sort all findings
    all_findings = sorted(
        findings + esc_findings,
        key=lambda f: f.severity.value,
        reverse=True
    )

    # Step 4: Terminal output
    print(analyzer.format_report("text"))

    if esc_findings:
        print(f"\n[ESCALATION PATHS] — {len(esc_findings)} finding(s)")
        print("-" * 70)
        for f in esc_findings:
            print(f"  Rule     : {f.rule_id}")
            print(f"  Title    : {f.title}")
            print(f"  Severity : {f.severity.name}")
            print(f"  Resource : {f.affected_resource}")
            print()
    else:
        print("\n[ESCALATION PATHS] — 0 finding(s). No escalation paths detected.")

    # Step 5: Write Markdown report
    generate_report(all_findings, inventory_data, "reports/report.md")


if __name__ == '__main__':
    main()
