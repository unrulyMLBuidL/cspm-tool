from iam_inventory import collect_inventory
from analyzer import PermissionAnalyzer
import json

inventory_data = collect_inventory()
analyzer = PermissionAnalyzer(inventory_data)
findings  = analyzer.analyze_all()
print(analyzer.format_report("text"))
