# core/utils/report_generator.py
from pathlib import Path
from datetime import datetime
import json

# Modified to accept findings as an argument
def generate_report(scan_type, target, findings=None, output_dir="outputs/reports/"):
    """Generate standardized vulnerability reports"""
    if findings is None:
        findings = [] # Ensure findings is a list if not provided

    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Changed report file name to be more specific to scan_type
    report_file = report_dir / f"{scan_type}_report_{timestamp}.json" 

    report_data = {
        "scan_type": scan_type,
        "target": target,
        "timestamp": timestamp,
        "findings": findings # Populate findings from the argument
    }
    
    with open(report_file, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    return str(report_file)