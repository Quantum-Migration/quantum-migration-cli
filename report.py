from rich.console import Console
from rich.table import Table
from jinja2 import Template

def get_recommendation(finding):
    msg = finding.get("message", "").lower()
    if "rsa" in msg:
        return "Replace RSA usage with PQC key generation (e.g., Kyber) and reissue keys."
    return "Review the finding."

def generate_rich_report(findings):
    console = Console()
    table = Table(title="RSA-to-PQC Migration Audit Report", show_lines=True)
    table.add_column("File", style="cyan", no_wrap=True)
    table.add_column("Line", justify="center", style="magenta")
    table.add_column("Message", style="yellow")
    table.add_column("Risk", style="red")
    table.add_column("Code Snippet", style="green")
    for f in findings:
        table.add_row(
            f.get("file", "Unknown"),
            str(f.get("line", "N/A")),
            f.get("message", "No message"),
            f.get("risk", "Unknown"),
            f.get("code", "")
        )
    console.print(table)

def generate_final_report(total_files_scanned, total_vulnerable_files, findings, key_reissuance_done):
    percent = (total_vulnerable_files / total_files_scanned) * 100 if total_files_scanned else 0
    template_str = """
==================== Migration Report ====================

Total files scanned                : {{ total_files_scanned }}
Files with RSA vulnerabilities     : {{ total_vulnerable_files }} ({{ percent | round(2) }}%)

-------------------- Details --------------------
{% for f in findings %}
File: {{ f.file }}
Line: {{ f.line }}
Issue: {{ f.message }}
Recommendation: {{ recommendation(f) }}
-------------------------------------------------------
{% endfor %}

------------------ Next Steps ------------------
1. Review the changes above.
2. {% if key_reissuance_done %}PQC keys have been automatically reissued.{% else %}Please trigger key reissuance manually.{% endif %}
3. Run further integration tests and validate the migration.
===========================================================
"""
    template = Template(template_str)
    report = template.render(
        total_files_scanned=total_files_scanned,
        total_vulnerable_files=total_vulnerable_files,
        percent=percent,
        findings=findings,
        key_reissuance_done=key_reissuance_done,
        recommendation=get_recommendation
    )
    return report

def display_report(findings, output_format="rich"):
    if output_format == "rich":
        generate_rich_report(findings)
    else:
        print("Only 'rich' output is supported in this CLI version.")
