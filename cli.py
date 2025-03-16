#!/usr/bin/env python3
import click
import json
import os
import yaml
from scanner import scan_codebase
from report import display_report, generate_final_report
from refactor import refactor_file
from key_manager import reissue_keys
from test_runner import run_tests

def save_json(findings, json_path):
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
        click.echo(f"JSON findings saved to {json_path}")
    except Exception as e:
        click.echo(f"Error saving JSON output: {e}")

def load_config(config_file):
    config = {}
    if os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                config = data.get("scan", {})
        except Exception as e:
            click.echo(f"Error loading config file {config_file}: {e}")
    return config

@click.group()
def cli():
    """Quantum Migration CLI Tool: RSA-to-PQC Migration."""
    pass

@cli.command(name="configure")
def configure():
    """Generate a configuration file interactively."""
    scan_root = click.prompt("Enter the root directory to scan", default=".")
    include = click.prompt("Enter file patterns to include (comma-separated)", 
                           default="*.py,*.js,*.java,*.c,*.cpp,*.cs,*.rb,*.go,*.php")
    exclude = click.prompt("Enter directories to exclude (comma-separated)", default=".git,node_modules")
    dry_run = click.confirm("Enable dry-run mode (only log files without scanning)?", default=False)
    verbose = click.confirm("Enable verbose mode?", default=True)
    anonymize = click.confirm("Anonymize file paths in the report? (Not recommended for migration)", default=False)
    
    config_data = {
        "scan_root": scan_root,
        "include_patterns": [p.strip() for p in include.split(",")],
        "exclude_directories": [e.strip() for e in exclude.split(",")],
        "dry_run": dry_run,
        "verbose": verbose,
        "anonymize": anonymize,
        "rule_file": "rsa_rules.yml"
    }
    filename = click.prompt("Enter the config file name to save", default="config.yml")
    try:
        with open(filename, "w", encoding="utf-8") as f:
            yaml.dump({"scan": config_data}, f)
        click.echo(f"Configuration saved to {filename}")
    except Exception as e:
        click.echo(f"Error saving configuration: {e}")

@cli.command(name="scan_code")
@click.option('--path', default='.', help='Directory path to recursively scan for RSA vulnerabilities')
@click.option('--output-format', default='rich', type=click.Choice(['rich', 'html', 'pdf']), help='Output format for the report')
@click.option('--json-output', default=None, help='Optional path to save findings in JSON format')
@click.option('--config-file', default="config.yml", help="Path to config file (YAML)")
def scan_code(path, output_format, json_output, config_file):
    """Scan the codebase for insecure RSA usage."""
    click.echo(f"Scanning directory: {path}")
    config = load_config(config_file)
    findings = scan_codebase(path, config)
    display_report(findings, output_format)
    if json_output:
        save_json(findings, json_output)

@cli.command(name="migrate")
@click.option('--path', default='.', help='Root directory to scan and migrate')
@click.option('--dry-run', is_flag=True, help='Preview changes without modifying files')
@click.option('--json-output', default=None, help='Optional path to save raw scan findings in JSON format')
@click.option('--config-file', default="config.yml", help="Path to config file (YAML)")
def migrate(path, dry_run, json_output, config_file):
    """
    Scan for RSA vulnerabilities, refactor vulnerable files, trigger key reissuance, run tests,
    and generate a customized migration report.
    """
    click.echo("Starting RSA vulnerability scan...")
    config = load_config(config_file)
    findings = scan_codebase(path, config)
    total_files_scanned = sum([len(files) for _, _, files in os.walk(path)])
    if not findings:
        click.echo("No RSA vulnerabilities found. Exiting.")
        return

    display_report(findings, "rich")
    if json_output:
        save_json(findings, json_output)

    if click.confirm("Do you want to auto-refactor all vulnerable files?", default=True):
        files_to_refactor = {}
        for finding in findings:
            fpath = finding.get("real_path", finding["file"])
            files_to_refactor.setdefault(fpath, []).append(finding)

        for file_path, vulns in files_to_refactor.items():
            click.echo(f"Refactoring {file_path} (dry-run={dry_run}) ...")
            try:
                new_content = refactor_file(file_path, vulns, dry_run=dry_run)
                if not dry_run:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    click.echo(f"Updated {file_path}")
            except Exception as e:
                click.echo(f"Error refactoring {file_path}: {e}")

        if not dry_run and click.confirm("Refactoring complete. Do you want to auto-trigger key reissuance?", default=True):
            reissue_keys()

        click.echo("Running automated tests...")
        test_result = run_tests(path)
        if not test_result.get("success"):
            click.echo("Tests failed. Please review changes manually.")
            return
        else:
            click.echo("All tests passed.")

        final_report = generate_final_report(
            total_files_scanned=total_files_scanned,
            total_vulnerable_files=len(files_to_refactor),
            findings=findings,
            key_reissuance_done=(not dry_run)
        )
        click.echo("\nFinal Migration Report:\n")
        click.echo(final_report)
    else:
        click.echo("Auto-refactoring aborted. You may upload the JSON output to our platform for assisted migration.")

if __name__ == '__main__':
    cli()
