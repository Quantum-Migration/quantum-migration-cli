#!/usr/bin/env python3
import subprocess
import json
import os
import platform
import fnmatch
import logging
from tqdm import tqdm

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

def run_semgrep(file_paths, rule_file="rsa_rules.yml"):
    # Check if the rule file exists
    if not os.path.exists(rule_file):
        print(f"Error: Rule file '{rule_file}' does not exist. Please create it.")
        return {}
    if platform.system() == "Windows":
        print("Semgrep is not supported on Windows natively. Please run this under WSL or on Linux.")
        return {}
    
    # Prepare the command: pass all file paths in the batch
    if isinstance(file_paths, list):
        cmd = ["semgrep", "--include", "*.py", "--config", rule_file, "--json"] + file_paths
    else:
        cmd = ["semgrep", "--include", "*.py", "--config", rule_file, "--json", file_paths]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running Semgrep on files: {e}")
        print("Semgrep output:", e.stdout, e.stderr)
        return {}
    except FileNotFoundError:
        print("Semgrep not found. Please install semgrep and ensure it is in your PATH.")
        return {}

def assess_risk(result):
    msg = result.get("extra", {}).get("message", "").lower().strip()
    if msg.startswith("insecure rsa key usage detected"):
        if (">=3072" in msg) or ("kyber" in msg):
            return "Low"
        return "High"
    elif msg.startswith("insecure use of md5 detected"):
        return "High"
    elif msg.startswith("insecure use of sha-1 detected"):
        return "High"
    elif msg.startswith("insecure use of ecdsa detected"):
        return "High"
    elif msg.startswith("insecure use of triple des detected") or ("3des" in msg and "insecure" in msg):
        return "Medium"
    elif msg.startswith("insecure use of diffie") or ("diffie" in msg and "insecure" in msg):
        return "Low"
    elif msg.startswith("insecure hmac with md5 detected"):
        return "High"
    return "Low"

def should_include(file_name, include_patterns):
    for pattern in include_patterns:
        if fnmatch.fnmatch(file_name, pattern):
            return True
    return False

def should_exclude(dir_path, exclude_patterns):
    for pattern in exclude_patterns:
        if pattern in dir_path or fnmatch.fnmatch(dir_path, pattern):
            return True
    return False

def anonymize_path(full_path, levels=2):
    parts = os.path.normpath(full_path).split(os.sep)
    return os.sep.join(parts[-levels:]) if len(parts) >= levels else full_path

def scan_codebase(root_path, config={}):
    """
    Recursively scans root_path using configuration options:
      - include_patterns: list of glob patterns to include (default: ["*.py"])
      - exclude_directories: list of directory patterns to exclude (default: [".git", "node_modules", "venv", "__pycache__"])
      - dry_run: if True, only log files without scanning them
      - verbose: if True, print detailed progress messages
      - anonymize: if True, show only the last few path segments in the report
      - rule_file: the Semgrep config file to use (default: "rsa_rules.yml")
    """
    include_patterns = config.get("include_patterns", ["*.py"])
    if not include_patterns:
        include_patterns = ["*.py"]
    # Default excludes for common third-party directories.
    default_excludes = [".git", "node_modules", "venv", "__pycache__"]
    user_excludes = config.get("exclude_directories", [])
    exclude_dirs = list(set(default_excludes + user_excludes))
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", True)
    anonymize = config.get("anonymize", False)
    rule_file = config.get("rule_file", "rsa_rules.yml")
    
    logging.debug(f"Include patterns: {include_patterns}")
    logging.debug(f"Exclude directories: {exclude_dirs}")
    
    findings = []
    if not os.path.exists(root_path):
        print(f"Error: The specified root path '{root_path}' does not exist.")
        return findings

    file_list = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Exclude directories using our default list
        dirnames[:] = [d for d in dirnames if not should_exclude(os.path.join(dirpath, d), exclude_dirs)]
        for file in filenames:
            if should_include(file, include_patterns):
                file_list.append(os.path.join(dirpath, file))
    
    logging.info(f"Found {len(file_list)} files to scan under {root_path}.")
    if len(file_list) == 0:
        logging.warning("No files to scan.")
        return findings

    if dry_run:
        for file_path in file_list:
            print(f"[DRY RUN] Would scan: {file_path}")
        return findings

    # Batch processing to reduce per-call overhead
    semgrep_results = {"results": []}
    batch_size = 100
    if len(file_list) <= batch_size:
        semgrep_results = run_semgrep(file_list, rule_file=rule_file)
    else:
        for i in range(0, len(file_list), batch_size):
            batch = file_list[i:i+batch_size]
            logging.debug(f"Scanning batch {i} to {i+len(batch)}")
            batch_results = run_semgrep(batch, rule_file=rule_file)
            if "results" in batch_results:
                semgrep_results["results"].extend(batch_results["results"])
    
    # Process Semgrep results—only add findings that mention "rsa" in the message.
    for res in semgrep_results.get("results", []):
        file_path = res.get("path", "")
        if "rsa" not in res.get("extra", {}).get("message", "").lower():
            continue
        line_num = res.get("start", {}).get("line")
        if line_num is None:
            line_str = "N/A"
            code_snippet = ""
        else:
            line_str = str(line_num)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                code_snippet = lines[line_num - 1].rstrip("\n") if line_num <= len(lines) else ""
            except Exception:
                code_snippet = ""
        findings.append({
            "file": anonymize_path(file_path) if anonymize else file_path,
            "real_path": file_path,
            "line": line_str,
            "message": "RSA detected",
            "risk": assess_risk(res),
            "code": code_snippet
        })

    # Additional text search for any unmatched "rsa" occurrences.
    for file_path in file_list:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for idx, line in enumerate(lines, start=1):
                if "rsa" in line.lower():
                    already_reported = any(
                        f["real_path"] == file_path and f["line"] == str(idx)
                        for f in findings
                    )
                    if not already_reported:
                        findings.append({
                            "file": anonymize_path(file_path) if anonymize else file_path,
                            "real_path": file_path,
                            "line": str(idx),
                            "message": "Unmatched RSA reference",
                            "risk": "Review",
                            "code": line.strip()
                        })
        except Exception:
            continue

    if verbose:
        print("Scan complete.")
    return findings
