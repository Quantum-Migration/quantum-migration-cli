#!/usr/bin/env python3
import subprocess
import yaml
import json
import os
import platform
import fnmatch
import logging
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def run_semgrep(target_path, rule_file="pqc_rules.yml"):
    if platform.system() == "Windows":
        print("Semgrep is not supported on Windows natively. Please run this under WSL or on Linux.")
        return {}
    
    # Run semgrep on the target file using a rule file
    cmd = ["semgrep", "--include", "*.py", "--config", rule_file, "--json", target_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Semgrep on {target_path}: {e}")
        logging.error(f"Semgrep output: {e.stdout} {e.stderr}")
        return {}
    except FileNotFoundError:
        logging.error("Semgrep not found. Please install semgrep and ensure it is in your PATH.")
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
    """Return only the last 'levels' parts of the path to protect sensitive directories."""
    parts = os.path.normpath(full_path).split(os.sep)
    return os.sep.join(parts[-levels:]) if len(parts) >= levels else full_path

def scan_codebase(root_path, config={}):
    """
    Recursively scans the root_path using configuration options provided in config:
      - include_patterns: list of glob patterns to include (default: ["*.py"])
      - exclude_directories: list of directory patterns to exclude (default: [])
      - dry_run: if True, only log files without scanning them
      - verbose: if True, print detailed progress messages
      - anonymize: if True, only show the last few path segments in the report
    """
    include_patterns = config.get("include_patterns", ["*.py"])
    exclude_dirs = config.get("exclude_directories", [])
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", True)
    anonymize = config.get("anonymize", False)
    
    findings = []
    if not os.path.exists(root_path):
        print(f"Error: The specified root path '{root_path}' does not exist.")
        return findings

    # Collect all file paths to scan
    file_list = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Exclude directories as per configuration
        dirnames[:] = [d for d in dirnames if not should_exclude(os.path.join(dirpath, d), exclude_dirs)]
        for file in filenames:
            if should_include(file, include_patterns):
                file_list.append(os.path.join(dirpath, file))
    
    if verbose:
        print(f"Found {len(file_list)} files to scan under {root_path}.")

    for file_path in tqdm(file_list, desc="Scanning files", disable=not verbose):
        try:
            if not os.access(file_path, os.R_OK):
                if verbose:
                    print(f"Skipping unreadable file: {file_path}")
                continue
            if dry_run:
                print(f"[DRY RUN] Would scan: {file_path}")
                continue
            # Run semgrep on the file
            result = run_semgrep(file_path)
            for res in result.get("results", []):
                line = res.get("start", {}).get("line")
                # Ensure line is a number; if not available, default to 0
                line = int(line) if line is not None else 0
                message = res.get("extra", {}).get("message", "No message")
                risk = assess_risk(res)
                if risk == "Low":
                    logging.info(f"[SAFE] {anonymize_path(file_path) if anonymize else file_path} line {line}: {message}")
                else:
                    logging.warning(f"[VULN] {anonymize_path(file_path) if anonymize else file_path} line {line}: {message}")
                findings.append({
                    "file": anonymize_path(file_path) if anonymize else file_path,
                    "line": line,
                    "message": message,
                    "risk": risk,
                    "code": ""  # You can choose to add a code snippet here if needed
                })

        except Exception as e:
            logging.error(f"Error scanning {file_path}: {e}")
            continue

    if verbose:
        print("Read-only scan complete; no file modifications were performed.")
    return findings
