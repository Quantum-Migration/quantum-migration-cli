import os
import re
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def determine_config_risk(alg):
    high = ["RSA"]
    if alg.upper() in high:
        return "High"
    return "Low"

def scan_file(file_path):
    if os.path.basename(file_path) in ["pqc_rules.yml"]:
        return []
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        patterns = {
            "RSA": (r"\bRSA\b", ["hybrid RSA+Kyber", ">=3072"])
        }
        for alg, (pat, safe_indicators) in patterns.items():
            if re.search(pat, content, re.IGNORECASE):
                safe_found = any(safe in content for safe in safe_indicators)
                if not safe_found:
                    findings.append({
                        "file": file_path,
                        "line": 0,
                        "message": f"Found reference to {alg} in config.",
                        "risk": determine_config_risk(alg),
                        "code": ""
                    })
    except Exception as e:
        findings.append({
            "file": file_path,
            "line": 0,
            "message": f"Error: {e}",
            "risk": "Unknown",
            "code": ""
        })
    return findings

def scan_config_dir(path):
    findings = []
    config_exts = {".yml", ".yaml", ".json", ".ini", ".conf"}
    for root, _, files in os.walk(path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in config_exts:
                file_path = os.path.join(root, file)
                findings.extend(scan_file(file_path))
    return findings
