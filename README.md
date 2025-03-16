# Quantum Migration CLI Tool

Quantum Migration is an automated post‑quantum cryptography migration platform. This CLI tool scans your codebase for insecure RSA usage and automatically refactors RSA operations into production‑ready PQC (post‑quantum cryptography) calls using the oqs library (Kyber512 for encryption and Dilithium2 for signing). It also triggers automatic key reissuance when vulnerabilities are found.

---

## Overview

- **RSA Refactoring:**  
  The tool detects RSA usage (via Semgrep rules and additional text scanning) and transforms RSA calls (e.g., `rsa.newkeys`, `rsa.encrypt`, `rsa.decrypt`, `rsa.sign`, and `rsa.verify`) into PQC functions (e.g., `oqs_generate_keypair`, `oqs_encrypt`, `oqs_decrypt`, `oqs_sign`, `oqs_verify`).

- **Hybrid Encryption Scheme:**  
  The refactored code implements a hybrid encryption scheme. Kyber512 is used for key encapsulation and AES‑GCM secures the actual message encryption.

- **Key Reissuance:**  
  When RSA vulnerabilities are found, new PQC keys are automatically generated (using `oqs.KEM("Kyber512")`) and stored securely. This process follows production‑ready practices using the latest pyoqs API (v1.0.0+).

- **Complete Logging:**  
  The scanner logs every occurrence of “rsa” (via Semgrep and a manual text scan) so that you can verify that no RSA usage is missed.

---

## Requirements

- Python 3.7+
- pyoqs (version 1.0.0 or later)
- Cryptography (for AES‑GCM)
- Semgrep
- Additional Python libraries: click, rich, pyyaml, jinja2, etc.

---

## Setup

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/yourusername/quantum-migration-cli.git
    cd quantum-migration-cli
    ```

2. **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    Ensure that your `requirements.txt` includes:
            click
            rich
            pyOpenSSL
            semgrep
            rsa
            pyyaml
            jinja2
            weasyprint
            oqs
            astunparse
            flask
            tqdm
            pytest
            requests
3. **Configuration:**
    Run the interactive configuration command to generate a configuration file:
    ```bash
    python3 cli.py configure
    ```
    This command creates or updates `config.yml` with scan settings, including:
    - The root directory to scan.
    - Include/exclude patterns.
    - Dry-run and verbose options.

---

## Usage

### 1. Scanning for RSA Usage

Run the following command to scan your codebase for RSA vulnerabilities. The tool uses Semgrep rules (defined in `rsa_rules.yml`) and an additional text scan to log every occurrence of “rsa”:

```bash
python3 cli.py scan_code --path <directory_path> [--output-format rich]
