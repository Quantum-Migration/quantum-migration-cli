#!/usr/bin/env python3
import os
import json
import datetime
import oqs  # Requires pyoqs version 1.0.0 or later (using oqs.KEM)

KEYS_DIR = "keys"

def reissue_keys():
    """
    Generate new PQC keys using oqs for Kyber512 and store them securely.
    
    This function uses the real PQC library oqs to generate a Kyber512 keypair.
    The keys are written to a JSON file in the KEYS_DIR directory with a timestamp.
    
    NOTE: This syntax requires pyoqs version 1.0.0 or later (using oqs.KEM).
    """
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR, exist_ok=True)
    try:
        kem = oqs.KEM("Kyber512")
        public_key, private_key = kem.generate_keypair()
        pub_hex = public_key.hex()
        priv_hex = private_key.hex()
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        key_data = {
            "public_key": pub_hex,
            "private_key": priv_hex,
            "issued_at": timestamp
        }
        key_file = os.path.join(KEYS_DIR, f"pqc_keys_{timestamp}.json")
        with open(key_file, "w", encoding="utf-8") as f:
            json.dump(key_data, f, indent=2)
        print("New PQC keys generated and stored in", key_file)
    except Exception as e:
        print("Error generating PQC keys:", e)
