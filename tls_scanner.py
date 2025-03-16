import ssl
from OpenSSL import crypto
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def scan_tls_certificate(host, port=443):
    logging.info(f"Scanning TLS certificate on {host}:{port} ...")
    try:
        cert = ssl.get_server_certificate((host, port))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        algo = x509.get_signature_algorithm()
        if isinstance(algo, bytes):
            algo = algo.decode()
        key = x509.get_pubkey()
        key_bits = key.bits()
        risk = "Low"
        if "rsa" in algo.lower() and key_bits < 3072:
            risk = "High"
        message = f"{algo} with {key_bits} bits"
        return [{
            "file": "TLS",
            "line": 0,
            "message": message,
            "risk": risk,
            "code": ""
        }]
    except Exception as e:
        logging.error(f"Error scanning TLS certificate on {host}:{port} - {e}")
        return [{
            "file": "TLS",
            "line": 0,
            "message": f"Error scanning TLS certificate: {e}",
            "risk": "Unknown",
            "code": ""
        }]
