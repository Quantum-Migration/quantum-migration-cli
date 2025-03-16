#!/usr/bin/env python3
import rsa

def test_rsa_usage():
    # Generate RSA keys (expected to be flagged)
    public_key, private_key = rsa.newkeys(1024)

    # Encrypt a message (expected to be flagged)
    message = b"Test message for RSA."
    encrypted = rsa.encrypt(message, public_key)

    # Decrypt the message (expected to be flagged)
    decrypted = rsa.decrypt(encrypted, private_key)
    print("Decrypted:", decrypted)

    # Sign the message (expected to be flagged)
    signature = rsa.sign(message, private_key, 'SHA-1')

    # Verify the signature (expected to be flagged)
    try:
        rsa.verify(message, signature, public_key)
        print("Signature verified.")
    except Exception as e:
        print("Verification failed:", e)

if __name__ == "__main__":
    test_rsa_usage()
