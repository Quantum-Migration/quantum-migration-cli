#!/usr/bin/env python3
import oqs
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# The following implements a hybrid encryption scheme using Kyber512 (for KEM) and AES-GCM (for symmetric encryption).
# This requires pyoqs version 1.0.0+ and the cryptography package.

def oqs_generate_keypair(dummy_size=None):
    """
    Generate a Kyber512 keypair using oqs.
    The dummy_size parameter is ignored since Kyber512 has fixed key sizes.
    Returns (public_key, private_key) as bytes.
    """
    kem = oqs.KEM("Kyber512")
    public_key, private_key = kem.generate_keypair()
    return public_key, private_key

def oqs_encrypt(message, public_key):
    """
    Encrypt a message using a hybrid scheme:
      1. Encapsulate using Kyber512 to obtain (ct, ss) [shared secret].
      2. Derive a 256-bit AES key from ss via SHA-256.
      3. Encrypt the message using AES-GCM.
    Returns a dict with 'ct_kem', 'nonce', and 'ct_aes'.
    
    NOTE: In a full production system, the KEM API should accept the provided public key.
    """
    kem = oqs.KEM("Kyber512")
    ct, ss = kem.encapsulate(public_key)
    key = hashlib.sha256(ss).digest()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_aes = aesgcm.encrypt(nonce, message, None)
    return {
        "ct_kem": ct,
        "nonce": nonce,
        "ct_aes": ct_aes
    }

def oqs_decrypt(encrypted, private_key):
    """
    Decrypt a message using the hybrid scheme:
      1. Decapsulate using Kyber512 with private_key and ct_kem to recover ss.
      2. Derive the AES key from ss.
      3. Decrypt the AES-GCM ciphertext using the nonce.
    Returns the original plaintext message.
    """
    kem = oqs.KEM("Kyber512")
    ss = kem.decapsulate(encrypted["ct_kem"], private_key)
    key = hashlib.sha256(ss).digest()
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(encrypted["nonce"], encrypted["ct_aes"], None)
    return plaintext

def oqs_sign(message, private_key, hash_algo="SHA-256"):
    """
    Sign a message using the Dilithium2 signature scheme.
    For production use, generate a separate Dilithium2 keypair.
    This function requires that pyoqs supports the Signature API.
    """
    sig_scheme = "Dilithium2"
    with oqs.Signature(sig_scheme) as signer:
        signature = signer.sign(message, private_key)
    return signature

def oqs_verify(message, signature, public_key):
    """
    Verify a message signature using the Dilithium2 signature scheme.
    This function requires that pyoqs supports the Signature API.
    """
    sig_scheme = "Dilithium2"
    with oqs.Signature(sig_scheme) as verifier:
        if not verifier.verify(message, signature, public_key):
            raise ValueError("Signature verification failed")
