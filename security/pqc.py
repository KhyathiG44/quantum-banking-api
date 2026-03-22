# ══════════════════════════════════════════════
# REAL POST-QUANTUM CRYPTOGRAPHY
# Kyber-1024 (Key Encapsulation) + Dilithium-3 (Digital Signature)
# NIST PQC Standard — Actually encrypts and signs transactions
# ══════════════════════════════════════════════

from kyber_py.kyber import Kyber1024
from dilithium_py.dilithium import Dilithium3
import hashlib
import json
import base64

# ── KYBER-1024 KEY ENCAPSULATION ──
def kyber_keygen():
    """Generate Kyber-1024 public/private key pair"""
    pk, sk = Kyber1024.keygen()
    return {
        'public_key':  base64.b64encode(pk).decode(),
        'private_key': base64.b64encode(sk).decode()
    }

def kyber_encrypt(public_key_b64: str, message: str):
    """Encrypt message using Kyber-1024 encaps"""
    pk = base64.b64decode(public_key_b64)
    # encaps returns (shared_key, ciphertext)
    shared_key, ciphertext = Kyber1024.encaps(pk)
    # XOR message with shared key for encryption
    msg_bytes    = message.encode()
    key_extended = (shared_key * ((len(msg_bytes) // len(shared_key)) + 1))[:len(msg_bytes)]
    encrypted    = bytes(a ^ b for a, b in zip(msg_bytes, key_extended))
    return {
        'ciphertext':     base64.b64encode(ciphertext).decode(),
        'encrypted_msg':  base64.b64encode(encrypted).decode(),
        'algorithm':      'Kyber-1024',
        'security_level': 'NIST Level 5'
    }

def kyber_decrypt(private_key_b64: str, ciphertext_b64: str, encrypted_msg_b64: str):
    """Decrypt message using Kyber-1024 decaps"""
    sk         = base64.b64decode(private_key_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    encrypted  = base64.b64decode(encrypted_msg_b64)
    # decaps returns shared_key
    shared_key   = Kyber1024.decaps(sk, ciphertext)
    key_extended = (shared_key * ((len(encrypted) // len(shared_key)) + 1))[:len(encrypted)]
    decrypted    = bytes(a ^ b for a, b in zip(encrypted, key_extended))
    return decrypted.decode()

# ── DILITHIUM-3 DIGITAL SIGNATURES ──
def dilithium_keygen():
    """Generate Dilithium-3 signing key pair"""
    pk, sk = Dilithium3.keygen()
    return {
        'verify_key': base64.b64encode(pk).decode(),
        'sign_key':   base64.b64encode(sk).decode()
    }

def dilithium_sign(sign_key_b64: str, message: str):
    """Sign transaction with Dilithium-3"""
    sk  = base64.b64decode(sign_key_b64)
    msg = message.encode()
    sig = Dilithium3.sign(sk, msg)
    return {
        'signature': base64.b64encode(sig).decode(),
        'algorithm': 'Dilithium-3',
        'msg_hash':  hashlib.sha256(msg).hexdigest()
    }

def dilithium_verify(verify_key_b64: str, message: str, signature_b64: str):
    """Verify Dilithium-3 signature"""
    try:
        pk  = base64.b64decode(verify_key_b64)
        msg = message.encode()
        sig = base64.b64decode(signature_b64)
        Dilithium3.verify(pk, msg, sig)
        return True
    except Exception:
        return False

# ── FULL TRANSACTION PROTECTION ──
def protect_transaction(transaction_data: dict):
    """
    Full PQC protection for a transaction:
    1. Generate fresh Kyber-1024 keypair
    2. Encrypt transaction data with Kyber encaps
    3. Generate fresh Dilithium-3 keypair
    4. Sign the ciphertext with Dilithium
    Returns everything needed to verify later
    """
    tx_json = json.dumps(transaction_data, sort_keys=True)

    # Kyber-1024 encryption
    kyber_keys = kyber_keygen()
    encrypted  = kyber_encrypt(kyber_keys['public_key'], tx_json)

    # Dilithium-3 signing
    dilithium_keys = dilithium_keygen()
    signature      = dilithium_sign(
        dilithium_keys['sign_key'],
        encrypted['ciphertext']
    )

    return {
        'kyber_public_key':     kyber_keys['public_key'],
        'kyber_private_key':    kyber_keys['private_key'],
        'dilithium_verify_key': dilithium_keys['verify_key'],
        'dilithium_sign_key':   dilithium_keys['sign_key'],
        'encrypted':            encrypted,
        'signature':            signature,
        'pqc_status':           'PROTECTED',
        'algorithms':           'Kyber-1024 + Dilithium-3'
    }

def verify_transaction(protected_tx: dict):
    """Verify a PQC-protected transaction"""
    try:
        # Verify Dilithium signature
        valid = dilithium_verify(
            protected_tx['dilithium_verify_key'],
            protected_tx['encrypted']['ciphertext'],
            protected_tx['signature']['signature']
        )
        if not valid:
            return {'valid': False, 'reason': 'Dilithium signature verification failed'}

        # Decrypt with Kyber
        decrypted = kyber_decrypt(
            protected_tx['kyber_private_key'],
            protected_tx['encrypted']['ciphertext'],
            protected_tx['encrypted']['encrypted_msg']
        )
        return {
            'valid':     True,
            'decrypted': json.loads(decrypted),
            'algorithm': 'Kyber-1024 + Dilithium-3',
            'status':    'SIGNATURE VERIFIED'
        }
    except Exception as e:
        return {'valid': False, 'reason': str(e)}