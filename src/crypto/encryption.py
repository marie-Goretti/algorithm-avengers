import os
import hashlib
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.bindings import crypto_scalarmult
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF

from Crypto.Hash import SHA256

def get_shared_secret(my_priv_ecdh, peer_pub_ecdh):
    """
    Computes shared secret using X25519.
    """
    # my_priv_ecdh: PrivateKey object
    # peer_pub_ecdh: bytes[32]
    return crypto_scalarmult(my_priv_ecdh.encode(), peer_pub_ecdh)

def derive_session_key(shared_secret):
    """
    Derives a 32-byte session key from a shared secret using HKDF.
    """
    return HKDF(shared_secret, 32, b"archipel-v1", SHA256)

def encrypt_aes_gcm(key, plaintext):
    """
    Encrypts data using AES-256-GCM.
    Returns (nonce, ciphertext, tag).
    """
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

def decrypt_aes_gcm(key, nonce, ciphertext, tag):
    """
    Decrypts data using AES-256-GCM.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

class HandshakeState:
    def __init__(self, my_signing_key, is_initiator=True):
        self.my_signing_key = my_signing_key
        self.is_initiator = is_initiator
        self.ephemeral_priv = PrivateKey.generate()
        self.peer_ephemeral_pub = None
        self.shared_secret = None
        self.session_key = None
        
    def get_hello_payload(self):
        """
        Payload for HELLO (Alice -> Bob)
        """
        import time
        return {
            "e_pub": self.ephemeral_priv.public_key.encode().hex(),
            "timestamp": int(time.time() * 1000)
        }

    def respond_hello(self, hello_payload):
        """
        Payload for HELLO_REPLY (Bob -> Alice)
        """
        self.peer_ephemeral_pub = bytes.fromhex(hello_payload["e_pub"])
        
        # Bob generates his ephemeral key and signs it
        e_B_pub = self.ephemeral_priv.public_key.encode()
        sig_B = self.my_signing_key.sign(e_B_pub).signature
        
        # Calculate session key
        self.shared_secret = get_shared_secret(self.ephemeral_priv, self.peer_ephemeral_pub)
        self.session_key = derive_session_key(self.shared_secret)
        
        return {
            "e_pub": e_B_pub.hex(),
            "sig_B": sig_B.hex()
        }

    def process_hello_reply(self, reply_payload, peer_verify_key_hex):
        """
        Alice processes Bob's HELLO_REPLY.
        """
        e_B_pub = bytes.fromhex(reply_payload["e_pub"])
        sig_B = bytes.fromhex(reply_payload["sig_B"])
        
        # Verify Bob's identity
        peer_verify_key = VerifyKey(bytes.fromhex(peer_verify_key_hex))
        peer_verify_key.verify(e_B_pub, sig_B) # Throws exception if invalid
        
        self.peer_ephemeral_pub = e_B_pub
        self.shared_secret = get_shared_secret(self.ephemeral_priv, self.peer_ephemeral_pub)
        self.session_key = derive_session_key(self.shared_secret)
        
        # Alice now needs to send AUTH
        sig_A = self.my_signing_key.sign(self.shared_secret).signature
        return {"sig_A": sig_A.hex()}

    def process_auth(self, auth_payload, peer_verify_key_hex):
        """
        Bob processes Alice's AUTH.
        """
        sig_A = bytes.fromhex(auth_payload["sig_A"])
        peer_verify_key = VerifyKey(bytes.fromhex(peer_verify_key_hex))
        peer_verify_key.verify(self.shared_secret, sig_A) # Throws exception if invalid
        return True
