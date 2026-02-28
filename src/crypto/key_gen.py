import os
from nacl.signing import SigningKey
from nacl.public import PrivateKey

def generate_and_save_keys(node_name="node"):
    """
    Generates Ed25519 keys for signing and X25519 for encryption.
    Saves them to .key files.
    """
    # Ed25519 for Identity and Signing
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    # Save signing key (private)
    with open(f"{node_name}_signing.key", "wb") as f:
        f.write(signing_key.encode())
        
    # Save verify key (public)
    with open(f"{node_name}_verify.key", "wb") as f:
        f.write(verify_key.encode())
        
    # X25519 for ECDH (Encryption)
    # Note: For Noise-like protocol, we'll generate these when needed, 
    # but having a permanent identity key is required.
    
    print(f"Keys generated for {node_name}")
    print(f"Public ID (Hex): {verify_key.encode().hex()}")
    return verify_key.encode().hex()

if __name__ == "__main__":
    generate_and_save_keys()
