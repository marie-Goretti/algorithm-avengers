import os
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder

# --- Configuration ---
KEYS_DIR = ".keys"
PRIVATE_KEY_FILE = os.path.join(KEYS_DIR, "private.key")


def generate_keys():
    """Génère une nouvelle paire de clés Ed25519."""
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    return signing_key, verify_key


def save_keys(signing_key):
    """Sauvegarde la clé privée sur le disque."""
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(signing_key.encode(encoder=RawEncoder))
    print(f"Clés sauvegardées dans {KEYS_DIR}/")


def load_keys():
    """Charge la clé privée depuis le disque."""
    with open(PRIVATE_KEY_FILE, "rb") as f:
        raw_key = f.read()

    signing_key = SigningKey(raw_key, encoder=RawEncoder)
    return signing_key, signing_key.verify_key


def load_or_generate_keys():
    """Charge les clés existantes ou en génère de nouvelles."""
    if os.path.exists(PRIVATE_KEY_FILE):
        print("Clés existantes trouvées. Chargement...")
        return load_keys()
    else:
        print("Aucune clé trouvée. Génération d'une nouvelle identité...")
        sk, vk = generate_keys()
        save_keys(sk)
        return sk, vk


# --- Exemple d'utilisation ---
if __name__ == "__main__":
    node_id, public_key = load_or_generate_keys()
    print(f"Node ID (Public Key): {public_key.encode(encoder=RawEncoder).hex()}")
