import os
from nacl.signing import SigningKey
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

def generate_pki_keys():
    """Génère et sauvegarde la paire de clés Ed25519 pour Archipel."""
    
    # Génération de la paire de clés (Privée et Publique)
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    # Chemin des fichiers de clés
    private_key_path = ".keys/private.key"
    public_key_path = ".keys/public.key"

    # Créer le dossier keys s'il n'existe pas
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)

    # Sauvegarde de la clé privée (à ne jamais partager)
    with open(private_key_path, "wb") as f:
        f.write(signing_key.encode())
    
    # Sauvegarde de la clé publique (votre Node ID, à partager via HELLO)
    with open(public_key_path, "wb") as f:
        f.write(verify_key.encode())

    print(f"Clés PKI générées avec succès !")
    print(f"Node ID (Clé Publique) : {verify_key.encode().hex()}")
    print(f"Clé privée sauvegardée dans : {private_key_path}")
    print(f"NE PARTAGEZ JAMAIS LA CLÉ PRIVÉE.")

if __name__ == "__main__":
    generate_pki_keys()