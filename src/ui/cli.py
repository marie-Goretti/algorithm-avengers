import threading
import sys
import asyncio

# NOUVEAU: Import nécessaire pour la clé de signature
from nacl.signing import SigningKey
from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import VerifyKey
from ai.gemini_integration import get_file_summary
from config import TLVType
from network.tlv import encode_tlv, read_tlv
from network.packet import PacketBuilder
from config import PacketType

# Supposons que vous ayez une classe de gestionnaire de fichiers
# from src.core.file_manager import FileManager


# CORRECTION: Ajout de signing_key ici
def start_cli(node_id, peer_table, file_manager, loop, signing_key: SigningKey):
    """Lance l'interface en ligne de commande dans un thread séparé."""

    def cli_loop():
        print("\n--- Archipel CLI (tape 'help' pour la liste) ---")
        while True:
            try:
                command = input("> ").strip().split()
                if not command:
                    continue

                cmd = command[0]

                if cmd == "help":
                    print(
                        "Commandes : help, peers, list_files, summary <filename>, get_file <filename> <peer_id>"
                    )

                elif cmd == "peers":
                    print(f"Pairs actifs : {len(peer_table.peers)}")
                    for nid, info in peer_table.peers.items():
                        # Nid peut être str ou bytes selon votre implémentation de peer_table
                        nid_hex = nid.hex() if isinstance(nid, bytes) else nid
                        print(f" - {nid_hex[:8]} : {info['ip']}:{info['tcp_port']}")

                elif cmd == "list_files":
                    file_manager.index_files()
                    print("📂 Fichiers locaux :")
                    # Corrigé: file_index -> shared_files
                    for fname in file_manager.shared_files:
                        print(f" - {fname}")

                elif cmd == "summary" and len(command) > 1:
                    filename = command[1]
                    print(f"Gemini analyse le fichier {filename}...")
                    content = file_manager.get_file_content(filename)
                    if content:
                        summary = get_file_summary(content)
                        print(f"Résumé par Gemini: {summary}")
                    else:
                        print("Fichier non trouvé.")

                # --- COMMANDE SPRINT 3 ---
                elif cmd == "get_file" and len(command) > 2:
                    filename = command[1]
                    peer_id_hex = command[2]
                    print(
                        f"Début du téléchargement de {filename} depuis {peer_id_hex[:8]}..."
                    )
                    # Lancer la coroutine async sans bloquer la CLI
                    asyncio.run_coroutine_threadsafe(
                        get_file_async(filename, peer_id_hex), loop
                    )
                # -------------------------

            except Exception as e:
                print(f"Erreur CLI : {e}")

    # --- MÉTHODE ASYNC CORRIGÉE ---
    async def get_file_async(filename, peer_node_id_hex):
        """Demande et assemble un fichier depuis un pair (Async)."""
        peer_info = peer_table.peers.get(peer_node_id_hex)
        if not peer_info:
            print(f"Pair inconnu : {peer_node_id_hex[:8]}")
            return

        try:
            # 1. Connexion au pair
            reader, writer = await asyncio.open_connection(
                peer_info["ip"], peer_info["tcp_port"]
            )

            # HANDSHAKE SÉCURISÉ (SPRINT 2)

            # 1. Générer clé éphémère pour ce téléchargement
            ephemeral = PrivateKey.generate()

            # 2. Envoyer notre clé publique éphémère
            writer.write(ephemeral.public_key.encode())
            await writer.drain()

            # 3. Recevoir la clé publique éphémère du pair
            peer_public_bytes = await reader.readexactly(32)
            peer_public_key = PublicKey(peer_public_bytes)

            # 4. Calculer le Shared Secret
            shared_key = ephemeral.shared_key(peer_public_key)

            # Initialiser le chiffrement symétrique (AES-GCM)
            box = SecretBox(shared_key)

            # 5. Authentification (Ed25519)
            # A. Recevoir la clé publique d'identité du pair
            peer_identity_bytes = await reader.readexactly(32)
            peer_verify_key = VerifyKey(peer_identity_bytes)

            # B. Recevoir la signature du pair
            signature = await reader.readexactly(64)
            # Vérifier que le pair possède la clé privée correspondant à peer_verify_key
            peer_verify_key.verify(shared_key, signature)

            # C. Envoyer notre propre signature
            my_signature = signing_key.sign(shared_key).signature
            writer.write(my_signature)
            await writer.drain()

            print(f"Tunnel chiffré et authentifié avec {peer_node_id_hex[:8]}")
            print(f"Connecté. Demande des chunks pour {filename}...")

            # 2. Demander la liste des chunks (nécessite un nouveau PacketType/TLVType)
            # ... (Logique pour envoyer REQUEST_CHUNK_LIST) ...

            # Exemple fictif : on reçoit une liste de hashes
            chunk_hashes = ["hash1", "hash2"]

            full_file_data = b""
            for ch_hash in chunk_hashes:
                print(f"Téléchargement du chunk : {ch_hash[:8]}...")

                # 3. Envoyer REQUEST_CHUNK (chiffré si votre protocole l'exige)
                request = encode_tlv(TLVType.REQUEST_CHUNK, ch_hash.encode())
                writer.write(request)
                await writer.drain()

                # 4. Attendre CHUNK_DATA
                tlv_type, value = await read_tlv(reader)
                if tlv_type == TLVType.CHUNK_DATA:
                    # --- SPRINT 2 : Déchiffrement ici ---
                    decrypted_chunk = box.decrypt(value)
                    # ------------------------------------
                    full_file_data += decrypted_chunk
                else:
                    print(f"Erreur réception chunk {ch_hash[:8]}")
                    break

            # 5. Sauvegarder le fichier final
            file_manager.save_file(filename, full_file_data)
            print(f"Fichier {filename} téléchargé avec succès.")
            writer.close()
            await writer.wait_closed()

        except Exception as e:
            print(f"Échec téléchargement : {e}")

    # Lancement du thread CLI
    cli_thread = threading.Thread(target=cli_loop, daemon=True)
    cli_thread.start()

