import threading
import time

# Imports de vos modules
from crypto.pki import load_or_generate_keys
from network.discovery import start_discovery_service
from network.transport import TcpServer
from core.file_manager import FileManager
from ui.cli import start_cli


def main():
    print("--- Démarrage du Nœud Archipel ---")
    # 1. Chargement de l'identité
    node_id, signing_key, verify_key = load_or_generate_keys()
    print(f"Node ID : {node_id.hex()}...")

    # 2. Initialisation du FileManager
    file_manager = FileManager()
    file_manager.index_files()

    from network.peer_table import PeerTable

    peer_table = PeerTable()

    # 3. Démarrage du Serveur TCP (Transport)
    server = TcpServer(node_id=node_id, port=0, peer_table=peer_table)
    server.signing_key = signing_key  # Port aléatoire
    tcp_thread = threading.Thread(target=server.start)
    tcp_thread.daemon = True
    tcp_thread.start()
    time.sleep(1)  # Laisse le temps au serveur de démarrer

    # 4. Démarrage de la découverte (UDP Broadcast)
    peer_table = start_discovery_service(node_id, server.port)

    # 5. Démarrage de l'interface CLI (avec Gemini)
    start_cli(node_id, peer_table, file_manager)

    print("Nœud prêt. tapez 'help' pour les commandes.")

    # Garder le main thread en vie
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArrêt du nœud.")


if __name__ == "__main__":
    main()
