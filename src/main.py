import threading
import time
import asyncio  # Corrigé: Import nécessaire

# Imports de vos modules
from crypto.keys import load_or_generate_keys
from network.discovery import DiscoveryService
from core.file_manager import FileManager
from ui.cli import start_cli
from network.transport import TcpServer  # Corrigé: Import manquant
from network.peer_table import PeerTable  # Corrigé: Import ici


async def main():
    print("--- Démarrage du Nœud Archipel ---")

    # 1. Chargement de l'identité
    # Corrigé: load_or_generate_keys retourne (signing_key, verify_key)
    signing_key, verify_key = load_or_generate_keys()
    # node_id est généralement la clé publique ou son hash
    node_id = verify_key.encode()
    print(f"Node ID : {node_id.hex()[:8]}...")

    # 2. Initialisation du FileManager
    file_manager = FileManager()
    file_manager.index_files()

    peer_table = PeerTable()

    # 3. Démarrage du Serveur TCP (Transport)
    # Corrigé: Passage de la signing_key ici
    server = TcpServer(
        node_id=node_id, port=0, peer_table=peer_table, signing_key=signing_key
    )

    def start_async_loop(loop, coro):
        asyncio.set_event_loop(loop)
        loop.run_until_complete(coro)

    new_loop = asyncio.new_event_loop()
    tcp_thread = threading.Thread(
        target=start_async_loop, args=(new_loop, server.start()), daemon=True
    )

    tcp_thread.start()

    # Attente active que le serveur ouvre son port
    while server.port == 0:
        await asyncio.sleep(0.1)
    print(f"[Main] Serveur TCP démarré sur le port {server.port}")
    # Attente active que le serveur ouvre son port

    # 4. Démarrage de la découverte (UDP Broadcast)
    service = DiscoveryService(node_id, server.port, peer_table)
    await service.start()

    # 5. Démarrage de l'interface CLI (avec Gemini)
    # Corrigé: Passage de asyncio.get_running_loop() et de signing_key
    start_cli(
        node_id,
        peer_table,
        file_manager,
        loop=asyncio.get_running_loop(),
        signing_key=signing_key,
    )

    print("Nœud prêt. tapez 'help' pour les commandes.")

    # Garder le main thread en vie
    try:
        while True:
            await asyncio.sleep(1)  # Corrigé: sleep async
    except KeyboardInterrupt:
        print("\nArrêt du nœud.")


if __name__ == "__main__":
    # Corrigé: Utilisation de asyncio.run
    asyncio.run(main())
