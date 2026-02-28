import socket
import threading
import json
import os
import sys
from src.network.packet import (
    Packet,
    TYPE_PEER_LIST,
    TYPE_HANDSHAKE_HELLO,
    TYPE_MSG,
    TYPE_CHUNK_REQ,
    TYPE_MANIFEST,
)

# Dossier manifests/ à la racine du projet
_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MANIFESTS = os.path.normpath(os.path.join(_ROOT, "manifests"))


class TCPServer:
    def __init__(
        self,
        node_id,
        port,
        peer_table,
        messaging_manager=None,
        transfer_manager=None,
        web_queue=None,
    ):
        self.node_id = node_id
        self.port = port
        self.peer_table = peer_table
        self.messaging_manager = messaging_manager
        self.transfer_manager = transfer_manager
        self.web_queue = web_queue
        self.running = False
        self.server_sock = None

    def start(self):
        self.running = True
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("0.0.0.0", self.port))
        self.server_sock.listen(10)
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.server_sock.accept()
                threading.Thread(
                    target=self._handle_connection, args=(conn, addr), daemon=True
                ).start()
            except Exception as e:
                if self.running:
                    print(f"[server] Error accepting: {e}")

    def _handle_connection(self, conn, addr):
        try:
            data = conn.recv(65536)
            if not data:
                return

            packet = Packet.decode(data)
            if not packet:
                return

            # ── PEER_LIST ──────────────────────────────
            if packet.type == TYPE_PEER_LIST:
                self._process_peer_list(packet, addr[0])
                conn.close()

            # ── HANDSHAKE ──────────────────────────────
            elif packet.type == TYPE_HANDSHAKE_HELLO:
                if self.messaging_manager:
                    self.messaging_manager.handle_handshake_request(conn, packet)

            # ── MESSAGE CHIFFRÉ ────────────────────────
            elif packet.type == TYPE_MSG:
                if self.messaging_manager:
                    plaintext = self.messaging_manager.decrypt_msg(packet)
                    if plaintext:
                        # ✅ Détecter si c'est un manifest envoyé via messaging
                        if plaintext.startswith("MANIFEST:"):
                            self._process_manifest_from_msg(
                                plaintext[9:],  # retirer le préfixe
                                packet.node_id.hex(),
                            )
                        else:
                            msg_text = f"from {packet.node_id.hex()[:8]}: {plaintext}"
                            print(f"\n[MSG] {msg_text}")
                            if self.web_queue:
                                self.web_queue.put(msg_text)
                conn.close()

            # ── CHUNK REQUEST ──────────────────────────
            elif packet.type == TYPE_CHUNK_REQ:
                if self.transfer_manager:
                    self.transfer_manager.handle_chunk_request(packet, conn)
                conn.close()

            # ── MANIFEST (socket brut — fallback) ──────
            elif packet.type == TYPE_MANIFEST:
                try:
                    manifest = json.loads(packet.payload.decode("utf-8"))
                    self._save_manifest(manifest, packet.node_id.hex())
                except Exception as e:
                    print(f"[server] Error parsing manifest: {e}")
                conn.close()

            else:
                conn.close()

        except Exception as e:
            pass  # connexion fermée, etc.

    def _process_peer_list(self, packet, sender_ip):
        try:
            peer_list = json.loads(packet.payload.decode())
            for node_id_hex, data in peer_list.items():
                if node_id_hex != self.node_id.hex():
                    self.peer_table.upsert(node_id_hex, data["ip"], data["tcp_port"])
        except Exception as e:
            print(f"[server] Error processing peer list: {e}")

    def _process_manifest_from_msg(self, manifest_json: str, sender_hex: str):
        """
        Traite un manifest reçu via message chiffré (préfixe MANIFEST:).
        """
        try:
            manifest = json.loads(manifest_json)
            self._save_manifest(manifest, sender_hex)
        except Exception as e:
            print(f"[server] Error parsing manifest from msg: {e}")

    def _save_manifest(self, manifest: dict, sender_hex: str):
        """
        Sauvegarde un manifest reçu dans manifests/ pour que
        l'interface web puisse l'afficher et proposer le téléchargement.
        """
        try:
            os.makedirs(_MANIFESTS, exist_ok=True)

            filename = manifest.get("filename", "unknown")
            file_id = manifest.get("file_id", "unknown")

            # ✅ Retirer l'extension du fichier source pour le nom du manifest
            base_name = os.path.splitext(filename)[0]
            manifest_fname = f"{base_name}_{file_id[:8]}.json"
            manifest_path = os.path.normpath(os.path.join(_MANIFESTS, manifest_fname))

            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2, ensure_ascii=False)

            print(
                f"\n[MANIFEST] Reçu de {sender_hex[:8]} : {filename} "
                f"({manifest.get('size', 0)} bytes, {manifest.get('nb_chunks', 0)} chunks)"
            )
            print(f"[MANIFEST] Sauvegardé : {manifest_path}")

            # Notifier l'interface web
            if self.web_queue:
                self.web_queue.put(
                    f"from {sender_hex[:8]}: "
                    f"[Fichier disponible] {filename} — "
                    f"téléchargeable depuis l'interface web"
                )

        except Exception as e:
            print(f"[server] Error saving manifest: {e}")

    def stop(self):
        self.running = False
        if self.server_sock:
            self.server_sock.close()


def send_peer_list(target_ip, target_port, my_node_id, peer_table):
    try:
        with socket.create_connection((target_ip, target_port), timeout=5) as sock:
            from src.network.packet import Packet, TYPE_PEER_LIST

            payload = json.dumps(peer_table.get_peers()).encode()
            packet = Packet(TYPE_PEER_LIST, my_node_id, payload)
            sock.sendall(packet.encode())
    except Exception:
        pass
