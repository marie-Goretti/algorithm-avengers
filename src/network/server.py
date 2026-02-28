import socket
import threading
import json
import os
import struct

from src.network.packet import (
    Packet,
    TYPE_PEER_LIST,
    TYPE_HANDSHAKE_HELLO,
    TYPE_MSG,
    TYPE_CHUNK_REQ,
    TYPE_MANIFEST,
)

# Dossier manifests/ à la racine du projet
_ROOT = os.getcwd()
_MANIFESTS = os.path.join(_ROOT, "manifests")

# Taille du header Packet : MAGIC(4) + TYPE(1) + NODE_ID(32) + PAYLOAD_LEN(4) = 41 bytes
_HEADER_SIZE = 41


def recv_packet(sock, timeout=30):
    """
    ✅ Lit un paquet complet depuis le socket.

    Protocole : MAGIC(4) | TYPE(1) | NODE_ID(32) | PAYLOAD_LEN(4) | PAYLOAD(var) | HMAC(32)

    On lit d'abord les 41 bytes de header pour connaître PAYLOAD_LEN,
    puis on lit exactement PAYLOAD_LEN + 32 bytes supplémentaires.
    Ça évite le bug où recv(4096) tronque les gros paquets.
    """
    sock.settimeout(timeout)
    try:
        # 1. Lire le header complet (41 bytes)
        header = _recv_exactly(sock, _HEADER_SIZE)
        if not header or len(header) < _HEADER_SIZE:
            return None

        # 2. Vérifier le magic
        if header[:4] != b"ARCP":
            return None

        # 3. Lire PAYLOAD_LEN depuis les 4 derniers bytes du header
        payload_len = struct.unpack("!I", header[37:41])[0]

        # Sanité — refuser les paquets absurdement grands (> 100 MB)
        if payload_len > 100 * 1024 * 1024:
            print(f"[server] Paquet trop grand : {payload_len} bytes — rejeté")
            return None

        # 4. Lire payload + HMAC (32 bytes)
        rest = _recv_exactly(sock, payload_len + 32)
        if rest is None:
            return None

        # 5. Décoder le paquet complet
        full_data = header + rest
        return Packet.decode(full_data)

    except socket.timeout:
        print("[server] recv_packet timeout")
        return None
    except Exception as e:
        print(f"[server] recv_packet error: {e}")
        return None


def _recv_exactly(sock, n):
    """Lit exactement n bytes depuis le socket."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        except Exception:
            return None
    return bytes(buf)


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
        print(f"[server] TCP en écoute sur le port {self.port}")
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
                    print(f"[server] Erreur accept: {e}")

    def _handle_connection(self, conn, addr):
        try:
            # ✅ FIX PRINCIPAL : recv_packet lit le paquet COMPLET
            # L'ancien conn.recv(4096) tronquait les gros paquets (chunks > 4KB)
            packet = recv_packet(conn)
            if not packet:
                conn.close()
                return

            # ── PEER_LIST ──────────────────────────────────
            if packet.type == TYPE_PEER_LIST:
                self._process_peer_list(packet, addr[0])
                conn.close()

            # ── HANDSHAKE ──────────────────────────────────
            elif packet.type == TYPE_HANDSHAKE_HELLO:
                if self.messaging_manager:
                    self.messaging_manager.handle_handshake_request(conn, packet)
                # Le handshake ferme sa propre connexion

            # ── MESSAGE CHIFFRÉ ────────────────────────────
            elif packet.type == TYPE_MSG:
                if self.messaging_manager:
                    plaintext = self.messaging_manager.decrypt_msg(packet)
                    if plaintext:
                        if plaintext.startswith("MANIFEST:"):
                            self._save_manifest(
                                json.loads(plaintext[9:]), packet.node_id.hex()
                            )
                        else:
                            msg_text = f"from {packet.node_id.hex()[:8]}: {plaintext}"
                            print(f"\n[MSG] {msg_text}")
                            if self.web_queue:
                                self.web_queue.put(msg_text)
                conn.close()

            # ── CHUNK REQUEST ──────────────────────────────
            elif packet.type == TYPE_CHUNK_REQ:
                if self.transfer_manager:
                    # On passe recv_packet pour que handle_chunk_request
                    # puisse aussi lire des paquets complets si besoin
                    self.transfer_manager.handle_chunk_request(packet, conn)
                conn.close()

            # ── MANIFEST (socket brut) ─────────────────────
            elif packet.type == TYPE_MANIFEST:
                try:
                    manifest = json.loads(packet.payload.decode("utf-8"))
                    self._save_manifest(manifest, packet.node_id.hex())
                except Exception as e:
                    print(f"[server] Erreur parsing manifest: {e}")
                conn.close()

            else:
                conn.close()

        except Exception as e:
            try:
                conn.close()
            except Exception:
                pass

    # ──────────────────────────────────────────────
    #  HELPERS
    # ──────────────────────────────────────────────

    def _process_peer_list(self, packet, sender_ip):
        try:
            peer_list = json.loads(packet.payload.decode())
            for node_id_hex, data in peer_list.items():
                if node_id_hex != self.node_id.hex():
                    self.peer_table.upsert(node_id_hex, data["ip"], data["tcp_port"])
        except Exception as e:
            print(f"[server] Erreur peer list: {e}")

    def _save_manifest(self, manifest: dict, sender_hex: str):
        """Sauvegarde un manifest reçu dans manifests/ pour téléchargement ultérieur."""
        try:
            os.makedirs(_MANIFESTS, exist_ok=True)

            filename = manifest.get("filename", "unknown")
            file_id = manifest.get("file_id", "unknown")
            base_name = os.path.splitext(filename)[0]  # retire .py .pdf etc.

            manifest_fname = f"{base_name}_{file_id[:8]}.json"
            manifest_path = os.path.join(_MANIFESTS, manifest_fname)

            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2, ensure_ascii=False)

            print(
                f"\n[MANIFEST] Reçu de {sender_hex[:8]} : {filename} "
                f"({manifest.get('size', 0)} bytes, {manifest.get('nb_chunks', 0)} chunk(s))"
            )
            print(f"[MANIFEST] Sauvegardé : {manifest_path}")

            if self.web_queue:
                self.web_queue.put(
                    f"from {sender_hex[:8]}: "
                    f"[Fichier disponible] {filename} — "
                    f"clique Download dans l'interface web"
                )

        except Exception as e:
            print(f"[server] Erreur save_manifest: {e}")

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
