import json
import socket
import struct

from src.network.packet import (
    Packet,
    TYPE_HANDSHAKE_HELLO,
    TYPE_HANDSHAKE_REPLY,
    TYPE_HANDSHAKE_AUTH,
    TYPE_HANDSHAKE_OK,
    TYPE_MSG,
)
from src.crypto.encryption import HandshakeState, encrypt_aes_gcm, decrypt_aes_gcm
from src.messaging.session import Session
from src.messaging.trust import TrustTable

# Taille du header Packet
_HEADER_SIZE = 41  # MAGIC(4) + TYPE(1) + NODE_ID(32) + PAYLOAD_LEN(4)


def _recv_exactly(sock, n):
    """Lit exactement n bytes depuis le socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def recv_packet(sock, timeout=15):
    """
    ✅ Lit un paquet Archipel COMPLET depuis le socket.
    Lit d'abord 41 bytes de header pour connaître PAYLOAD_LEN,
    puis lit exactement le reste. Évite les troncatures avec recv(4096).
    """
    sock.settimeout(timeout)
    try:
        header = _recv_exactly(sock, _HEADER_SIZE)
        if not header:
            return None
        if header[:4] != b"ARCP":
            return None

        payload_len = struct.unpack("!I", header[37:41])[0]
        if payload_len > 100 * 1024 * 1024:
            return None

        rest = _recv_exactly(sock, payload_len + 32)  # payload + HMAC
        if rest is None:
            return None

        return Packet.decode(header + rest)

    except socket.timeout:
        return None
    except Exception as e:
        print(f"[messaging] recv_packet error: {e}")
        return None


class MessagingManager:
    def __init__(self, node_id, signing_key, trust_table):
        self.node_id = node_id
        self.signing_key = signing_key
        self.trust_table = trust_table
        self.sessions = {}  # node_id_hex -> Session

    # ──────────────────────────────────────────────
    #  HANDSHAKE INITIATEUR (Alice)
    # ──────────────────────────────────────────────

    def initiate_handshake(self, target_ip, target_port, target_node_id_hex):
        print(f"[handshake] Initiation avec {target_node_id_hex[:8]}...")
        try:
            with socket.create_connection((target_ip, target_port), timeout=10) as sock:
                # 1. Envoyer HELLO
                hs = HandshakeState(self.signing_key, is_initiator=True)
                hello_payload = hs.get_hello_payload()
                packet = Packet(
                    TYPE_HANDSHAKE_HELLO,
                    self.node_id,
                    json.dumps(hello_payload).encode(),
                )
                sock.sendall(packet.encode())

                # 2. Recevoir HELLO_REPLY
                # ✅ recv_packet lit le paquet complet, pas juste 4096 bytes
                reply_pkt = recv_packet(sock)
                if not reply_pkt or reply_pkt.type != TYPE_HANDSHAKE_REPLY:
                    print(f"[handshake] Pas de HELLO_REPLY de {target_node_id_hex[:8]}")
                    return False

                reply_payload = json.loads(reply_pkt.payload.decode())
                peer_node_id = reply_pkt.node_id
                peer_node_id_hex = peer_node_id.hex()

                if not self.trust_table.check_and_save(peer_node_id_hex, peer_node_id):
                    print(f"[handshake] Trust refusé pour {peer_node_id_hex[:8]}")
                    return False

                # 3. Envoyer AUTH
                auth_payload = hs.process_hello_reply(reply_payload, peer_node_id_hex)
                auth_pkt = Packet(
                    TYPE_HANDSHAKE_AUTH, self.node_id, json.dumps(auth_payload).encode()
                )
                sock.sendall(auth_pkt.encode())

                # 4. Recevoir AUTH_OK
                ok_pkt = recv_packet(sock)
                if not ok_pkt or ok_pkt.type != TYPE_HANDSHAKE_OK:
                    print(f"[handshake] Pas de AUTH_OK de {target_node_id_hex[:8]}")
                    return False

                # Session établie
                self.sessions[target_node_id_hex] = Session(
                    target_node_id_hex, hs.session_key, hs.peer_ephemeral_pub
                )
                print(f"[handshake] ✓ Session établie avec {target_node_id_hex[:8]}")
                return True

        except Exception as e:
            print(f"[handshake] Échec avec {target_node_id_hex[:8]}: {e}")
            return False

    # ──────────────────────────────────────────────
    #  HANDSHAKE RÉPONDEUR (Bob)
    # ──────────────────────────────────────────────

    def handle_handshake_request(self, sock, first_packet):
        try:
            hello_payload = json.loads(first_packet.payload.decode())
            peer_node_id = first_packet.node_id
            peer_node_id_hex = peer_node_id.hex()

            if not self.trust_table.check_and_save(peer_node_id_hex, peer_node_id):
                print(f"[handshake] Trust refusé pour {peer_node_id_hex[:8]}")
                return False

            hs = HandshakeState(self.signing_key, is_initiator=False)
            reply_payload = hs.respond_hello(hello_payload)

            # Envoyer HELLO_REPLY
            reply_pkt = Packet(
                TYPE_HANDSHAKE_REPLY, self.node_id, json.dumps(reply_payload).encode()
            )
            sock.sendall(reply_pkt.encode())

            # Recevoir AUTH
            # ✅ recv_packet au lieu de recv(4096)
            auth_pkt = recv_packet(sock)
            if not auth_pkt or auth_pkt.type != TYPE_HANDSHAKE_AUTH:
                return False

            auth_payload = json.loads(auth_pkt.payload.decode())

            if hs.process_auth(auth_payload, peer_node_id_hex):
                # Envoyer AUTH_OK
                ok_pkt = Packet(TYPE_HANDSHAKE_OK, self.node_id, b"OK")
                sock.sendall(ok_pkt.encode())

                self.sessions[peer_node_id_hex] = Session(
                    peer_node_id_hex, hs.session_key, hs.peer_ephemeral_pub
                )
                print(f"[handshake] ✓ Session établie avec {peer_node_id_hex[:8]}")
                return True
            else:
                print(f"[handshake] AUTH invalide de {peer_node_id_hex[:8]}")
                return False

        except Exception as e:
            print(f"[handshake] Erreur handle_request: {e}")
            return False

    # ──────────────────────────────────────────────
    #  ENVOI DE MESSAGE CHIFFRÉ
    # ──────────────────────────────────────────────

    def send_encrypted_msg(self, target_node_id_hex, target_ip, target_port, message):
        # Établir session si nécessaire
        if target_node_id_hex not in self.sessions:
            if not self.initiate_handshake(target_ip, target_port, target_node_id_hex):
                return False

        session = self.sessions[target_node_id_hex]
        nonce, ciphertext, tag = encrypt_aes_gcm(session.session_key, message.encode())

        payload_data = {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex(),
        }
        packet = Packet(TYPE_MSG, self.node_id, json.dumps(payload_data).encode())

        try:
            with socket.create_connection((target_ip, target_port), timeout=10) as sock:
                sock.sendall(packet.encode())
            return True
        except Exception as e:
            print(f"[messaging] Échec envoi vers {target_node_id_hex[:8]}: {e}")
            return False

    # ──────────────────────────────────────────────
    #  DÉCHIFFREMENT MESSAGE ENTRANT
    # ──────────────────────────────────────────────

    def decrypt_msg(self, packet):
        sender_hex = packet.node_id.hex()
        if sender_hex not in self.sessions:
            print(f"[messaging] Pas de session pour {sender_hex[:8]} — message ignoré")
            return None

        session = self.sessions[sender_hex]
        try:
            payload = json.loads(packet.payload.decode())
            nonce = bytes.fromhex(payload["nonce"])
            ciphertext = bytes.fromhex(payload["ciphertext"])
            tag = bytes.fromhex(payload["tag"])
            plaintext = decrypt_aes_gcm(session.session_key, nonce, ciphertext, tag)
            return plaintext.decode() if plaintext else None
        except Exception as e:
            print(f"[messaging] Erreur déchiffrement: {e}")
            return None
