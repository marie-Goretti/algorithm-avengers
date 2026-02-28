import asyncio
import json
import secrets
from dataclasses import dataclass
from typing import Dict, Optional
import nacl.secret
import nacl.utils
from nacl.signing import VerifyKey, SigningKey
from nacl.secret import SecretBox
from nacl.kx import SealedBox, Box, PrivateKey, PublicKey

from config import Config, PacketType, TLVType
from network.packet import ArchipelPacket
from network.peer_table import PeerTable
from network.tlv import encode_tlv, read_tlv
from core.file_manager import FileManager  # Import nécessaire


@dataclass
class PeerConnection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    node_id: Optional[str] = None
    authenticated: bool = False
    alive: bool = True
    box: Optional[SecretBox] = None  # Ajout du conteneur de chiffrement


class TCPServer:
    def __init__(self, node_id: bytes, port: int, peer_table: PeerTable):
        self.config = Config()
        self.node_id = node_id
        self.port = port
        self.peer_table = peer_table
        self.server: Optional[asyncio.AbstractServer] = None
        self.running = False
        self.connections: Dict[str, PeerConnection] = {}
        # ATTENTION: La clé de signature devrait être chargée, pas générée ici
        self.signing_key = SigningKey.generate()
        self.file_manager = FileManager()  # Initialisation

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_client,
            host="0.0.0.0",
            port=self.port,
            backlog=100,
        )
        self.running = True
        print(f"[TCP] listening on 0.0.0.0:{self.port}")
        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn = PeerConnection(reader=reader, writer=writer)

        try:
            # 1. Handshake Éphémère (X25519)
            ephemeral_key = PrivateKey.generate()
            writer.write(ephemeral_key.public_key.encode())
            await writer.drain()

            peer_public_bytes = await reader.readexactly(32)
            peer_public_key = PublicKey(peer_public_bytes)

            shared_key = ephemeral_key.shared_key(peer_public_key)

            # Initialiser chiffrement symétrique (AES-GCM)
            conn.box = SecretBox(shared_key)
            print("[🔐] Tunnel chiffré établi.")

            # 2. Authentification (Ed25519)
            writer.write(self.signing_key.verify_key.encode())
            await writer.drain()

            peer_identity_bytes = await reader.readexactly(32)
            peer_verify_key = VerifyKey(peer_identity_bytes)

            # Vérifier signature challenge
            signature = await reader.readexactly(64)
            peer_verify_key.verify(shared_key, signature)

            # Envoyer notre signature
            my_signature = self.signing_key.sign(shared_key).signature
            writer.write(my_signature)
            await writer.drain()

            conn.authenticated = True
            print(f"[✅] Pair authentifié : {peer_identity_bytes.hex()[:12]}")

        except Exception as e:
            print(f"[❌] Échec authentification : {e}")
            writer.close()
            return

        keepalive_task = asyncio.create_task(self._keepalive_loop(conn))

        try:
            while self.running:
                tlv_type, value = await read_tlv(reader)

                # --- DÉCHIFFREMENT DES DONNÉES APPLICATIVES ---
                if conn.box and tlv_type in [TLVType.PACKET, TLVType.CHUNK_DATA]:
                    value = conn.box.decrypt(value)

                await self._on_tlv(conn, tlv_type, value)

        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as e:
            print(f"Erreur connexion : {e}")
        finally:
            keepalive_task.cancel()
            conn.alive = False
            writer.close()
            await writer.wait_closed()
            if conn.node_id and conn.node_id in self.connections:
                del self.connections[conn.node_id]

    async def _on_tlv(self, conn: PeerConnection, tlv_type: int, value: bytes) -> None:
        if tlv_type == TLVType.PING:
            conn.writer.write(encode_tlv(TLVType.PONG, b"pong"))
            await conn.writer.drain()
            return

        # --- GESTION CHUNKING ---
        if tlv_type == TLVType.REQUEST_CHUNK:
            chunk_hash = value.decode("utf-8")
            chunk_data = self.file_manager.get_chunk(chunk_hash)

            if chunk_data and conn.box:
                # Chiffrer avant envoi
                encrypted_chunk = conn.box.encrypt(chunk_data)
                conn.writer.write(encode_tlv(TLVType.CHUNK_DATA, encrypted_chunk))
                await conn.writer.drain()
            return

        if tlv_type != TLVType.PACKET:
            return

        # ... (reste de la logique Packet)
