import asyncio
import secrets
from dataclasses import dataclass
from typing import Dict, Optional
from nacl.public import Box, PrivateKey, PublicKey
import nacl.secret
import nacl.utils
from nacl.signing import SigningKey, VerifyKey
from nacl.secret import SecretBox

from config import Config, PacketType, TLVType
from network.peer_table import PeerTable
from network.tlv import encode_tlv, read_tlv
from core.file_manager import FileManager


@dataclass
class PeerConnection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    node_id: Optional[str] = None
    authenticated: bool = False
    alive: bool = True
    box: Optional[SecretBox] = None  # Pour le chiffrement symétrique


class TcpServer:
    def __init__(
        self, node_id: bytes, port: int, peer_table: PeerTable, signing_key: SigningKey
    ):
        self.config = Config()
        self.node_id = node_id
        self.port = port
        self.peer_table = peer_table
        self.signing_key = signing_key  # Clé Ed25519 pour auth
        self.server: Optional[asyncio.AbstractServer] = None
        self.running = False
        self.connections: Dict[str, PeerConnection] = {}
        self.file_manager = FileManager()

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_client,
            host="0.0.0.0",
            port=self.port,
            backlog=100,
        )
        self.port = self.server.sockets[0].getsockname()[1]
        self.running = True
        print(f"[TCP] listening on 0.0.0.0:{self.port}")
        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn = PeerConnection(reader=reader, writer=writer)

        # HANDSHAKE X25519 & AUTH Ed25519
        try:
            # 1. Échange de clés éphémères (Handshake X25519)
            ephemeral = PrivateKey.generate()
            writer.write(ephemeral.public_key.encode())
            await writer.drain()

            peer_public_bytes = await reader.readexactly(32)
            peer_public_key = PublicKey(peer_public_bytes)
            shared_key = Box(ephemeral, peer_public_key).shared_key()  # <-- À AJOUTER

            # Initialiser le chiffrement (AES-GCM)
            conn.box = SecretBox(shared_key)

            # 2. Authentification (Échange de signatures Ed25519)
            # Envoyer notre clé publique d'identité
            writer.write(self.signing_key.verify_key.encode())
            await writer.drain()

            # Recevoir la clé publique d'identité du pair
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
            print(f"Pair authentifié : {peer_identity_bytes.hex()[:8]}")

        except Exception as e:
            print(f"Échec authentification : {e}")
            writer.close()
            return

        # --- BOUCLE DE DONNÉES ---
        keepalive_task = asyncio.create_task(self._keepalive_loop(conn))
        try:
            while self.running:
                tlv_type, value = await read_tlv(reader)

                # Déchiffrement des données applicatives
                if conn.box and tlv_type in [
                    TLVType.PACKET,
                    TLVType.CHUNK_DATA,
                    TLVType.REQUEST_CHUNK,
                ]:
                    value = conn.box.decrypt(value)

                await self._on_tlv(conn, tlv_type, value)
        except Exception:
            pass
        finally:
            keepalive_task.cancel()
            conn.alive = False
            writer.close()
            await writer.wait_closed()

    async def _on_tlv(self, conn: PeerConnection, tlv_type: int, value: bytes) -> None:
        if tlv_type == TLVType.PING:
            conn.writer.write(encode_tlv(TLVType.PONG, b"pong"))
            await conn.writer.drain()
            return

        # Gestion des chunks (Sprint 3)
        if tlv_type == TLVType.REQUEST_CHUNK:
            chunk_hash = value.decode("utf-8")
            chunk_data = self.file_manager.get_chunk(chunk_hash)
            if chunk_data and conn.box:
                # Chiffrer avant envoi
                encrypted = conn.box.encrypt(chunk_data)
                conn.writer.write(encode_tlv(TLVType.CHUNK_DATA, encrypted))
                await conn.writer.drain()

    async def _keepalive_loop(self, conn: PeerConnection) -> None:
        while self.running and conn.alive:
            try:
                conn.writer.write(encode_tlv(TLVType.PING, b"ping"))
                await conn.writer.drain()
            except Exception:
                break
            await asyncio.sleep(self.config.KEEPALIVE_INTERVAL)
