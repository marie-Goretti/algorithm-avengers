import asyncio
import json
import secrets
from dataclasses import dataclass
from typing import Dict, Optional

from config import Config, PacketType, TLVType
from network.packet import ArchipelPacket
from network.peer_table import PeerTable
from network.tlv import encode_tlv, read_tlv


@dataclass
class PeerConnection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    node_id: Optional[str] = None
    authenticated: bool = False
    alive: bool = True


class TCPServer:
    def __init__(self, node_id: bytes, port: int, peer_table: PeerTable):
        self.config = Config()
        self.node_id = node_id
        self.port = port
        self.peer_table = peer_table
        self.server: Optional[asyncio.AbstractServer] = None
        self.running = False
        self.connections: Dict[str, PeerConnection] = {}

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
        keepalive_task = asyncio.create_task(self._keepalive_loop(conn))
        try:
            while self.running:
                tlv_type, value = await read_tlv(reader)
                await self._on_tlv(conn, tlv_type, value)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except asyncio.CancelledError:
            pass
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
        if tlv_type == TLVType.PONG:
            return
        if tlv_type != TLVType.PACKET:
            return

        pkt = ArchipelPacket.parse(value)
        if not pkt:
            return
        node_id = pkt.node_id.hex()
        conn.node_id = node_id
        self.connections[node_id] = conn
        self.peer_table.touch(node_id)

        if pkt.pkt_type == PacketType.PEER_LIST:
            await self._process_peer_list(pkt.payload)

    async def _process_peer_list(self, payload: bytes) -> None:
        try:
            peers = json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        for peer in peers:
            try:
                node_id = str(peer["node_id"])
                ip = str(peer["ip"])
                port = int(peer["tcp_port"])
            except (KeyError, ValueError, TypeError):
                continue
            if node_id != self.node_id.hex():
                self.peer_table.upsert(node_id, ip, port)

    async def _keepalive_loop(self, conn: PeerConnection) -> None:
        while self.running and conn.alive:
            try:
                payload = secrets.token_bytes(4)
                conn.writer.write(encode_tlv(TLVType.PING, payload))
                await conn.writer.drain()
            except Exception:
                break
            await asyncio.sleep(self.config.KEEPALIVE_INTERVAL)

    def stop(self) -> None:
        self.running = False
        if self.server:
            self.server.close()
        for conn in list(self.connections.values()):
            conn.alive = False
            conn.writer.close()

