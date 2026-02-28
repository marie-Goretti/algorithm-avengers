import asyncio
import json
import socket
import struct
import time
from typing import Optional

from config import Config, PacketType, TLVType
from network.packet import ArchipelPacket, PacketBuilder
from network.peer_table import PeerTable
from network.tlv import encode_tlv


class DiscoveryService:
    def __init__(self, node_id: bytes, tcp_port: int, peer_table: PeerTable):
        self.config = Config()
        self.node_id = node_id
        self.tcp_port = tcp_port
        self.peer_table = peer_table
        self.running = False
        self.sock: Optional[socket.socket] = None
        self.tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", self.config.MULTICAST_PORT))

        mreq = struct.pack(
            "4sL", socket.inet_aton(self.config.MULTICAST_ADDR), socket.INADDR_ANY
        )
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.sock.setblocking(False)

        self.tasks = [
            asyncio.create_task(self._send_hello_loop()),
            asyncio.create_task(self._recv_loop()),
            asyncio.create_task(self._cleanup_loop()),
        ]
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def _send_hello_loop(self) -> None:
        while self.running:
            payload = json.dumps(
                {"tcp_port": self.tcp_port, "timestamp": int(time.time())}
            ).encode("utf-8")
            packet = PacketBuilder.build(PacketType.HELLO, self.node_id, payload)
            self.sock.sendto(
                packet, (self.config.MULTICAST_ADDR, self.config.MULTICAST_PORT)
            )
            print(f"[HELLO->] node={self.node_id.hex()[:12]} port={self.tcp_port}")
            await asyncio.sleep(self.config.HELLO_INTERVAL)

    async def _recv_loop(self) -> None:
        loop = asyncio.get_event_loop()
        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(self.sock, 4096)
                await self._handle_packet(data, addr[0])
            except OSError:
                if not self.running:
                    break
                await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.1)

    async def _handle_packet(self, data: bytes, sender_ip: str) -> None:
        pkt = ArchipelPacket.parse(data)
        if not pkt:
            return
        if pkt.node_id == self.node_id:
            return
        if pkt.pkt_type != PacketType.HELLO:
            return

        try:
            info = json.loads(pkt.payload.decode("utf-8"))
            peer_port = int(info["tcp_port"])
        except (ValueError, KeyError, json.JSONDecodeError):
            return

        peer_id = pkt.node_id.hex()
        is_new = self.peer_table.upsert(peer_id, sender_ip, peer_port)
        print(f"[HELLO<-] from={peer_id[:12]} ip={sender_ip}:{peer_port} new={is_new}")
        if is_new:
            await self._send_peer_list_unicast(sender_ip, peer_port)

    async def _send_peer_list_unicast(self, target_ip: str, target_port: int) -> None:
        peers = [
            {"node_id": p.node_id, "ip": p.ip, "tcp_port": p.tcp_port}
            for p in self.peer_table.all()
        ]
        payload = json.dumps(peers).encode("utf-8")
        packet = PacketBuilder.build(PacketType.PEER_LIST, self.node_id, payload)
        tlv = encode_tlv(TLVType.PACKET, packet)
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, target_port), timeout=3.0
            )
            writer.write(tlv)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception:
            return

    async def _cleanup_loop(self) -> None:
        while self.running:
            removed = self.peer_table.remove_stale()
            if removed:
                print(f"[PEER_TABLE] removed stale peers: {removed}")
            await asyncio.sleep(5)

    def stop(self) -> None:
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None
        for task in self.tasks:
            if not task.done():
                task.cancel()
