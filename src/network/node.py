import argparse
import asyncio
import secrets
import time

from config import Config
from network.discovery import DiscoveryService
from network.peer_table import PeerTable
from network.tcp_server import TCPServer


class Node:
    def __init__(self, port: int):
        self.config = Config()
        self.config.init_dirs()
        self.node_id = secrets.token_bytes(32)
        self.port = port
        self.peer_table = PeerTable()
        self.discovery = DiscoveryService(self.node_id, port, self.peer_table)
        self.tcp_server = TCPServer(self.node_id, port, self.peer_table)
        self.running = False

    async def start(self) -> None:
        self.running = True
        print("Demarrage Archipel")
        print(f"Node ID: {self.node_id.hex()[:16]}...")
        print(f"Port TCP: {self.port}")
        await asyncio.gather(
            self.discovery.start(),
            self.tcp_server.start(),
            self._peer_table_printer(),
        )

    async def _peer_table_printer(self) -> None:
        while self.running:
            peers = self.peer_table.all()
            print(f"\n[{time.strftime('%H:%M:%S')}] Peers connectes: {len(peers)}")
            for p in peers:
                age = int(time.time() - p.last_seen)
                print(
                    f"- {p.node_id[:12]} {p.ip}:{p.tcp_port} Vu pour la dernière fois={age}s"
                )
            await asyncio.sleep(5)

    def stop(self) -> None:
        self.running = False
        self.discovery.stop()
        self.tcp_server.stop()

