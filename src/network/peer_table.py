import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List

from config import Config


@dataclass
class PeerInfo:
    node_id: str
    ip: str
    tcp_port: int
    last_seen: float = field(default_factory=time.time)
    shared_files: List[str] = field(default_factory=list)
    reputation: float = 1.0

    def is_alive(self, timeout: int) -> bool:
        return (time.time() - self.last_seen) < timeout


class PeerTable:
    def __init__(self, filepath: Path | None = None):
        self.config = Config()
        self.config.init_dirs()
        self.filepath = filepath or self.config.PEER_TABLE_FILE
        self.peers: Dict[str, PeerInfo] = {}
        self.load()

    def upsert(self, node_id: str, ip: str, tcp_port: int) -> bool:
        is_new = node_id not in self.peers
        peer = self.peers.get(node_id)
        if peer:
            peer.ip = ip
            peer.tcp_port = tcp_port
            peer.last_seen = time.time()
        else:
            self.peers[node_id] = PeerInfo(node_id=node_id, ip=ip, tcp_port=tcp_port)
        self.save()
        return is_new

    def touch(self, node_id: str) -> None:
        if node_id in self.peers:
            self.peers[node_id].last_seen = time.time()
            self.save()

    def remove_stale(self) -> int:
        stale = [
            node_id
            for node_id, info in self.peers.items()
            if not info.is_alive(self.config.PEER_TIMEOUT)
        ]
        for node_id in stale:
            del self.peers[node_id]
        if stale:
            self.save()
        return len(stale)

    def all(self) -> List[PeerInfo]:
        return list(self.peers.values())

    def save(self) -> None:
        data = [asdict(peer) for peer in self.peers.values()]
        self.filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load(self) -> None:
        if not self.filepath.exists():
            return
        try:
            data = json.loads(self.filepath.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        self.peers = {item["node_id"]: PeerInfo(**item) for item in data}

