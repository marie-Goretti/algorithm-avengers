import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    MULTICAST_ADDR: str = os.getenv("ARCHIPEL_MULTICAST_ADDR", "239.255.42.99")
    MULTICAST_PORT: int = int(os.getenv("ARCHIPEL_MULTICAST_PORT", "6000"))
    DEFAULT_TCP_PORT: int = int(os.getenv("ARCHIPEL_TCP_PORT", "7777"))

    HELLO_INTERVAL: int = int(os.getenv("ARCHIPEL_HELLO_INTERVAL", "30"))
    PEER_TIMEOUT: int = int(os.getenv("ARCHIPEL_PEER_TIMEOUT", "90"))
    KEEPALIVE_INTERVAL: int = int(os.getenv("ARCHIPEL_KEEPALIVE_INTERVAL", "15"))

    DATA_DIR: Path = Path.home() / ".archipel_sprint1"
    PEER_TABLE_FILE: Path = DATA_DIR / "peers.json"

    @classmethod
    def init_dirs(cls) -> None:
        cls.DATA_DIR.mkdir(parents=True, exist_ok=True)


class PacketType:
    HELLO = 0x01
    PEER_LIST = 0x02
    MSG = 0x03
    CHUNK_REQ = 0x04
    CHUNK_DATA = 0x05
    MANIFEST = 0x06
    ACK = 0x07


class TLVType:
    PACKET = 0x01
    PING = 0x02
    PONG = 0x03
    REQUEST_CHUNK = 0x04


ARCHIPEL_MAGIC = b"ARCH"
