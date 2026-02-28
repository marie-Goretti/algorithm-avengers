import struct
from dataclasses import dataclass
from typing import Optional
import nacl.signing

from config import ARCHIPEL_MAGIC


@dataclass
class ArchipelPacket:
    magic: bytes
    pkt_type: int
    node_id: bytes
    payload_len: int
    payload: bytes
    signature: bytes

    HEADER_SIZE = 4 + 1 + 32 + 4
    SIGNATURE_SIZE = 64

    @classmethod
    def parse(cls, data: bytes) -> Optional["ArchipelPacket"]:
        if len(data) < cls.HEADER_SIZE + cls.SIGNATURE_SIZE:
            return None
        magic, pkt_type, node_id, payload_len = struct.unpack(
            ">4sB32sI", data[: cls.HEADER_SIZE]
        )
        if magic != ARCHIPEL_MAGIC:
            return None
        expected_len = cls.HEADER_SIZE + payload_len + cls.SIGNATURE_SIZE
        if len(data) < expected_len:
            return None
        payload = data[cls.HEADER_SIZE : cls.HEADER_SIZE + payload_len]
        signature = data[cls.HEADER_SIZE + payload_len : expected_len]
        return cls(magic, pkt_type, node_id, payload_len, payload, signature)


class PacketBuilder:
    @staticmethod
    def build(
        pkt_type: int,
        node_id: bytes,
        payload: bytes,
        signing_key: Optional[nacl.signing.SigningKey] = None,
    ) -> bytes:
        header = struct.pack(
            ">4sB32sI", ARCHIPEL_MAGIC, pkt_type, node_id, len(payload)
        )
        if signing_key:
            signature = signing_key.sign(header + payload).signature
        else:
            signature = b"\x00" * 32
        return header + payload + signature
