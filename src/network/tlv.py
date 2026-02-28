import asyncio
import struct
from typing import Tuple


def encode_tlv(tlv_type: int, value: bytes) -> bytes:
    return struct.pack(">BI", tlv_type, len(value)) + value


async def read_tlv(reader: asyncio.StreamReader) -> Tuple[int, bytes]:
    header = await reader.readexactly(5)
    tlv_type, length = struct.unpack(">BI", header)
    value = await reader.readexactly(length)
    return tlv_type, value

