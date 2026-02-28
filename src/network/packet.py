import struct
import hashlib
import hmac

MAGIC = b"ARCP" # Archipel Packet v1

class Packet:
    def __init__(self, p_type, node_id, payload, hmac_key=None):
        self.type = p_type
        self.node_id = node_id # bytes[32]
        self.payload = payload # bytes
        self.hmac_key = hmac_key # bytes[32] for signing/verification
        
    def encode(self):
        """
        Encodes the packet to binary format.
        MAGIC (4B) | TYPE (1B) | NODE_ID (32B) | PAYLOAD_LEN (4B) | PAYLOAD (Var) | HMAC-SHA256 (32B)
        """
        payload_len = len(self.payload)
        header = struct.pack("!4sB32sI", MAGIC, self.type, self.node_id, payload_len)
        data_to_sign = header + self.payload
        
        # If no key provided, fill with zeros (e.g., during discovery)
        if self.hmac_key:
            signature = hmac.new(self.hmac_key, data_to_sign, hashlib.sha256).digest()
        else:
            signature = b"\x00" * 32
            
        return data_to_sign + signature

    @staticmethod
    def decode(data, hmac_key=None):
        """
        Decodes binary data into a Packet object.
        """
        if len(data) < 41: # Min size: Magic (4) + Type (1) + NodeID (32) + PayloadLen (4) + HMAC (32)
            return None
            
        header_fmt = "!4sB32sI"
        header_size = struct.calcsize(header_fmt)
        magic, p_type, node_id, payload_len = struct.unpack(header_fmt, data[:header_size])
        
        if magic != MAGIC:
            return None
            
        payload = data[header_size : header_size + payload_len]
        received_hmac = data[header_size + payload_len : header_size + payload_len + 32]
        
        # Verify HMAC if key is provided
        if hmac_key:
            data_to_verify = data[:header_size + payload_len]
            expected_hmac = hmac.new(hmac_key, data_to_verify, hashlib.sha256).digest()
            if not hmac.compare_digest(received_hmac, expected_hmac):
                print("HMAC verification failed")
                return None
        
        return Packet(p_type, node_id, payload, hmac_key)

# Packet types
TYPE_HELLO = 0x01
TYPE_PEER_LIST = 0x02
TYPE_MSG = 0x03
TYPE_CHUNK_REQ = 0x04
TYPE_CHUNK_DATA = 0x05
TYPE_MANIFEST = 0x06
TYPE_ACK = 0x07
TYPE_HANDSHAKE_HELLO = 0x08
TYPE_HANDSHAKE_REPLY = 0x09
TYPE_HANDSHAKE_AUTH = 0x0A
TYPE_HANDSHAKE_OK = 0x0B
