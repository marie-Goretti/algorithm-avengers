import json
import socket
from src.network.packet import Packet, TYPE_HANDSHAKE_HELLO, TYPE_HANDSHAKE_REPLY, TYPE_HANDSHAKE_AUTH, TYPE_HANDSHAKE_OK, TYPE_MSG
from src.crypto.encryption import HandshakeState, encrypt_aes_gcm, decrypt_aes_gcm
from src.messaging.session import Session
from src.messaging.trust import TrustTable

class MessagingManager:
    def __init__(self, node_id, signing_key, trust_table):
        self.node_id = node_id
        self.signing_key = signing_key
        self.trust_table = trust_table
        self.sessions = {} # node_id_hex -> Session object

    def initiate_handshake(self, target_ip, target_port, target_node_id_hex):
        """
        Alice initiates handshake with Bob.
        """
        print(f"Initiating handshake with {target_node_id_hex[:8]}...")
        try:
            with socket.create_connection((target_ip, target_port), timeout=10) as sock:
                # 1. HELLO (e_A_pub, timestamp)
                hs = HandshakeState(self.signing_key, is_initiator=True)
                hello_payload = hs.get_hello_payload()
                packet = Packet(TYPE_HANDSHAKE_HELLO, self.node_id, json.dumps(hello_payload).encode())
                sock.sendall(packet.encode())
                
                # 2. HELLO_REPLY (e_B_pub, sig_B)
                data = sock.recv(4096)
                if not data: return False
                packet = Packet.decode(data)
                if not packet or packet.type != TYPE_HANDSHAKE_REPLY: return False
                
                reply_payload = json.loads(packet.payload.decode())
                
                # Check Bob's trust (TOFU)
                peer_node_id = packet.node_id
                peer_node_id_hex = peer_node_id.hex()
                if not self.trust_table.check_and_save(peer_node_id_hex, peer_node_id):
                    return False
                
                # Process Bob's reply and generate AUTH
                auth_payload = hs.process_hello_reply(reply_payload, peer_node_id_hex)
                
                # 3. AUTH (sig_A sur shared_secret)
                packet = Packet(TYPE_HANDSHAKE_AUTH, self.node_id, json.dumps(auth_payload).encode())
                sock.sendall(packet.encode())
                
                # 4. AUTH_OK
                data = sock.recv(4096)
                if not data: return False
                packet = Packet.decode(data)
                if not packet or packet.type != TYPE_HANDSHAKE_OK: return False
                
                # Create session
                self.sessions[target_node_id_hex] = Session(target_node_id_hex, hs.session_key, hs.peer_ephemeral_pub)
                print(f"Handshake successful with {target_node_id_hex[:8]}")
                return True
        except Exception as e:
            print(f"Handshake failed with {target_node_id_hex[:8]}: {e}")
            return False

    def handle_handshake_request(self, sock, first_packet):
        """
        Bob handles handshake request from Alice.
        """
        try:
            # 1. Process HELLO
            hello_payload = json.loads(first_packet.payload.decode())
            peer_node_id = first_packet.node_id
            peer_node_id_hex = peer_node_id.hex()
            
            # Check Alice's trust (TOFU)
            if not self.trust_table.check_and_save(peer_node_id_hex, peer_node_id):
                return False
                
            hs = HandshakeState(self.signing_key, is_initiator=False)
            reply_payload = hs.respond_hello(hello_payload)
            
            # 2. HELLO_REPLY
            packet = Packet(TYPE_HANDSHAKE_REPLY, self.node_id, json.dumps(reply_payload).encode())
            sock.sendall(packet.encode())
            
            # 3. AUTH
            data = sock.recv(4096)
            if not data: return False
            packet = Packet.decode(data)
            if not packet or packet.type != TYPE_HANDSHAKE_AUTH: return False
            
            auth_payload = json.loads(packet.payload.decode())
            
            # Verify Alice's AUTH
            if hs.process_auth(auth_payload, peer_node_id_hex):
                # 4. AUTH_OK
                packet = Packet(TYPE_HANDSHAKE_OK, self.node_id, b"OK")
                sock.sendall(packet.encode())
                
                # Create session
                self.sessions[peer_node_id_hex] = Session(peer_node_id_hex, hs.session_key, hs.peer_ephemeral_pub)
                # print(f"Handshake successful with {peer_node_id_hex[:8]}")
                return True
            else:
                return False
        except Exception as e:
            print(f"Error handling handshake: {e}")
            return False

    def send_encrypted_msg(self, target_node_id_hex, target_ip, target_port, message):
        """
        Sends an encrypted message to Bob.
        Re-uses session if exists, else initiates handshake.
        """
        if target_node_id_hex not in self.sessions:
            if not self.initiate_handshake(target_ip, target_port, target_node_id_hex):
                return False
        
        session = self.sessions[target_node_id_hex]
        nonce, ciphertext, tag = encrypt_aes_gcm(session.session_key, message.encode())
        
        # Build encrypted payload for TYPE_MSG as shown in Module 2.4 (page 8)
        # However, the packet format on page 4 says PAYLOAD is chiffré.
        # So we should probably put (nonce, ciphertext, tag) in the PAYLOAD.
        
        payload_data = {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex()
        }
        
        packet = Packet(TYPE_MSG, self.node_id, json.dumps(payload_data).encode())
        
        try:
            with socket.create_connection((target_ip, target_port), timeout=10) as sock:
                sock.sendall(packet.encode())
            return True
        except Exception as e:
            print(f"Failed to send encrypted message: {e}")
            return False

    def decrypt_msg(self, packet):
        """
        Decrypts an incoming TYPE_MSG packet.
        """
        sender_id_hex = packet.node_id.hex()
        if sender_id_hex not in self.sessions:
            return None # No session exists
            
        session = self.sessions[sender_id_hex]
        try:
            payload = json.loads(packet.payload.decode())
            nonce = bytes.fromhex(payload["nonce"])
            ciphertext = bytes.fromhex(payload["ciphertext"])
            tag = bytes.fromhex(payload["tag"])
            
            plaintext = decrypt_aes_gcm(session.session_key, nonce, ciphertext, tag)
            return plaintext.decode() if plaintext else None
        except Exception as e:
            print(f"Failed to decrypt message: {e}")
            return None
