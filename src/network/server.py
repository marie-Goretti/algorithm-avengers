import socket
import threading
import json
import struct
from src.network.packet import Packet, TYPE_PEER_LIST, TYPE_HELLO, TYPE_HANDSHAKE_HELLO, TYPE_MSG, TYPE_CHUNK_REQ, TYPE_MANIFEST

class TCPServer:
    def __init__(self, node_id, port, peer_table, messaging_manager=None, transfer_manager=None, web_queue=None):
        self.node_id = node_id
        self.port = port
        self.peer_table = peer_table
        self.messaging_manager = messaging_manager
        self.transfer_manager = transfer_manager
        self.web_queue = web_queue
        self.running = False
        self.server_sock = None

    def start(self):
        self.running = True
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(('0.0.0.0', self.port))
        self.server_sock.listen(10)
        
        # print(f"TCP Server listening on port {self.port}")
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.server_sock.accept()
                threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection: {e}")

    def _handle_connection(self, conn, addr):
        try:
            # Simple TLV or just the Packet format
            data = conn.recv(4096)
            if not data:
                return
                
            packet = Packet.decode(data)
            if packet:
                if packet.type == TYPE_PEER_LIST:
                    self._process_peer_list(packet, addr[0])
                    conn.close()
                elif packet.type == TYPE_HANDSHAKE_HELLO:
                    if self.messaging_manager:
                        self.messaging_manager.handle_handshake_request(conn, packet)
                    # Note: Handle Handshake request closes its own socket
                elif packet.type == TYPE_MSG:
                    if self.messaging_manager:
                        plaintext = self.messaging_manager.decrypt_msg(packet)
                        if plaintext:
                            msg_text = f"from {packet.node_id.hex()[:8]}: {plaintext}"
                            print(f"\n[NEW MESSAGE] {msg_text}")
                            if self.web_queue:
                                self.web_queue.put(msg_text)
                    conn.close()
                elif packet.type == TYPE_CHUNK_REQ:
                    if self.transfer_manager:
                        self.transfer_manager.handle_chunk_request(packet, conn)
                    conn.close()
                elif packet.type == TYPE_MANIFEST:
                    if self.transfer_manager:
                        manifest = json.loads(packet.payload.decode())
                        print(f"\n[NEW MANIFEST] Shared by {packet.node_id.hex()[:8]}: {manifest['filename']} ({manifest['size']} bytes)")
                        # In a real app, Alice would store this manifest and decide to download it later.
                    conn.close()
                else:
                    conn.close()
        except Exception as e:
            # print(f"Error handling connection from {addr}: {e}")
            pass

    def _process_peer_list(self, packet, sender_ip):
        try:
            peer_list = json.loads(packet.payload.decode())
            for node_id_hex, data in peer_list.items():
                if node_id_hex != self.node_id.hex():
                    # print(f"Learned about peer {node_id_hex[:8]} from peer list")
                    self.peer_table.upsert(node_id_hex, data["ip"], data["tcp_port"])
        except Exception as e:
            print(f"Error processing peer list: {e}")

    def stop(self):
        self.running = False
        if self.server_sock:
            self.server_sock.close()

def send_peer_list(target_ip, target_port, my_node_id, peer_table):
    """
    Sends our peer table to a specific target via TCP.
    """
    try:
        with socket.create_connection((target_ip, target_port), timeout=5) as sock:
            peers = peer_table.get_peers()
            # Convert peer table to a sendable format
            payload = json.dumps(peers).encode()
            packet = Packet(TYPE_PEER_LIST, my_node_id, payload)
            sock.sendall(packet.encode())
    except Exception as e:
        # print(f"Could not send peer list to {target_ip}:{target_port}: {e}")
        pass
