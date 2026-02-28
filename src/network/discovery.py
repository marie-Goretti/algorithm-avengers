import socket
import struct
import threading
import time
import json
import socket
import struct
import threading
import time
import json
from src.network.packet import Packet, TYPE_HELLO
from src.network.server import send_peer_list

MULTICAST_GROUP = '239.255.42.99'
MULTICAST_PORT = 6000

def get_local_ip():
    """Tries to find the main LAN IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable, just triggers OS interface selection
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

class Discovery:
    def __init__(self, node_id, tcp_port, peer_table):
        self.node_id = node_id # bytes[32]
        self.tcp_port = tcp_port
        self.peer_table = peer_table
        self.running = False
        self.sock = None
        self.local_ip = get_local_ip()
        print(f"Discovery started on interface: {self.local_ip}")

    def start(self):
        self.running = True
        # Set up multicast socket for receiving
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        
        # Options pour permettre plusieurs instances sur la même machine
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            
        # Bind à 0.0.0.0 pour écouter sur toutes les interfaces
        self.sock.bind(('', MULTICAST_PORT))
        
        # S'abonner au groupe spécifiquement sur l'interface LAN détectée
        # Cela force le noyau à écouter le multicast sur la bonne carte réseau
        mreq = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton(self.local_ip)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        
        # Activer le loopback pour les tests sur la même machine
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        
        # Start receiver thread
        threading.Thread(target=self._receive_loop, daemon=True).start()
        # Start sender thread
        threading.Thread(target=self._send_loop, daemon=True).start()
        # Start cleanup thread
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

    def _send_loop(self):
        # Socket for sending
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        
        # Forcer l'interface de sortie sur l'IP LAN détectée
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.local_ip))
        
        # TTL=2 pour passer au moins un switch/routeur
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        
        while self.running:
            try:
                payload_data = {
                    "tcp_port": self.tcp_port,
                    "timestamp": int(time.time() * 1000)
                }
                payload_bytes = json.dumps(payload_data).encode()
                
                packet = Packet(TYPE_HELLO, self.node_id, payload_bytes)
                data = packet.encode()
                
                send_sock.sendto(data, (MULTICAST_GROUP, MULTICAST_PORT))
            except Exception as e:
                print(f"Error sending HELLO: {e}")
            
            time.sleep(30)

    def _receive_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                packet = Packet.decode(data)
                
                if packet and packet.type == TYPE_HELLO:
                    sender_id_hex = packet.node_id.hex()
                    
                    # Ignore self
                    if packet.node_id == self.node_id:
                        continue
                        
                    try:
                        payload = json.loads(packet.payload.decode())
                        sender_tcp_port = payload.get("tcp_port")
                        
                        if sender_tcp_port:
                            # print(f"Discovered peer {sender_id_hex[:8]} at {addr[0]}:{sender_tcp_port}")
                            self.peer_table.upsert(sender_id_hex, addr[0], sender_tcp_port)
                            
                            # Reply with PEER_LIST via unicast TCP
                            threading.Thread(target=send_peer_list, args=(addr[0], sender_tcp_port, self.node_id, self.peer_table), daemon=True).start()
                    except json.JSONDecodeError:
                        print("Malformed HELLO payload")
            except Exception as e:
                if self.running:
                    print(f"Error receiving discovery packet: {e}")

    def _cleanup_loop(self):
        while self.running:
            self.peer_table.remove_dead_peers(timeout=90)
            time.sleep(10)
