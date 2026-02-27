import socket
import struct
import time
import threading
import os
from collections import defaultdict

# --- Configuration ---
MULTICAST_GROUP = '239.255.42.99'
MULTICAST_PORT = 6000
TIMEOUT = 90  # Secondes avant de considérer un nœud comme mort

class PeerTable:
    def __init__(self):
        self.peers = {} # node_id -> {info}
        self.lock = threading.Lock()

    def update_peer(self, node_id, ip, tcp_port):
        with self.lock:
            self.peers[node_id] = {
                'ip': ip,
                'tcp_port': tcp_port,
                'last_seen': time.time()
            }
            print(f"Pair mis à jour : {node_id.hex()[:8]}... ({ip}:{tcp_port})")

    def remove_dead_peers(self):
        with self.lock:
            now = time.time()
            dead_peers = [nid for nid, info in self.peers.items() 
                          if now - info['last_seen'] > TIMEOUT]
            for nid in dead_peers:
                del self.peers[nid]
                print(f"Pair supprimé (timeout) : {nid.hex()[:8]}...")

def start_discovery_service(node_id, tcp_port):
    """Lance le thread de découverte UDP."""
    
    # 1. Socket pour écouter les HELLOs des autres
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((MULTICAST_GROUP, MULTICAST_PORT))
    
    mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    peer_table = PeerTable()

    # Thread pour écouter les messages
    def listen():
        while True:
            data, addr = sock.recvfrom(1024)
            # Simplification: on suppose que HELLO est juste node_id + port
            # Dans le vrai protocole, parser le binaire ici
            try:
                # Format supposé: 32 bytes node_id, 2 bytes port (big endian)
                peer_node_id = data[:32]
                peer_tcp_port = struct.unpack('!H', data[32:34])[0]
                peer_table.update_peer(peer_node_id, addr[0], peer_tcp_port)
            except Exception as e:
                print(f"Erreur parsing paquet : {e}")

    # Thread pour broadcaster son propre HELLO
    def broadcast():
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        
        # Structure paquet HELLO (type:1, node_id:32, port:2)
        hello_packet = struct.pack('!B32sH', 1, node_id, tcp_port)
        
        while True:
            send_sock.sendto(hello_packet, (MULTICAST_GROUP, MULTICAST_PORT))
            time.sleep(30)

    # Thread pour nettoyer les pairs morts
    def cleanup():
        while True:
            time.sleep(10)
            peer_table.remove_dead_peers()

    threading.Thread(target=listen, daemon=True).start()
    threading.Thread(target=broadcast, daemon=True).start()
    threading.Thread(target=cleanup, daemon=True).start()
    
    return peer_table

# --- Exemple de lancement ---
if __name__ == "__main__":
    # Chargez votre node_id généré au Sprint 0 ici
    dummy_node_id = os.urandom(32) 
    print(f"Lancement Nœud {dummy_node_id.hex()[:8]}...")
    start_discovery_service(dummy_node_id, 7777)
    
    # Garder le main thread en vie
    while True: time.sleep(1)