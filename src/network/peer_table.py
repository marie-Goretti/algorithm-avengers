import time
import json
import threading

class PeerTable:
    def __init__(self, persistence_file="peers.json"):
        self.peers = {} # node_id (hex) -> {ip, tcp_port, last_seen, shared_files, reputation}
        self.persistence_file = persistence_file
        self.lock = threading.Lock()
        self._load()

    def upsert(self, node_id_hex, ip, tcp_port):
        with self.lock:
            self.peers[node_id_hex] = {
                "ip": ip,
                "tcp_port": tcp_port,
                "last_seen": time.time(),
                "shared_files": [],
                "reputation": 1.0
            }
            self._save()

    def get_peers(self):
        with self.lock:
            return self.peers.copy()

    def remove_dead_peers(self, timeout=90):
        now = time.time()
        with self.lock:
            dead_nodes = [node_id for node_id, data in self.peers.items() 
                          if now - data["last_seen"] > timeout]
            for node_id in dead_nodes:
                del self.peers[node_id]
            if dead_nodes:
                self._save()

    def _save(self):
        try:
            with open(self.persistence_file, "w") as f:
                json.dump(self.peers, f)
        except Exception as e:
            print(f"Error saving peer table: {e}")

    def _load(self):
        try:
            with open(self.persistence_file, "r") as f:
                self.peers = json.load(f)
        except FileNotFoundError:
            self.peers = {}
        except Exception as e:
            print(f"Error loading peer table: {e}")
