import time

class Session:
    def __init__(self, node_id, session_key, peer_ephemeral_pub):
        self.node_id = node_id # peer node_id
        self.session_key = session_key
        self.peer_ephemeral_pub = peer_ephemeral_pub
        self.created_at = time.time()
        self.last_used = time.time()
        
    def update_usage(self):
        self.last_used = time.time()
