import json
import os

class TrustTable:
    def __init__(self, persistence_file="trust.json"):
        self.trust = {} # node_id_hex -> {public_key, first_seen, status}
        self.persistence_file = persistence_file
        self._load()

    def check_and_save(self, node_id_hex, public_key):
        if node_id_hex in self.trust:
            if self.trust[node_id_hex]["public_key"] != public_key.hex():
                print(f"CRITICAL: Identity changed for {node_id_hex}! Possible MITM.")
                return False
            return True
        else:
            # TOFU: Trust On First Use
            self.trust[node_id_hex] = {
                "public_key": public_key.hex(),
                "first_seen": os.path.getmtime(self.persistence_file) if os.path.exists(self.persistence_file) else 0,
                "status": "trusted"
            }
            self._save()
            return True

    def _save(self):
        with open(self.persistence_file, "w") as f:
            json.dump(self.trust, f)

    def _load(self):
        try:
            with open(self.persistence_file, "r") as f:
                self.trust = json.load(f)
        except FileNotFoundError:
            self.trust = {}
