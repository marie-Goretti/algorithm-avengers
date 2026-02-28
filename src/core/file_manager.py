import os
import hashlib

# --- Configuration ---
SHARED_DIR = "shared_files"
CHUNKS_DIR = "chunks"  # NOUVEAU
CHUNK_SIZE = 1024 * 64  # 64KB


class FileManager:
    def __init__(self):
        # Créer les dossiers nécessaires
        for directory in [SHARED_DIR, CHUNKS_DIR]:
            if not os.path.exists(directory):
                os.makedirs(directory)

        self.shared_files = {}  # filename -> list of chunk_hashes

    def index_files(self):
        """Scan, découpe en chunks et calcule les hashes."""
        self.shared_files = {}
        for filename in os.listdir(SHARED_DIR):
            path = os.path.join(SHARED_DIR, filename)
            if os.path.isfile(path):
                chunk_hashes = self._chunk_file(path)
                self.shared_files[filename] = chunk_hashes
        print(f"{len(self.shared_files)} fichiers indexés et découpés.")

    def _chunk_file(self, file_path):
        """Découpe un fichier en chunks et les sauvegarde."""
        chunk_hashes = []
        with open(file_path, "rb") as f:
            chunk_idx = 0
            while True:
                chunk_data = f.read(CHUNK_SIZE)
                if not chunk_data:
                    break

                # Calculer le hash du chunk
                chunk_hash = hashlib.sha256(chunk_data).hexdigest()
                chunk_hashes.append(chunk_hash)

                # Sauvegarder le chunk individuellement
                chunk_path = os.path.join(CHUNKS_DIR, chunk_hash)
                with open(chunk_path, "wb") as chunk_file:
                    chunk_file.write(chunk_data)

                chunk_idx += 1
        return chunk_hashes

    def get_chunk(self, chunk_hash):
        """Récupère un chunk spécifique."""
        chunk_path = os.path.join(CHUNKS_DIR, chunk_hash)
        if os.path.exists(chunk_path):
            with open(chunk_path, "rb") as f:
                return f.read()
        return None
