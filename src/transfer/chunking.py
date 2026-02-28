import os
import hashlib
import json

CHUNK_SIZE = 512 * 1024 # 512 KB

def create_file_manifest(file_path, sender_id_hex):
    """
    Creates a manifest for a file.
    """
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    
    with open(file_path, "rb") as f:
        full_hash = hashlib.sha256(f.read()).hexdigest()
        f.seek(0)
        
        chunks = []
        chunk_idx = 0
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            chunk_hash = hashlib.sha256(data).hexdigest()
            chunks.append({
                "index": chunk_idx,
                "hash": chunk_hash,
                "size": len(data)
            })
            chunk_idx += 1
            
    manifest = {
        "file_id": full_hash,
        "filename": file_name,
        "size": file_size,
        "chunk_size": CHUNK_SIZE,
        "nb_chunks": len(chunks),
        "chunks": chunks,
        "sender_id": sender_id_hex
    }
    return manifest

def get_chunk(file_path, chunk_idx):
    """
    Reads a specific chunk from a file.
    """
    with open(file_path, "rb") as f:
        f.seek(chunk_idx * CHUNK_SIZE)
        return f.read(CHUNK_SIZE)
