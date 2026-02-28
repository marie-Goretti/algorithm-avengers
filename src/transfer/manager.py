import os
import json
import hashlib
import socket
import threading
from src.network.packet import Packet, TYPE_CHUNK_REQ, TYPE_CHUNK_DATA, TYPE_ACK, TYPE_MANIFEST
from src.transfer.chunking import get_chunk, CHUNK_SIZE

class TransferManager:
    def __init__(self, node_id, signing_key, messaging_manager):
        self.node_id = node_id
        self.signing_key = signing_key
        self.messaging_manager = messaging_manager
        self.local_files = {} # file_id -> file_path
        self.active_downloads = {} # file_id -> {manifest, downloaded_chunks, ...}
        self.temp_dir = ".archipel/tmp"
        os.makedirs(self.temp_dir, exist_ok=True)

    def register_file(self, file_path, file_id):
        self.local_files[file_id] = file_path

    def handle_chunk_request(self, packet, sock):
        """
        Bob handles a CHUNK_REQ from Alice.
        """
        try:
            payload = json.loads(packet.payload.decode())
            file_id = payload["file_id"]
            chunk_idx = payload["chunk_idx"]
            print(f"[DEBUG] Received CHUNK_REQ for {file_id[:8]} chunk {chunk_idx}")
            
            if file_id in self.local_files:
                file_path = self.local_files[file_id]
                chunk_data = get_chunk(file_path, chunk_idx)
                
                # Sign chunk data
                signature = self.signing_key.sign(chunk_data).signature
                
                # Encrypt data using session key
                # Note: For multi-node transfer, we should use the session key with the requester.
                requester_id_hex = packet.node_id.hex()
                session = self.messaging_manager.sessions.get(requester_id_hex)
                
                if session:
                    from src.crypto.encryption import encrypt_aes_gcm
                    nonce, ciphertext, tag = encrypt_aes_gcm(session.session_key, chunk_data)
                    
                    response_payload = {
                        "file_id": file_id,
                        "chunk_idx": chunk_idx,
                        "nonce": nonce.hex(),
                        "ciphertext": ciphertext.hex(),
                        "tag": tag.hex(),
                        "chunk_hash": hashlib.sha256(chunk_data).hexdigest(),
                        "signature": signature.hex()
                    }
                    
                    response_pkt = Packet(TYPE_CHUNK_DATA, self.node_id, json.dumps(response_payload).encode())
                    sock.sendall(response_pkt.encode())
                    print(f"[DEBUG] Sent CHUNK_DATA for chunk {chunk_idx}")
                else:
                    print(f"[DEBUG] No session found for requester {requester_id_hex[:8]}")
            else:
                print(f"[DEBUG] File {file_id[:8]} not in local_files. Have: {list(self.local_files.keys())}")
        except Exception as e:
            print(f"Error handling chunk request: {e}")

    def download_file(self, manifest, peers):
        """
        Alice downloads a file from multiple peers.
        """
        file_id = manifest["file_id"]
        filename = manifest["filename"]
        nb_chunks = manifest["nb_chunks"]
        
        print(f"Starting download of {filename} ({nb_chunks} chunks)...")
        self.active_downloads[file_id] = {
            "manifest": manifest,
            "downloaded": [False] * nb_chunks,
            "chunks_data": [None] * nb_chunks
        }
        
        # Parallel download strategy
        # Simplified: divide chunks among available peers
        threads = []
        chunks_per_peer = (nb_chunks // len(peers)) + 1
        
        for i, (peer_id, peer_data) in enumerate(peers.items()):
            start_idx = i * chunks_per_peer
            end_idx = min(start_idx + chunks_per_peer, nb_chunks)
            if start_idx >= nb_chunks: break
            
            t = threading.Thread(target=self._download_worker, args=(peer_id, peer_data, manifest, range(start_idx, end_idx)))
            threads.append(t)
            t.start()
            
        for t in threads:
            t.join()
            
        # Verify and Reassemble
        if all(self.active_downloads[file_id]["downloaded"]):
            print(f"Download of {filename} complete! Reassembling...")
            self._reassemble_file(file_id)
        else:
            print(f"Download of {filename} failed. Missing chunks.")

    def _download_worker(self, peer_id, peer_data, manifest, chunk_indices):
        file_id = manifest["file_id"]
        for idx in chunk_indices:
            # Request chunk
            success = self._request_chunk(peer_id, peer_data, file_id, idx)
            if success:
                # print(f"Chunk {idx} downloaded from {peer_id[:8]}")
                pass
            else:
                print(f"Failed to download chunk {idx} from {peer_id[:8]}")

    def _request_chunk(self, peer_id, peer_data, file_id, chunk_idx):
        # 1. Ensure session exists
        if peer_id not in self.messaging_manager.sessions:
            print(f"[DEBUG] No session for {peer_id[:8]}, initiating handshake...")
            if not self.messaging_manager.initiate_handshake(peer_data["ip"], peer_data["tcp_port"], peer_id):
                print(f"[DEBUG] Handshake failed for {peer_id[:8]}")
                return False
                
        # 2. Send CHUNK_REQ
        payload = {"file_id": file_id, "chunk_idx": chunk_idx}
        packet = Packet(TYPE_CHUNK_REQ, self.node_id, json.dumps(payload).encode())
        
        try:
            with socket.create_connection((peer_data["ip"], peer_data["tcp_port"]), timeout=10) as sock:
                sock.sendall(packet.encode())
                print(f"[DEBUG] Sent CHUNK_REQ for chunk {chunk_idx} to {peer_id[:8]}")
                
                # 3. Receive CHUNK_DATA
                data = sock.recv(CHUNK_SIZE * 2) # Larger buffer for overhead
                if not data: 
                    print(f"[DEBUG] No data received for chunk {chunk_idx}")
                    return False
                resp_pkt = Packet.decode(data)
                if not resp_pkt:
                    print(f"[DEBUG] Could not decode packet for chunk {chunk_idx}")
                    return False
                if resp_pkt.type != TYPE_CHUNK_DATA:
                    print(f"[DEBUG] Wrong packet type for chunk {chunk_idx}: {resp_pkt.type}")
                    return False
                
                # 4. Decrypt and verify chunk
                resp_payload = json.loads(resp_pkt.payload.decode())
                session = self.messaging_manager.sessions[peer_id]
                
                from src.crypto.encryption import decrypt_aes_gcm
                nonce = bytes.fromhex(resp_payload["nonce"])
                ciphertext = bytes.fromhex(resp_payload["ciphertext"])
                tag = bytes.fromhex(resp_payload["tag"])
                
                chunk_data = decrypt_aes_gcm(session.session_key, nonce, ciphertext, tag)
                if not chunk_data:
                    print(f"[DEBUG] Decryption failed for chunk {chunk_idx}")
                    return False
                
                # Verify SHA-256
                expected_hash = self.active_downloads[file_id]["manifest"]["chunks"][chunk_idx]["hash"]
                if hashlib.sha256(chunk_data).hexdigest() != expected_hash:
                    print(f"[DEBUG] Chunk {chunk_idx} hash mismatch!")
                    return False
                    
                # Verify Signature (Bob's signature)
                from nacl.signing import VerifyKey
                vk = VerifyKey(bytes.fromhex(peer_id))
                vk.verify(chunk_data, bytes.fromhex(resp_payload["signature"]))
                
                # Save chunk
                self.active_downloads[file_id]["chunks_data"][chunk_idx] = chunk_data
                self.active_downloads[file_id]["downloaded"][chunk_idx] = True
                print(f"[DEBUG] Chunk {chunk_idx} successful.")
                return True
        except Exception as e:
            print(f"[DEBUG] Error requesting chunk {chunk_idx}: {e}")
            return False

    def _reassemble_file(self, file_id):
        download_info = self.active_downloads[file_id]
        manifest = download_info["manifest"]
        filename = manifest["filename"]
        
        output_path = f"downloads/{filename}"
        os.makedirs("downloads", exist_ok=True)
        
        with open(output_path, "wb") as f:
            for chunk_data in download_info["chunks_data"]:
                f.write(chunk_data)
        
        # Final verification
        with open(output_path, "rb") as f:
            final_hash = hashlib.sha256(f.read()).hexdigest()
            if final_hash == file_id:
                print(f"File reassembled successfully: {output_path}")
                # Register locally
                self.register_file(output_path, file_id)
            else:
                print(f"Reassembly failed: Final hash mismatch.")
