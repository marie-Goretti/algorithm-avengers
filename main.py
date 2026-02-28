import os
import sys
import time
import argparse
import threading
from src.crypto.key_gen import generate_and_save_keys
from src.network.peer_table import PeerTable
from src.network.discovery import Discovery
from src.network.server import TCPServer
from src.messaging.manager import MessagingManager
from src.messaging.trust import TrustTable
from src.transfer.manager import TransferManager
from src.transfer.chunking import create_file_manifest
from src.messaging.gemini import GeminiAssistant
from src.network.packet import Packet, TYPE_MANIFEST
from nacl.signing import SigningKey
from dotenv import load_dotenv
import json
import socket

# Force flush for all prints
import builtins
def print(*args, **kwargs):
    kwargs['flush'] = True
    builtins.print(*args, **kwargs)

def cli_loop(node_name, node_id, peer_table, messaging_manager, transfer_manager, gemini, message_log, no_ai=False):
    print(f"--- Node {node_name} is running ---")
    commands_help = "Commands: list, msg <peer_id> <text>, add <ip> <port> <node_id>, share <file_path>, download <manifest_json_path>, status, exit"
    if not no_ai:
        commands_help += ", ia <question>, ia_file <file_path> <question>"
    print(commands_help)
    
    while True:
        try:
            line = sys.stdin.readline()
            if not line: break
            line = line.strip()
            if not line: continue
            
            cmd = line.split(maxsplit=2)
            if not cmd: continue
            
            action = cmd[0].lower()
            if action == "add":
                parts = line.split()
                if len(parts) < 4: continue
                peer_table.upsert(parts[3], parts[1], int(parts[2]))
                print(f"Peer {parts[3][:8]} added manually.")
            elif action == "list":
                peers = peer_table.get_peers()
                for pid, pdata in peers.items():
                    print(f" - {pid[:8]}: {pdata['ip']}:{pdata['tcp_port']}")
            elif action == "msg":
                if len(cmd) < 3: 
                    print("Usage: msg <peer_id> <text>")
                    continue
                peer_prefix, text = cmd[1], cmd[2]
                peers = peer_table.get_peers()
                target_pid = next((pid for pid in peers if pid.startswith(peer_prefix)), None)
                if target_pid:
                    pdata = peers[target_pid]
                    if messaging_manager.send_encrypted_msg(target_pid, pdata["ip"], pdata["tcp_port"], text):
                        message_log.append(f"ME -> {target_pid[:8]}: {text}")
                else:
                    print("Peer not found.")
            elif action == "ia":
                if no_ai:
                    print("IA actions are disabled.")
                    continue
                if len(cmd) < 2:
                    print("Usage: ia <question>")
                    continue
                question = line[3:].strip()
                if gemini:
                    print("IA is thinking...")
                    answer = gemini.query(question)
                    print(f"IA: {answer}")
                else:
                    print("Gemini assistant not initialized. Check API Key.")
            elif action == "ia_file":
                if no_ai:
                    print("IA actions are disabled.")
                    continue
                parts = line.split(maxsplit=2)
                if len(parts) < 3:
                    print("Usage: ia_file <file_path> <question>")
                    continue
                file_path, question = parts[1], parts[2]
                if gemini:
                    print(f"IA is analyzing {file_path}...")
                    answer = gemini.query(question, file_path=file_path)
                    print(f"IA: {answer}")
                else:
                    print("Gemini assistant not initialized. Check API Key.")
            elif action == "share":
                parts = line.split()
                if len(parts) < 2: continue
                file_path = parts[1]
                if os.path.exists(file_path):
                    manifest = create_file_manifest(file_path, node_id.hex())
                    transfer_manager.register_file(file_path, manifest["file_id"])
                    m_path = f"{node_name}_manifest_{manifest['file_id'][:8]}.json"
                    with open(m_path, "w") as f: json.dump(manifest, f)
                    print(f"Manifest created: {m_path}")
                    peers = peer_table.get_peers()
                    packet = Packet(TYPE_MANIFEST, node_id, json.dumps(manifest).encode())
                    for pid, pdata in peers.items():
                        try:
                            with socket.create_connection((pdata["ip"], pdata["tcp_port"]), timeout=2) as s:
                                s.sendall(packet.encode())
                        except: pass
            elif action == "download":
                parts = line.split()
                if len(parts) < 2: continue
                m_path = parts[1]
                if os.path.exists(m_path):
                    with open(m_path, "r") as f: manifest = json.load(f)
                    transfer_manager.download_file(manifest, peer_table.get_peers())
            elif action == "status":
                print(f"Node: {node_name} | ID: {node_id.hex()[:16]}... | Peers: {len(peer_table.get_peers())}")
            elif action == "exit":
                os._exit(0)
        except Exception as e:
            print(f"CLI Error: {e}")

def main():
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="node")
    parser.add_argument("--port", type=int, default=7777)
    parser.add_argument("--no-ai", action="store_true")
    parser.add_argument("--web", action="store_true", help="Enable web interface")
    parser.add_argument("--web-port", type=int, default=5000)
    args = parser.parse_args()

    # Keys
    key_path = f"{args.name}_signing.key"
    if not os.path.exists(key_path): generate_and_save_keys(args.name)
    with open(key_path, "rb") as f: signing_key = SigningKey(f.read())
    node_id = signing_key.verify_key.encode()
    print(f"Node ID: {node_id.hex()}", flush=True)

    # Components
    peer_table = PeerTable(f"{args.name}_peers.json")
    trust_table = TrustTable(f"{args.name}_trust.json")
    messaging_manager = MessagingManager(node_id, signing_key, trust_table)
    transfer_manager = TransferManager(node_id, signing_key, messaging_manager)
    
    gemini = None
    if not args.no_ai:
        gemini = GeminiAssistant()
        if not gemini.enabled:
            print("Warning: Gemini API Key not found. IA features might not work.")

    # Web integration
    web_queue = None
    if args.web:
        from src.web.app import node_data, run_flask
        web_queue = node_data['new_messages']
        node_data['peer_table'] = peer_table
        node_data['transfer_manager'] = transfer_manager
        node_data['messaging_manager'] = messaging_manager
        node_data['gemini_assistant'] = gemini
        node_data['node_id'] = node_id
        threading.Thread(target=run_flask, args=(args.web_port,), daemon=True).start()
        print(f"Web interface enabled on http://localhost:{args.web_port}")

    server = TCPServer(node_id, args.port, peer_table, messaging_manager, transfer_manager, web_queue=web_queue)
    discovery = Discovery(node_id, args.port, peer_table)
    
    message_log = []

    server.start()
    discovery.start()
    
    # Run CLI in main thread
    cli_loop(args.name, node_id, peer_table, messaging_manager, transfer_manager, gemini, message_log, no_ai=args.no_ai)

if __name__ == "__main__":
    main()
