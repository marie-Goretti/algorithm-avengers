from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
import threading
import queue

app = Flask(__name__)
CORS(app)

# Global references to node components
node_data = {
    'peer_table': None,
    'transfer_manager': None,
    'messaging_manager': None,
    'gemini_assistant': None,
    'node_id': None,
    'new_messages': queue.Queue()
}

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/peers')
def get_peers():
    if node_data['peer_table']:
        return jsonify(node_data['peer_table'].get_peers())
    return jsonify({})

@app.route('/api/files')
def get_files():
    if node_data['transfer_manager']:
        return jsonify(node_data['transfer_manager'].local_files)
    return jsonify({})

@app.route('/api/status')
def get_status():
    msgs = []
    while not node_data['new_messages'].empty():
        msgs.append(node_data['new_messages'].get())
    return jsonify({
        'node_id': node_data['node_id'].hex() if node_data['node_id'] else None,
        'new_messages': msgs
    })

@app.route('/api/gemini', methods=['POST'])
def gemini_query():
    if not node_data['gemini_assistant']:
        return "Gemini not enabled", 400
    
    data = request.json
    text = data.get('msg')
    if not text:
        return "Missing message", 400
        
    answer = node_data['gemini_assistant'].query(text)
    return jsonify({'answer': answer})

@app.route('/api/share', methods=['POST'])
def share_file():
    data = request.json
    file_path = data.get('path')
    if not file_path or not os.path.exists(file_path):
        return "File not found", 404
    
    from src.transfer.chunking import create_file_manifest
    manifest = create_file_manifest(file_path, node_data['node_id'].hex())
    node_data['transfer_manager'].register_file(file_path, manifest["file_id"])
    
    # Broadcast to peers
    from src.network.packet import Packet, TYPE_MANIFEST
    import json
    import socket
    packet = Packet(TYPE_MANIFEST, node_data['node_id'], json.dumps(manifest).encode())
    peers = node_data['peer_table'].get_peers()
    for pid, pdata in peers.items():
        try:
            with socket.create_connection((pdata["ip"], pdata["tcp_port"]), timeout=1) as s:
                s.sendall(packet.encode())
        except: pass
        
    return jsonify({"status": "OK", "manifest": manifest})

@app.route('/api/download', methods=['POST'])
def download_file():
    data = request.json
    manifest_path = data.get('path')
    if not manifest_path or not os.path.exists(manifest_path):
        return "Manifest not found", 404
        
    import json
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
        
    # Start download in background thread to not block Flask
    import threading
    threading.Thread(target=node_data['transfer_manager'].download_file, 
                     args=(manifest, node_data['peer_table'].get_peers()), 
                     daemon=True).start()
    
    return "Download started", 200

def run_flask(port=5000):
    # Disable flask logging to keep CLI clean
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
