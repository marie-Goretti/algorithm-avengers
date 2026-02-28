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

@app.route('/api/send_msg', methods=['POST'])
def send_msg():
    data = request.json
    peer_prefix = data.get('to')
    text = data.get('msg')
    
    if not peer_prefix or not text:
        return "Missing data", 400
        
    peers = node_data['peer_table'].get_peers()
    target_pid = next((pid for pid in peers if pid.startswith(peer_prefix)), None)
    
    if target_pid:
        pdata = peers[target_pid]
        if node_data['messaging_manager'].send_encrypted_msg(target_pid, pdata["ip"], pdata["tcp_port"], text):
            return "OK", 200
            
    return "Peer not found", 404

def run_flask(port=5000):
    # Disable flask logging to keep CLI clean
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
