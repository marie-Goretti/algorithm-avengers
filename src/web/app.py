from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
import sys
import threading
import queue
import json

# ✅ Structure du projet :
#   racine/
#     main.py
#     src/
#       transfer/chunking.py
#       network/packet.py
#     web/
#       app.py  ← CE FICHIER
#
# On remonte vers racine/ et on ajoute src/ au path Python
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SRC = os.path.join(_ROOT, "src")
for _p in [_ROOT, _SRC]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

app = Flask(__name__)
CORS(app)

node_data = {
    "peer_table": None,
    "transfer_manager": None,
    "messaging_manager": None,
    "gemini_assistant": None,
    "node_id": None,
    "new_messages": queue.Queue(),
}


# ── PAGE ──────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "index.html")


# ── PEERS ─────────────────────────────────────
@app.route("/api/peers")
def get_peers():
    if not node_data["peer_table"]:
        return jsonify({})
    try:
        return jsonify(node_data["peer_table"].get_peers())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── FILES ─────────────────────────────────────
@app.route("/api/files")
def get_files():
    if not node_data["transfer_manager"]:
        return jsonify({})
    try:
        raw = node_data["transfer_manager"].local_files  # {file_id: path}
        result = {}
        for fid, fpath in raw.items():
            result[fid] = {
                "path": fpath,
                "filename": os.path.basename(fpath),
                "size": os.path.getsize(fpath) if os.path.exists(fpath) else 0,
            }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── STATUS ────────────────────────────────────
@app.route("/api/status")
def get_status():
    msgs = []
    while not node_data["new_messages"].empty():
        try:
            msgs.append(node_data["new_messages"].get_nowait())
        except queue.Empty:
            break

    nid = node_data["node_id"]
    node_id_hex = None
    if nid is not None:
        node_id_hex = nid.hex() if isinstance(nid, bytes) else nid.encode().hex()

    peer_count = 0
    if node_data["peer_table"]:
        try:
            peer_count = len(node_data["peer_table"].get_peers())
        except Exception:
            pass

    return jsonify(
        {"node_id": node_id_hex, "new_messages": msgs, "peer_count": peer_count}
    )


# ── SEND MESSAGE ──────────────────────────────
@app.route("/api/send_msg", methods=["POST"])
def send_msg():
    data = request.json
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    peer_prefix = data.get("to", "").strip()
    text = data.get("msg", "").strip()
    if not peer_prefix or not text:
        return jsonify({"error": 'Missing "to" or "msg"'}), 400
    if not node_data["messaging_manager"]:
        return jsonify({"error": "messaging_manager not initialized"}), 503

    peers = node_data["peer_table"].get_peers() if node_data["peer_table"] else {}
    if not peers:
        return jsonify({"error": "No peers discovered yet"}), 404

    target_pid = next((pid for pid in peers if pid.startswith(peer_prefix)), None)
    if not target_pid:
        return jsonify(
            {
                "error": f'Peer not found: "{peer_prefix}"',
                "available": list(peers.keys()),
            }
        ), 404

    pdata = peers[target_pid]
    try:
        ok = node_data["messaging_manager"].send_encrypted_msg(
            target_pid, pdata["ip"], pdata["tcp_port"], text
        )
        return jsonify({"status": "OK"}) if ok else jsonify(
            {"error": "send returned False"}
        ), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── GEMINI ────────────────────────────────────
@app.route("/api/gemini", methods=["POST"])
def gemini_query():
    data = request.json
    text = (data or {}).get("msg", "").strip()
    if not text:
        return jsonify({"error": 'Missing "msg"'}), 400

    assistant = node_data["gemini_assistant"]
    if not assistant or not getattr(assistant, "enabled", False):
        return jsonify({"answer": "[Gemini indisponible — mode offline]"}), 200
    try:
        return jsonify({"answer": assistant.query(text)})
    except Exception as e:
        return jsonify({"answer": f"[Gemini erreur] {e}"}), 200


# ── SHARE FILE ────────────────────────────────
@app.route("/api/share", methods=["POST"])
def share_file():
    data = request.json
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    file_path = data.get("path", "").strip()
    if not file_path:
        return jsonify({"error": 'Missing "path"'}), 400
    if not os.path.exists(file_path):
        return jsonify({"error": f"File not found: {file_path}"}), 404
    if not node_data["transfer_manager"]:
        return jsonify({"error": "transfer_manager not initialized"}), 503

    try:
        # ✅ Import depuis src/transfer/chunking.py
        from transfer.chunking import create_file_manifest

        nid = node_data["node_id"]
        nid_hex = nid.hex() if isinstance(nid, bytes) else nid.encode().hex()

        manifest = create_file_manifest(file_path, nid_hex)
        file_id = manifest["file_id"]

        # 1. Enregistrer localement
        node_data["transfer_manager"].register_file(file_path, file_id)

        # 2. Sauvegarder manifest.json pour que les pairs puissent télécharger
        manifests_dir = os.path.join(_ROOT, "manifests")
        os.makedirs(manifests_dir, exist_ok=True)
        manifest_fname = f"{manifest['filename']}_{file_id[:8]}.json"
        manifest_path = os.path.join(manifests_dir, manifest_fname)
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        # 3. Broadcaster aux pairs connus
        import socket as _socket
        from network.packet import Packet, TYPE_MANIFEST

        node_id_bytes = nid if isinstance(nid, bytes) else nid.encode()
        peers = node_data["peer_table"].get_peers() if node_data["peer_table"] else {}
        sent_count = 0
        for pid, pdata in peers.items():
            try:
                pkt = Packet(
                    TYPE_MANIFEST, node_id_bytes, json.dumps(manifest).encode()
                )
                with _socket.create_connection(
                    (pdata["ip"], pdata["tcp_port"]), timeout=2
                ) as s:
                    s.sendall(pkt.encode())
                sent_count += 1
            except Exception as be:
                print(f"[share] broadcast → {pid[:8]}: {be}")

        return jsonify(
            {
                "status": "OK",
                "file_id": file_id,
                "filename": manifest["filename"],
                "nb_chunks": manifest["nb_chunks"],
                "size": manifest["size"],
                "manifest_path": manifest_path,
                "broadcast_to": sent_count,
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ── DOWNLOAD ──────────────────────────────────
@app.route("/api/download", methods=["POST"])
def download_file():
    data = request.json
    manifest_path = (data or {}).get("path", "").strip()
    if not manifest_path:
        return jsonify({"error": 'Missing "path"'}), 400
    if not os.path.exists(manifest_path):
        return jsonify({"error": f"Manifest not found: {manifest_path}"}), 404
    if not node_data["transfer_manager"]:
        return jsonify({"error": "transfer_manager not initialized"}), 503
    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
        peers = node_data["peer_table"].get_peers() if node_data["peer_table"] else {}
        threading.Thread(
            target=node_data["transfer_manager"].download_file,
            args=(manifest, peers),
            daemon=True,
        ).start()
        return jsonify(
            {"status": "Download started", "file_id": manifest.get("file_id")}
        ), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── MANIFESTS DISPONIBLES ─────────────────────
@app.route("/api/manifests")
def list_manifests():
    """Liste les manifests reçus/créés — utilisé par le frontend pour le bouton Download."""
    manifests_dir = os.path.join(_ROOT, "manifests")
    if not os.path.exists(manifests_dir):
        return jsonify([])
    result = []
    for fname in os.listdir(manifests_dir):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(manifests_dir, fname)
        try:
            with open(fpath) as f:
                m = json.load(f)
            result.append(
                {
                    "path": fpath,
                    "filename": m.get("filename"),
                    "size": m.get("size"),
                    "file_id": m.get("file_id"),
                    "sender": m.get("sender_id", "")[:16],
                }
            )
        except Exception:
            pass
    return jsonify(result)


# ── LANCEMENT ─────────────────────────────────
def run_flask(port=5000):
    import logging

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
