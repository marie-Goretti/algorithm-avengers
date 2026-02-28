from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
import threading
import queue

app = Flask(__name__)
CORS(app)

# Global references to node components
node_data = {
    "peer_table": None,
    "transfer_manager": None,
    "messaging_manager": None,
    "gemini_assistant": None,
    "node_id": None,
    "new_messages": queue.Queue(),
}


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


# ─────────────────────────────────────────────
#  PEERS
# ─────────────────────────────────────────────


@app.route("/api/peers")
def get_peers():
    if node_data["peer_table"]:
        try:
            return jsonify(node_data["peer_table"].get_peers())
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({})


# ─────────────────────────────────────────────
#  FILES
# ─────────────────────────────────────────────


@app.route("/api/files")
def get_files():
    if node_data["transfer_manager"]:
        try:
            return jsonify(node_data["transfer_manager"].local_files)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({})


# ─────────────────────────────────────────────
#  STATUS + MESSAGES ENTRANTS
# ─────────────────────────────────────────────


@app.route("/api/status")
def get_status():
    # Vider la queue des nouveaux messages
    msgs = []
    while not node_data["new_messages"].empty():
        try:
            msgs.append(node_data["new_messages"].get_nowait())
        except queue.Empty:
            break

    node_id_hex = None
    if node_data["node_id"]:
        # Supporte bytes ou objet PyNaCl
        if hasattr(node_data["node_id"], "hex"):
            node_id_hex = node_data["node_id"].hex()
        elif hasattr(node_data["node_id"], "encode"):
            node_id_hex = node_data["node_id"].encode().hex()
        else:
            node_id_hex = str(node_data["node_id"])

    return jsonify(
        {
            "node_id": node_id_hex,
            "new_messages": msgs,
            "peer_count": len(node_data["peer_table"].get_peers())
            if node_data["peer_table"]
            else 0,
        }
    )


# ─────────────────────────────────────────────
#  ENVOI DE MESSAGE — LE BUG PRINCIPAL CORRIGÉ
# ─────────────────────────────────────────────


@app.route("/api/send_msg", methods=["POST"])
def send_msg():
    data = request.json
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    peer_prefix = data.get("to", "").strip()
    text = data.get("msg", "").strip()

    if not peer_prefix or not text:
        return jsonify({"error": 'Missing "to" or "msg"'}), 400

    # ✅ FIX : vérifier que messaging_manager est bien initialisé
    if not node_data["messaging_manager"]:
        return jsonify(
            {"error": "messaging_manager not initialized — check main.py"}
        ), 503

    if not node_data["peer_table"]:
        return jsonify({"error": "peer_table not initialized"}), 503

    peers = node_data["peer_table"].get_peers()
    if not peers:
        return jsonify({"error": "No peers discovered yet"}), 404

    # Trouver le pair par préfixe d'ID
    target_pid = next((pid for pid in peers if pid.startswith(peer_prefix)), None)

    if not target_pid:
        return jsonify(
            {
                "error": f'Peer not found with prefix "{peer_prefix}"',
                "available_peers": list(peers.keys()),
            }
        ), 404

    pdata = peers[target_pid]

    try:
        success = node_data["messaging_manager"].send_encrypted_msg(
            target_pid, pdata["ip"], pdata["tcp_port"], text
        )
        if success:
            return jsonify({"status": "OK", "to": target_pid[:16]}), 200
        else:
            return jsonify({"error": "send_encrypted_msg returned False"}), 500

    except Exception as e:
        return jsonify({"error": f"Exception during send: {str(e)}"}), 500


# ─────────────────────────────────────────────
#  GEMINI — FALLBACK GRACIEUX SANS INTERNET
# ─────────────────────────────────────────────


@app.route("/api/gemini", methods=["POST"])
def gemini_query():
    data = request.json
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    text = data.get("msg", "").strip()
    if not text:
        return jsonify({"error": 'Missing "msg"'}), 400

    # ✅ Fallback gracieux si Gemini non dispo (mode offline)
    if not node_data["gemini_assistant"]:
        return jsonify(
            {
                "answer": "[Gemini indisponible — mode offline] "
                "Connexion internet requise pour utiliser l'IA."
            }
        ), 200

    try:
        answer = node_data["gemini_assistant"].query(text)
        return jsonify({"answer": answer})
    except Exception as e:
        return jsonify(
            {"answer": f"[Gemini erreur] {str(e)}"}
        ), 200  # 200 pour ne pas crasher le frontend


# ─────────────────────────────────────────────
#  PARTAGE DE FICHIER
# ─────────────────────────────────────────────


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

    try:
        from src.transfer.chunking import create_file_manifest
        import json, socket

        # Récupérer node_id en bytes
        nid = node_data["node_id"]
        if hasattr(nid, "encode"):
            nid_hex = nid.encode().hex()
        elif isinstance(nid, bytes):
            nid_hex = nid.hex()
        else:
            nid_hex = str(nid)

        manifest = create_file_manifest(file_path, nid_hex)
        node_data["transfer_manager"].register_file(file_path, manifest["file_id"])

        # Broadcaster le manifest à tous les pairs
        from src.network.packet import Packet, TYPE_MANIFEST

        packet = Packet(
            TYPE_MANIFEST, node_data["node_id"], json.dumps(manifest).encode()
        )
        peers = node_data["peer_table"].get_peers() if node_data["peer_table"] else {}

        sent_count = 0
        for pid, pdata in peers.items():
            try:
                with socket.create_connection(
                    (pdata["ip"], pdata["tcp_port"]), timeout=2
                ) as s:
                    s.sendall(packet.encode())
                sent_count += 1
            except Exception:
                pass

        return jsonify(
            {"status": "OK", "manifest": manifest, "broadcast_to": sent_count}
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
#  TÉLÉCHARGEMENT DE FICHIER
# ─────────────────────────────────────────────


@app.route("/api/download", methods=["POST"])
def download_file():
    data = request.json
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    manifest_path = data.get("path", "").strip()
    if not manifest_path:
        return jsonify({"error": 'Missing "path"'}), 400
    if not os.path.exists(manifest_path):
        return jsonify({"error": f"Manifest not found: {manifest_path}"}), 404

    try:
        import json

        with open(manifest_path, "r") as f:
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


# ─────────────────────────────────────────────
#  LANCEMENT FLASK
# ─────────────────────────────────────────────


def run_flask(port=5000):
    import logging

    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
