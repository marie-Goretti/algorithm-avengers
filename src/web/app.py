from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
import sys
import threading
import queue
import json

# ─────────────────────────────────────────────
#  CHEMINS — CALCUL DEPUIS LA RACINE DU PROJET
#
#  On lance toujours depuis la racine :
#    cd algorithm-avengers
#    python main.py --web
#
#  Donc os.getcwd() = racine du projet, toujours.
#  C'est plus fiable que __file__ qui dépend de
#  comment Python résout les chemins relatifs.
# ─────────────────────────────────────────────

# Racine du projet = là où on a lancé python main.py
_ROOT = os.getcwd()
_MANIFESTS = os.path.join(_ROOT, "manifests")

# Ajouter src/ au path Python pour les imports internes
_SRC = os.path.join(_ROOT, "src")
for _p in [_ROOT, _SRC]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Dossier de ce fichier (src/web/) pour servir index.html
_WEB_DIR = os.path.dirname(os.path.abspath(__file__))

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

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────


def _nid_hex():
    nid = node_data["node_id"]
    if nid is None:
        return None
    if isinstance(nid, bytes):
        return nid.hex()
    if hasattr(nid, "encode"):
        return nid.encode().hex()
    return str(nid)


def _nid_bytes():
    nid = node_data["node_id"]
    if isinstance(nid, bytes):
        return nid
    if hasattr(nid, "encode"):
        return nid.encode()
    return bytes(nid)


# ─────────────────────────────────────────────
#  PAGE
# ─────────────────────────────────────────────


@app.route("/")
def index():
    return send_from_directory(_WEB_DIR, "index.html")


# ─────────────────────────────────────────────
#  PEERS
# ─────────────────────────────────────────────


@app.route("/api/peers")
def get_peers():
    if not node_data["peer_table"]:
        return jsonify({})
    try:
        return jsonify(node_data["peer_table"].get_peers())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
#  FILES
# ─────────────────────────────────────────────


@app.route("/api/files")
def get_files():
    if not node_data["transfer_manager"]:
        return jsonify({})
    try:
        result = {}
        for fid, fpath in node_data["transfer_manager"].local_files.items():
            fpath = os.path.normpath(fpath)
            result[fid] = {
                "path": fpath,
                "filename": os.path.basename(fpath),
                "size": os.path.getsize(fpath) if os.path.exists(fpath) else 0,
            }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
#  STATUS
# ─────────────────────────────────────────────


@app.route("/api/status")
def get_status():
    msgs = []
    while not node_data["new_messages"].empty():
        try:
            msgs.append(node_data["new_messages"].get_nowait())
        except queue.Empty:
            break

    peer_count = 0
    if node_data["peer_table"]:
        try:
            peer_count = len(node_data["peer_table"].get_peers())
        except Exception:
            pass

    return jsonify(
        {
            "node_id": _nid_hex(),
            "new_messages": msgs,
            "peer_count": peer_count,
        }
    )


# ─────────────────────────────────────────────
#  ENVOI DE MESSAGE
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
        return (
            jsonify({"status": "OK"})
            if ok
            else (jsonify({"error": "send returned False"}), 500)
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
#  GEMINI
# ─────────────────────────────────────────────


@app.route("/api/gemini", methods=["POST"])
def gemini_query():
    text = (request.json or {}).get("msg", "").strip()
    if not text:
        return jsonify({"error": 'Missing "msg"'}), 400

    assistant = node_data["gemini_assistant"]
    if not assistant or not getattr(assistant, "enabled", False):
        return jsonify({"answer": "[Gemini indisponible — mode offline]"}), 200
    try:
        return jsonify({"answer": assistant.query(text)})
    except Exception as e:
        return jsonify({"answer": f"[Gemini erreur] {e}"}), 200


# ─────────────────────────────────────────────
#  PARTAGE DE FICHIER
# ─────────────────────────────────────────────


@app.route("/api/share", methods=["POST"])
def share_file():
    data = request.json
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    # Normaliser le chemin Windows dès la réception
    raw_path = data.get("path", "").strip()
    file_path = os.path.normpath(raw_path)

    if not file_path or file_path == ".":
        return jsonify({"error": 'Missing "path"'}), 400
    if not os.path.exists(file_path):
        return jsonify({"error": f"File not found: {file_path}"}), 404
    if not node_data["transfer_manager"]:
        return jsonify({"error": "transfer_manager not initialized"}), 503

    try:
        from transfer.chunking import create_file_manifest

        manifest = create_file_manifest(file_path, _nid_hex())
        file_id = manifest["file_id"]

        # 1. Enregistrer localement
        node_data["transfer_manager"].register_file(file_path, file_id)

        # 2. Sauvegarder le manifest
        #    ✅ os.path.splitext retire .pdf .txt .py etc.
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        manifest_fname = f"{base_name}_{file_id[:8]}.json"
        os.makedirs(_MANIFESTS, exist_ok=True)
        manifest_path = os.path.join(_MANIFESTS, manifest_fname)

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

        print(f"[share] ✓ Manifest : {manifest_path}")

        # 3. Broadcaster aux pairs
        #    Méthode 1 : message chiffré via messaging_manager (préféré)
        #    Méthode 2 : socket TCP brut TYPE_MANIFEST (fallback)
        peers = node_data["peer_table"].get_peers() if node_data["peer_table"] else {}
        sent_count = 0
        manifest_json = json.dumps(manifest)

        for pid, pdata in peers.items():
            sent = False

            # Méthode 1 — chiffré
            if node_data["messaging_manager"]:
                try:
                    ok = node_data["messaging_manager"].send_encrypted_msg(
                        pid, pdata["ip"], pdata["tcp_port"], f"MANIFEST:{manifest_json}"
                    )
                    if ok:
                        sent = True
                        sent_count += 1
                        print(f"[share] → {pid[:8]} (chiffré) ✓")
                except Exception as e1:
                    print(f"[share] messaging failed {pid[:8]}: {e1}")

            # Méthode 2 — fallback socket brut
            if not sent:
                try:
                    import socket as _sock
                    from network.packet import Packet, TYPE_MANIFEST

                    pkt = Packet(TYPE_MANIFEST, _nid_bytes(), manifest_json.encode())
                    with _sock.create_connection(
                        (pdata["ip"], pdata["tcp_port"]), timeout=3
                    ) as s:
                        s.sendall(pkt.encode())
                    sent_count += 1
                    print(f"[share] → {pid[:8]} (socket brut) ✓")
                except Exception as e2:
                    print(f"[share] socket failed {pid[:8]}: {e2}")

        return jsonify(
            {
                "status": "OK",
                "file_id": file_id,
                "filename": manifest["filename"],
                "nb_chunks": manifest["nb_chunks"],
                "size": manifest["size"],
                "manifest_path": manifest_path,
                "broadcast_to": sent_count,
                "total_peers": len(peers),
            }
        )

    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
#  TÉLÉCHARGEMENT
# ─────────────────────────────────────────────


@app.route("/api/download", methods=["POST"])
def download_file():
    manifest_path = os.path.normpath((request.json or {}).get("path", "").strip())
    if not manifest_path or manifest_path == ".":
        return jsonify({"error": 'Missing "path"'}), 400
    if not os.path.exists(manifest_path):
        return jsonify({"error": f"Manifest not found: {manifest_path}"}), 404
    if not node_data["transfer_manager"]:
        return jsonify({"error": "transfer_manager not initialized"}), 503

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
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
#  MANIFESTS DISPONIBLES
# ─────────────────────────────────────────────


@app.route("/api/manifests")
def list_manifests():
    if not os.path.exists(_MANIFESTS):
        return jsonify([])
    result = []
    for fname in sorted(os.listdir(_MANIFESTS)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(_MANIFESTS, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                m = json.load(f)
            result.append(
                {
                    "path": fpath,
                    "filename": m.get("filename", fname),
                    "size": m.get("size", 0),
                    "file_id": m.get("file_id", ""),
                    "sender": m.get("sender_id", "")[:16],
                    "nb_chunks": m.get("nb_chunks", 0),
                }
            )
        except Exception:
            pass
    return jsonify(result)


# ─────────────────────────────────────────────
#  LANCEMENT
# ─────────────────────────────────────────────


def run_flask(port=5000):
    import logging

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
