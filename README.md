# Archipel : Protocole P2P Souverain

<!--toc:start-->
- [Archipel : Protocole P2P Souverain](#archipel-protocole-p2p-souverain)
  - [Description du projet](#description-du-projet)
    - [Archipel : Le Protocole P2P Souverain](#archipel-le-protocole-p2p-souverain)
    - [La Mission (24H)](#la-mission-24h)
    - [Les Trois Piliers Fondamentaux](#les-trois-piliers-fondamentaux)
    - [Contrainte Absolue](#contrainte-absolue)
  - [Choix Technologiques](#choix-technologiques)
  - [Architecture du Protocole](#architecture-du-protocole)
  - [Format des Paquets](#format-des-paquets)
  - [Gestion des Clés PKI (Identité et Sécurité)](#gestion-des-clés-pki-identité-et-sécurité)
<!--toc:end-->

## Description du projet

### Archipel : Le Protocole P2P Souverain

Développé dans le cadre du hackathon "The Geek & The Moon" à la Lomé Business School, Archipel est une réponse technologique à la fragilité des infrastructures internet modernes.

La mission est claire : concevoir un protocole de communication P2P (Peer-to-Peer) capable de fonctionner en autarcie complète, sans serveur central, sans DNS et sans autorité de certification.

### La Mission (24H)

Créer un réseau local souverain où chaque nœud est à la fois client et serveur, "inspiré de BitTorrent, blindé comme Signal".

### Les Trois Piliers Fondamentaux

- Décentralisation Totale : Aucune donnée ne transite par un serveur tiers. La découverte des pairs s'effectue directement sur le réseau local ad-hoc.
- Segmentation des Données (Chunking) : Fichiers et messages sont fragmentés en blocs pour un transfert parallèle optimisé et une tolérance accrue aux pannes de nœuds.
- Chiffrement de Bout-en-Bout (E2EE) : Chaque paquet est chiffré avant émission. Les données ne circulent jamais en clair sur le réseau local.

### Contrainte Absolue

*ZÉRO CONNEXION INTERNET.* Le prototype doit fonctionner exclusivement sur un réseau local ad-hoc pur. Toute tentative de connexion vers l'extérieur entraînera une disqualification immédiate.

## Choix Technologiques

Pour garantir la sécurité, la performance et la rapidité de développement lors du hackathon de 24h, nous utilisons la stack suivante :

- Langage principal : Python (Choisi pour sa rapidité de prototypage et sa syntaxe concise).
- Transport Local :
  - UDP Multicast (239.255.42.99:6000) : Découverte automatique et annonce des pairs.
  - TCP Sockets : Transfert fiable et sécurisé des données (fichiers/messages).
- Cryptographie & Sécurité :
  - PyNaCl (libsodium) : Implémentation robuste de Ed25519 (Identité/Signatures) et X25519 (Échange de clés/Handshake).
  - PyCryptodome : Implémentation de AES-256-GCM (Chiffrement symétrique authentifié) et HMAC-SHA256 (Intégrité des paquets).

## Architecture du Protocole

```
RÉSEAU LOCAL (LAN) - 239.255.42.99:6000 (UDP Multicast)
──────────────────────────────────────────────────────────────────────────
   ▲ (Beacon) HELLO (0x01)     ▲ (Beacon) HELLO (0x01)     ▲ (Beacon) HELLO (0x01)
   │ (Manifest) MANIFEST (0x06)│ (Manifest) MANIFEST (0x06)│ (Manifest) MANIFEST (0x06)
   │                           │                           │
┌──┴──────────────┐         ┌──┴──────────────┐         ┌──┴──────────────┐
│     NODE A      │         │     NODE B      │         │     NODE C      │
│ ip:192.168.1.10 │         │ ip:192.168.1.11 │         │ ip:192.168.1.12 │
│ port: 50001     │         │ port: 50002     │         │ port: 50003     │
├─────────────────┤         ├─────────────────┤         ├─────────────────┤
│ Ed25519 PKI     │         │ Ed25519 PKI     │         │ Ed25519 PKI     │
│ Peer Table      │         │ Peer Table      │         │ Peer Table      │
│ Local Index(DB) │         │ Local Index(DB) │         │ Local Index(DB) │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
         │ TCP CONNEXIONS (Tunnels chiffrés AES-256-GCM)         │
         │                                                       │
         ├───────────────────────────┤                           │
         │  MSG (0x03) Chat          │                           │
         │◄─────────────────────────►│                           │
         │                           │                           │
         │ CHUNK_REQ (0x04)          │                           │
         │──────────────────────────►│                           │
         │ CHUNK_DATA (0x05)         │                           │
         │◄──────────────────────────│                           │
         │                           │                           │
         │           TCP Tunnel A-C (via routage B)              │
         │           (Récupération chunks sur Node C)            │
         │◄─────────────────────────────────────────────────────►│
         │                                                       │
```

## Format des Paquets

Chaque échange respecte la structure binaire Archipel v1:

| Champ | Taille | Description |
| --------------- | --------------- | --------------- |
| MAGIC | 4 bytes | Identifiant ARCH (0x41524348) |
| TYPE | 1 byte | Type de paquet (HELLO, MSG, CHUNK, etc.) |
| NODE ID | 32 bytes | Clé publique Ed25519 de l'émetteur |
| PAYLOAD LEN | 4 bytes | Longueur du contenu (uint32_BE) |
| PAYLOAD | Variable | Données chiffrées |
| SIGNATURE | 32 bytes | HMAC-SHA256 sur l'ensemble du paquet |

## Gestion des Clés PKI (Identité et Sécurité)

Conformément aux exigences du Sprint 0, chaque nœud Archipel génère sa propre identité cryptographique unique dès son premier lancement. Cette approche garantit une décentralisation totale sans autorité de certification centrale.

1. Paire de Clés (Algorithme Ed25519)

Lors de l'initialisation, le nœud génère une paire de clés Ed25519 via la bibliothèque PyNaCl :

- Clé Privée : Stockée localement de manière sécurisée (non versionnée sur Git). Elle sert à signer numériquement les paquets sortants pour garantir leur authenticité.
- Clé Publique (Node ID) : Diffusée sur le réseau local via le paquet 0x01 HELLO. Elle sert d'identifiant unique pour le nœud.

1. Sécurisation des Communications (X25519 & AES-GCM)

Pour le transfert de fichiers et les messages privés, une session chiffrée de bout-en-bout (E2EE) est établie :

- Handshake : Utilisation de X25519 (ECDH) pour échanger des clés éphémères et dériver un secret partagé unique pour chaque conversation.
- Chiffrement : Utilisation de AES-256-GCM (via pycryptodome) pour chiffrer et authentifier le contenu des données.

```python
import os
from nacl.signing import SigningKey
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

def generate_pki_keys():
    """Génère et sauvegarde la paire de clés Ed25519 pour Archipel."""
    
    # Génération de la paire de clés (Privée et Publique)
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    # Chemin des fichiers de clés
    private_key_path = ".keys/private.key"
    public_key_path = ".keys/public.key"

    # Créer le dossier keys s'il n'existe pas
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)

    # Sauvegarde de la clé privée (à ne jamais partager)
    with open(private_key_path, "wb") as f:
        f.write(signing_key.encode())
    
    # Sauvegarde de la clé publique (votre Node ID, à partager via HELLO)
    with open(public_key_path, "wb") as f:
        f.write(verify_key.encode())

    print(f"Clés PKI générées avec succès !")
    print(f"Node ID (Clé Publique) : {verify_key.encode().hex()}")
    print(f"Clé privée sauvegardée dans : {private_key_path}")
    print(f"NE PARTAGEZ JAMAIS LA CLÉ PRIVÉE.")

if __name__ == "__main__":
    generate_pki_keys()
```

## Format des Paquets Binaires

Tous les échanges réseau utilisent une sérialisation binaire compacte pour optimiser la bande passante.

1. Header Commun (Tous paquets)

Chaque paquet commence par un header de 33 octets permettant d'identifier le type de message et l'expéditeur.

| Taille | Type | Description |
| --------------- | --------------- | --------------- |
| 1 octet | uint8 | Type de packet (`0x1`=HELLO, `0x2`=MSG, ...) |
| 32 octets | bytes | NODE_ID (Clé publique ed25519 de l'expéditeur) |

1. Paquet HELLO (`0x01`)

Utilisé pour la découverte (UDP Multicast).

| Taille | Type | Description |
| --------------- | --------------- | --------------- |
| 1 octet | uint8 | Type (`0x01`) |
| 32 octets | bytes | NODE_ID de l'expéditeur |
| 2 octets | uint16 | Port TCP sur lequel le noeud écoute |
