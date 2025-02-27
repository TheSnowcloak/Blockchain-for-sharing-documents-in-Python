# blockchain.py
# 
# Main Python Flask application that implements the Node (server side) for the blockchain.
# 
# Key highlights:
#  - Stores blocks, transactions, handles consensus, file uploads, etc.
#  - Has "trusted_nodes" vs "nodes" sets to filter out sensitive data from untrusted nodes.
#  - If is_sensitive="1", broadcast and file sync are restricted to trusted nodes only.
#  - The user must remember to set correct IP:port for each node using the register endpoints.

import os
import binascii
import json
import logging
import datetime
import time
import threading
import requests

from flask import Flask, jsonify, request, render_template, send_from_directory, send_file, abort
from flask_cors import CORS
from collections import OrderedDict
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from uuid import uuid4
from werkzeug.utils import secure_filename

from Crypto.Cipher import AES
import base64

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)

DATA_FILE       = 'blockchain_data.json'
KEYS_DB_FILE    = 'keys_db.json'      # store encryption keys for demonstration
MINING_SENDER   = "THE BLOCKCHAIN"

PENDING_FOLDER = './pending_uploads'
UPLOAD_FOLDER  = './uploads'
os.makedirs(PENDING_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER,  exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt','pdf','png','jpg','jpeg','gif','docx'}

###################################
# Utility to unify IP:port format
###################################
def normalize_netloc(address: str) -> str:
    """
    Removes 'http://' or 'https://', trailing '/',
    and if no port is specified, adds ':5000'.
    Example: 'http://11.222.33.44:5555/' -> '11.222.33.44:5555'
    """
    address = address.strip()
    if address.startswith("http://"):
        address = address[7:]
    elif address.startswith("https://"):
        address = address[8:]
    if address.endswith("/"):
        address = address[:-1]
    if ":" not in address:
        address += ":5000"
    return address

##############################################
# Encryption keys database (just for demonstration)
##############################################
def load_keys_db():
    if os.path.exists(KEYS_DB_FILE):
        with open(KEYS_DB_FILE,'r',encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_keys_db(keys_dict):
    with open(KEYS_DB_FILE,'w',encoding='utf-8') as f:
        json.dump(keys_dict, f, indent=2)

def store_encryption_keys(tx_id, key_b64, nonce_b64, tag_b64):
    db = load_keys_db()
    db[tx_id] = {
        "enc_key_b64":   key_b64,
        "enc_nonce_b64": nonce_b64,
        "enc_tag_b64":   tag_b64
    }
    save_keys_db(db)

def get_encryption_keys(tx_id):
    db = load_keys_db()
    return db.get(tx_id)

###################################
# Blockchain class
###################################
class Blockchain:
    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()           # "ip:port" for untrusted
        self.trusted_nodes = set()   # "ip:port" for trusted

        if os.path.exists(DATA_FILE):
            self.load_data()
            if len(self.chain) == 0:
                self.create_block(proof=100, previous_hash='1')
        else:
            self.create_block(proof=100, previous_hash='1')
            self.save_data()

        # Example: add "11.222.33.44:5555" to trusted nodes
        #self.trusted_nodes.add("11.222.33.44:5555")
        #self.save_data()

    def transaction_exists(self, tx_id):
        for t in self.transactions:
            if t.get("tx_id") == tx_id:
                return True
        for block in self.chain:
            for t in block["transactions"]:
                if t.get("tx_id") == tx_id:
                    return True
        return False

    def create_block(self, proof, previous_hash):
        # Move files from pending_uploads to uploads upon block creation
        for tx in self.transactions:
            fp = tx.get("file_path")
            if fp and fp.startswith("./pending_uploads/"):
                old_abs = os.path.join(".", fp)
                if os.path.exists(old_abs):
                    new_path = fp.replace("pending_uploads", "uploads", 1)
                    new_abs  = os.path.join(".", new_path)
                    os.makedirs(os.path.dirname(new_abs), exist_ok=True)
                    os.rename(old_abs, new_abs)
                    tx["file_path"] = new_path

        block = {
            "index":        len(self.chain) + 1,
            "timestamp":    str(datetime.datetime.now()),
            "transactions": self.transactions,
            "proof":        proof,
            "previous_hash": previous_hash
        }
        self.chain.append(block)
        self.transactions = []
        self.save_data()
        return block

    def add_transaction(self,
                        tx_id,
                        sender,
                        recipient,
                        file_name,
                        file_path,
                        alias,
                        recipient_alias,
                        signature,
                        is_sensitive="0"):
        # Ignore if transaction already in chain
        if self.transaction_exists(tx_id):
            logging.info(f"Transaction {tx_id} already known. Duplicate ignored.")
            return self.last_block['index']

        # Build transaction dictionary
        from collections import OrderedDict
        tr = OrderedDict({
            "tx_id":           tx_id,
            "sender":          sender,
            "recipient":       recipient,
            "file_name":       file_name,
            "file_path":       file_path,
            "alias":           alias,
            "recipient_alias": recipient_alias,
            "is_sensitive":    is_sensitive
        })

        # If not a mining reward, verify signature
        if sender != MINING_SENDER:
            if not self.verify_signature(sender, signature, tr):
                logging.error("Signature invalid!")
                return False

        self.transactions.append(tr)

        # Auto-mine if transaction queue >= 5
        if len(self.transactions) >= 5:
            logging.info("Reached 5 pending TX. Auto-mining new block.")
            last_block = self.last_block
            prev_hash  = self.hash(last_block)
            self.create_block(proof=100, previous_hash=prev_hash)

        return self.last_block['index']

    def verify_signature(self, sender_pub_hex, signature_hex, transaction):
        """
        Verifies the signature of the transaction using the sender's public key.
        """
        import json
        try:
            s = json.dumps(transaction, sort_keys=True)
            pub_key = RSA.importKey(binascii.unhexlify(sender_pub_hex))
            verifier = pkcs1_15.new(pub_key)
            h = SHA256.new(s.encode('utf-8'))
            verifier.verify(h, binascii.unhexlify(signature_hex))
            return True
        except (ValueError, TypeError, binascii.Error) as e:
            logging.error(f"Signature verify error: {e}")
            return False

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        import json
        s = json.dumps(block, sort_keys=True).encode()
        from Crypto.Hash import SHA256
        return SHA256.new(s).hexdigest()

    def valid_chain(self, chain):
        """
        Simple chain validity check: ensure each block's previous_hash matches
        the hash of the previous block.
        """
        last_block = chain[0]
        idx = 1
        while idx < len(chain):
            block = chain[idx]
            if block['previous_hash'] != self.hash(last_block):
                return False
            last_block = block
            idx += 1
        return True

    def resolve_conflicts(self):
        """
        Consensus mechanism: tries to fetch chain from trusted_nodes first,
        if no longer chain found, tries untrusted nodes.
        If a longer valid chain is found, we adopt it, then call sync_files.
        """
        replaced = False
        length_here = len(self.chain)
        new_chain = None

        # 1) Check trusted nodes
        for netloc in self.trusted_nodes:
            try:
                url = f"http://{netloc}/chain"
                r   = requests.get(url, timeout=4)
                if r.status_code == 200:
                    data = r.json()
                    chain_len  = data['length']
                    chain_data = data['chain']
                    if chain_len > length_here and self.valid_chain(chain_data):
                        length_here = chain_len
                        new_chain   = chain_data
            except requests.exceptions.RequestException:
                pass

        # 2) Then check untrusted if no better chain found
        if not new_chain:
            untrusted = self.nodes - self.trusted_nodes
            for netloc in untrusted:
                try:
                    url = f"http://{netloc}/chain"
                    r   = requests.get(url, timeout=4)
                    if r.status_code == 200:
                        data = r.json()
                        chain_len  = data['length']
                        chain_data = data['chain']
                        if chain_len > length_here and self.valid_chain(chain_data):
                            length_here = chain_len
                            new_chain   = chain_data
                except requests.exceptions.RequestException:
                    pass

        # If found a new chain, adopt it and sync files
        if new_chain:
            self.chain = new_chain
            self.sync_files()
            self.save_data()
            replaced = True
        return replaced

    def sync_files(self):
        """
        For each node (trusted or not), retrieve /chain. For each transaction:
        if is_sensitive=1 and the node is not in self.trusted_nodes => skip.
        Otherwise, try to download the file from /file/<filename>.
        """
        all_netlocs = self.nodes.union(self.trusted_nodes)
        for netloc in all_netlocs:
            try:
                url = f"http://{netloc}/chain"
                r   = requests.get(url, timeout=4)
                if r.status_code == 200:
                    cdata = r.json().get('chain', [])
                    for block in cdata:
                        for tx in block['transactions']:
                            if tx.get("is_sensitive","0") == "1" and netloc not in self.trusted_nodes:
                                continue
                            fp = tx.get("file_path", "")
                            if fp and fp.startswith("./uploads/"):
                                local_abs = os.path.join(".", fp)
                                if not os.path.exists(local_abs):
                                    fn = tx["file_name"]
                                    downurl = f"http://{netloc}/file/{fn}"
                                    try:
                                        fresp = requests.get(downurl, stream=True, timeout=4)
                                        if fresp.status_code == 200:
                                            os.makedirs(os.path.dirname(local_abs), exist_ok=True)
                                            with open(local_abs, 'wb') as f:
                                                for chunk in fresp.iter_content(4096):
                                                    f.write(chunk)
                                    except requests.exceptions.RequestException:
                                        pass
            except requests.exceptions.RequestException:
                pass

    def broadcast_new_transaction(self, tx_dict):
        """
        If transaction is sensitive => only broadcast to trusted_nodes,
        else broadcast to everyone.
        """
        if tx_dict.get("is_sensitive","0") == "1":
            targets = self.trusted_nodes
            logging.info("Broadcast CITLIVÉ => only to trusted nodes.")
        else:
            targets = self.nodes.union(self.trusted_nodes)

        for netloc in targets:
            try:
                url = f"http://{netloc}/transactions/new"
                data = dict(tx_dict)
                data["skip_broadcast"] = True
                requests.post(url, json=data, timeout=3)
            except requests.exceptions.RequestException as e:
                logging.warning(f"Broadcast to {netloc} failed: {e}")

    def save_data(self):
        data = {
            "chain":         self.chain,
            "nodes":         list(self.nodes),
            "trusted_nodes": list(self.trusted_nodes),
            "transactions":  self.transactions
        }
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        logging.info("Blockchain data saved.")

    def load_data(self):
        """
        Loads chain, nodes, and transactions from DATA_FILE.
        Normalizes netloc for both self.nodes and self.trusted_nodes.
        """
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                d = json.load(f)
            new_nodes = set()
            for item in d.get("nodes", []):
                new_nodes.add(normalize_netloc(item))
            new_trusted = set()
            for item in d.get("trusted_nodes", []):
                new_trusted.add(normalize_netloc(item))

            self.chain         = d.get("chain", [])
            self.nodes         = new_nodes
            self.trusted_nodes = new_trusted
            self.transactions  = d.get("transactions", [])
        else:
            self.chain = []
            self.nodes = set()
            self.trusted_nodes = set()
            self.transactions = []

    def add_node(self, address):
        """
        Called by /nodes/register endpoint. Takes an address, normalizes it,
        and adds it to self.nodes.
        """
        address = normalize_netloc(address)
        self.nodes.add(address)
        self.save_data()

    def remove_node(self, address):
        address = normalize_netloc(address)
        if address in self.nodes:
            self.nodes.remove(address)
            self.save_data()
            return True
        return False

    def add_trusted_node(self, address):
        """
        Called by /trusted_nodes/register endpoint. Takes an address, normalizes it,
        and adds it to self.trusted_nodes.
        """
        address = normalize_netloc(address)
        self.trusted_nodes.add(address)
        self.save_data()

    def remove_trusted_node(self, address):
        address = normalize_netloc(address)
        if address in self.trusted_nodes:
            self.trusted_nodes.remove(address)
            self.save_data()
            return True
        return False

# Create the global Blockchain instance
blockchain = Blockchain()
node_identifier = str(uuid4()).replace('-', '')

app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

@app.route('/')
def node_index():
    """
    Renders the minimal Node index page (node_index.html).
    """
    return render_template('node_index.html')

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "OK"}), 200

@app.route('/configure', methods=['GET'])
def configure():
    """
    Renders the configuration page to add/remove nodes, see if they're online, etc.
    """
    return render_template('configure.html')

@app.route('/mine', methods=['GET'])
def mine():
    """
    Example method to auto-mine a new block with a mining reward.
    """
    last_block = blockchain.last_block
    proof = 100
    blockchain.add_transaction(
        tx_id=str(uuid4().hex),
        sender=MINING_SENDER,
        recipient=node_identifier,
        file_name=None,
        file_path=None,
        alias="Manually mined block",
        recipient_alias="",
        signature=""
    )
    prev_hash = blockchain.hash(last_block)
    block = blockchain.create_block(proof, prev_hash)
    return jsonify({
        "message":"New block forged",
        "index": block["index"],
        "transactions": block["transactions"],
        "proof": block["proof"],
        "previous_hash": block["previous_hash"]
    }), 200

@app.route('/chain', methods=['GET'])
def get_chain():
    """
    If caller is trusted (based on IP), returns the full chain,
    otherwise prunes out is_sensitive=1 transactions.
    """
    caller_ip = request.remote_addr
    is_trusted = False
    for netloc in blockchain.trusted_nodes:
        base_ip = netloc.split(":")[0]
        if base_ip == caller_ip:
            is_trusted = True
            break

    import copy
    pruned_chain = []
    for block in blockchain.chain:
        blockcopy = copy.deepcopy(block)
        if not is_trusted:
            new_txs = []
            for tx in blockcopy["transactions"]:
                if tx.get("is_sensitive","0") == "1":
                    pass
                else:
                    new_txs.append(tx)
            blockcopy["transactions"] = new_txs
        pruned_chain.append(blockcopy)

    return jsonify({"chain": pruned_chain, "length": len(pruned_chain)}),200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    data = request.get_json() or {}
    skip_broadcast = data.pop("skip_broadcast", False)

    if "tx_id" not in data:
        data["tx_id"] = str(uuid4().hex)

    needed = ["tx_id","sender","recipient","file_name","file_path","signature"]
    if not all(k in data for k in needed):
        return "Missing values",400

    idx = blockchain.add_transaction(
        tx_id           = data["tx_id"],
        sender          = data['sender'],
        recipient       = data['recipient'],
        file_name       = data['file_name'],
        file_path       = data['file_path'],
        alias           = data.get('alias',''),
        recipient_alias = data.get('recipient_alias',''),
        signature       = data['signature'],
        is_sensitive    = data.get('is_sensitive','0')
    )
    if not idx:
        return "Invalid signature",400

    if idx and not skip_broadcast:
        blockchain.broadcast_new_transaction(data)

    return jsonify({"message": f"Transaction will be added to block {idx}"}),201

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    """
    Returns the current list of pending transactions (not yet in a block).
    """
    return jsonify({"transactions": blockchain.transactions}),200

@app.route('/file/<filename>', methods=['GET'])
def get_file(filename):
    """
    Returns the file from ./uploads, either plaintext or ciphertext if is_sensitive=1.
    """
    try:
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)
    except FileNotFoundError:
        abort(404,"File not found")

@app.route('/decrypt/<tx_id>', methods=['GET'])
def decrypt_file(tx_id):
    """
    DEMO endpoint that the Node can use to decrypt a sensitive file
    if we have stored the AES key, nonce, tag in keys_db.json.
    Returns the original content as a downloadable file.
    """
    file_name = None
    for block in blockchain.chain:
        for tx in block["transactions"]:
            if tx.get("tx_id") == tx_id:
                if tx.get("is_sensitive","0") != "1":
                    return jsonify({"error":"Not a sensitive TX"}),400
                file_name = tx.get("file_name")
                break
        if file_name:
            break

    if not file_name:
        return jsonify({"error":"Transaction not found or not sensitive."}),404

    enc_info = get_encryption_keys(tx_id)
    if not enc_info:
        return jsonify({"error":"No encryption info stored for this TX"}),404

    up_abs = os.path.join(UPLOAD_FOLDER, file_name)
    if not os.path.exists(up_abs):
        return jsonify({"error":"File not found in ./uploads"}),404

    with open(up_abs, 'rb') as f:
        ciphertext = f.read()

    key_b   = base64.b64decode(enc_info["enc_key_b64"])
    nonce_b = base64.b64decode(enc_info["enc_nonce_b64"])
    tag_b   = base64.b64decode(enc_info["enc_tag_b64"])

    try:
        cipher = AES.new(key_b, AES.MODE_GCM, nonce=nonce_b)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag_b)
    except ValueError as e:
        return jsonify({"error":f"Decrypt error: {e}"}),400

    from io import BytesIO
    bio = BytesIO(plaintext)
    bio.seek(0)

    ext = os.path.splitext(file_name)[1].lower()
    ct_map = {
        '.pdf': 'application/pdf',
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.txt': 'text/plain'
    }
    content_type = ct_map.get(ext, 'application/octet-stream')
    dec_name = "decrypted_" + file_name

    return send_file(bio,
                     as_attachment=True,
                     download_name=dec_name,
                     mimetype=content_type)

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    if request.is_json:
        val   = request.get_json()
        node_netlocs = val.get('nodes')
    else:
        node_netlocs = request.form.get('nodes','').split(',')

    if not node_netlocs:
        return "Error: no nodes",400

    for netloc in node_netlocs:
        blockchain.add_node(netloc.strip())

    return jsonify({
        "message": "Nodes added",
        "total_nodes": list(blockchain.nodes)
    }),201

@app.route('/nodes/remove', methods=['POST'])
def remove_node():
    d = request.get_json() or {}
    if 'node' not in d:
        return jsonify({"message":"Missing node address"}),400

    rm = d['node'].strip()
    rem = blockchain.remove_node(rm)
    if rem:
        return jsonify({"message": f"Node {rm} removed"}),200
    return jsonify({"message":"Node not found"}),404

@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    return jsonify({"total_nodes": list(blockchain.nodes)}),200

@app.route('/trusted_nodes/register', methods=['POST'])
def register_trusted_nodes():
    if request.is_json:
        val = request.get_json()
        node_netlocs = val.get('nodes')
    else:
        node_netlocs = request.form.get('nodes','').split(',')

    if not node_netlocs:
        return jsonify({"message": "No trusted nodes"}),400

    for netloc in node_netlocs:
        blockchain.add_trusted_node(netloc.strip())

    return jsonify({
        "message": "Trusted nodes added",
        "trusted_nodes": list(blockchain.trusted_nodes)
    }),201

@app.route('/trusted_nodes/remove', methods=['POST'])
def remove_trusted_node():
    d = request.get_json() or {}
    if 'node' not in d:
        return jsonify({"message":"Missing node address"}),400

    rm = d['node'].strip()
    rem = blockchain.remove_trusted_node(rm)
    if rem:
        return jsonify({"message": f"Trusted node {rm} removed"}),200
    return jsonify({"message":"Trusted node not found"}),404

@app.route('/trusted_nodes/get', methods=['GET'])
def get_trusted_nodes():
    return jsonify({
        "trusted_nodes": list(blockchain.trusted_nodes)
    }),200

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({"message":"Chain replaced"}),200
    return jsonify({"message":"Chain is authoritative"}),200

@app.route('/sync', methods=['GET'])
def manual_sync():
    blockchain.sync_files()
    return jsonify({"message":"sync done"}),200

def auto_sync_conflicts(interval=10):
    """
    Periodically calls resolve_conflicts() in a background thread.
    Default interval = 10s. Adjust as needed.
    """
    while True:
        time.sleep(interval)
        replaced = blockchain.resolve_conflicts()
        if replaced:
            logging.info("Chain replaced.")
        else:
            logging.info("Chain is authoritative.")

if __name__ == "__main__":
    t = threading.Thread(target=auto_sync_conflicts, args=(10,), daemon=True)
    t.start()
    # This node listens on port 5000 by default.
    app.run(host="0.0.0.0", port=5000)
