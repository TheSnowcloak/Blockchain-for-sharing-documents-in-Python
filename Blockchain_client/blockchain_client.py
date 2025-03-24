# ------------------------------------------------------------------------
# blockchain_client.py
# 
# Python Flask client application for uploading files (optionally encrypted)
# and creating transactions on the blockchain.
# 
# Key notes:
#  - Connects to the Node via NODE_URL (change IP and port as needed).
#  - Accepts user input: public/private keys, file, etc.
#  - Optionally encrypts the file using AES GCM before sending.
#  - Signs the transaction on the client side (client-side signing).
#  - After successful upload, the local temp file is removed.
# ------------------------------------------------------------------------

import os
import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import requests
import datetime
import base64
import json
import logging

from Crypto.Cipher import AES
from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

from uuid import uuid4

app = Flask(__name__, static_folder='static', static_url_path='/static')
logging.basicConfig(level=logging.DEBUG)

# NODE_URL: The blockchain node's base URL (replace with your node's IP:port)
NODE_URL = "http://127.0.0.1:5000/"

# Upload folder for temporary client side usage
UPLOAD_FOLDER = './temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def sign_transaction(priv_hex, tx_dict):
    """
    Signs the transaction dictionary (tx_dict) using the private key
    in hexadecimal form (priv_hex). Returns signature as hex string.
    """
    s = json.dumps(tx_dict, sort_keys=True)
    priv_key = RSA.importKey(binascii.unhexlify(priv_hex))
    signer   = pkcs1_15.new(priv_key)
    h        = SHA256.new(s.encode('utf-8'))
    signature= signer.sign(h)
    return binascii.hexlify(signature).decode('ascii')

def encrypt_file_aes(file_bytes, key=None):
    """
    Encrypts the file_bytes using AES-256 GCM mode.
    Returns dict with ciphertext, nonce, tag, key.
    If key=None, a new random 256-bit key is generated.
    """
    if key is None:
        key = Crypto.Random.get_random_bytes(32)  # 256-bit
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext = cipher.encrypt(file_bytes)
    return {
        'ciphertext': ciphertext,
        'nonce': cipher.nonce,
        'tag': cipher.digest(),
        'key': key
    }

@app.route('/')
def client_index():
    """
    Displays the client home (to generate a new wallet).
    """
    return render_template('client_index.html')

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    """
    Generates a new wallet (public/private key pair).
    Keys are returned in DER-encoded hex form.
    """
    rgen = Crypto.Random.new().read
    priv = RSA.generate(1024, rgen)
    pub  = priv.publickey()
    return jsonify({
        "private_key": binascii.hexlify(priv.exportKey(format='DER')).decode('ascii'),
        "public_key":  binascii.hexlify(pub.exportKey(format='DER')).decode('ascii')
    }), 200

@app.route('/view/transactions', methods=['GET'])
def view_transactions():
    """
    Renders a page to view all transactions from the node's chain.
    """
    return render_template('view_transactions.html')

@app.route('/upload', methods=['GET','POST'])
def upload_form():
    """
    GET: Show the upload form.
    POST: Handle file upload, optional encryption, signing, then sending to Node.
    """
    if request.method == 'GET':
        return render_template('upload_file.html')

    needed = ['sender_public_key','sender_private_key','recipient_public_key']
    for n in needed:
        if n not in request.form or not request.form[n].strip():
            return jsonify({"error":f"Missing {n}"}),400

    upfile = request.files.get('file')
    if not upfile:
        return jsonify({"error":"Missing file"}),400

    orig_name = secure_filename(upfile.filename)
    if not orig_name:
        return jsonify({"error":"Invalid original filename"}),400

    timestr = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base,ext = os.path.splitext(orig_name)
    unique_name = f"{base}_{timestr}{ext}"
    local_abs = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)

    file_data = upfile.read()

    # Check if file is marked as sensitive (and should be encrypted)
    is_sensitive = request.form.get('is_sensitive', '0') == '1'

    # Prepare encryption info if needed
    enc_key_b64, enc_nonce_b64, enc_tag_b64 = None, None, None
    if is_sensitive:
        # Encrypt the file
        enc_result = encrypt_file_aes(file_data)
        with open(local_abs, 'wb') as f:
            f.write(enc_result['ciphertext'])

        key_b64   = base64.b64encode(enc_result['key']).decode('utf-8')
        nonce_b64 = base64.b64encode(enc_result['nonce']).decode('utf-8')
        tag_b64   = base64.b64encode(enc_result['tag']).decode('utf-8')
        enc_key_b64   = key_b64
        enc_nonce_b64 = nonce_b64
        enc_tag_b64   = tag_b64

        app.logger.info(f"*** SENSITIVE file => stored at {local_abs}")
        app.logger.info(f"   encryption key (base64) = {key_b64}")
        app.logger.info(f"   nonce = {nonce_b64}")
        app.logger.info(f"   tag   = {tag_b64}")
    else:
        # No encryption
        with open(local_abs, 'wb') as f:
            f.write(file_data)

    # Gather form data for transaction
    spub   = request.form['sender_public_key'].strip()
    spriv  = request.form['sender_private_key'].strip()
    rpub   = request.form['recipient_public_key'].strip()
    alias  = request.form.get('sender_alias','')
    ralias = request.form.get('recipient_alias','')

    tx_id  = str(uuid4().hex)

    partial_tx = {
        "tx_id":           tx_id,
        "sender":          spub,
        "recipient":       rpub,
        "file_name":       unique_name,
        "file_path":       f"./pending_uploads/{unique_name}",
        "alias":           alias,
        "recipient_alias": ralias,
        "is_sensitive":    "1" if is_sensitive else "0"
    }

    # Sign the transaction
    signature_hex = sign_transaction(spriv, partial_tx)

    files_part = {}
    data_part  = {
        'sender':           spub,
        'recipient':        rpub,
        'alias':            alias,
        'recipient_alias':  ralias,
        'signature':        signature_hex,
        'tx_id':            tx_id,
        'is_sensitive':     "1" if is_sensitive else "0"
    }

    # If the file is sensitive, attach encryption keys to the request
    if is_sensitive and enc_key_b64 and enc_nonce_b64 and enc_tag_b64:
        data_part['enc_key_b64']   = enc_key_b64
        data_part['enc_nonce_b64'] = enc_nonce_b64
        data_part['enc_tag_b64']   = enc_tag_b64

    # Prepare file for sending to the Node
    with open(local_abs, 'rb') as fh:
        files_part['file'] = (unique_name, fh)
        try:
            r = requests.post(f"{NODE_URL}/node/upload", files=files_part, data=data_part, timeout=15)
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Error connecting to node: {e}")
            return jsonify({"error":f"Connection error: {str(e)}"}),500

    # If Node accepted the transaction
    if r.status_code == 201:
        # Remove local temp file
        try:
            os.remove(local_abs)
        except OSError as e:
            app.logger.warning(f"Failed to remove temp file: {local_abs} => {e}")

        return jsonify(r.json()), 201
    else:
        # Node returned an error
        return jsonify({
            "error": f"Node error {r.status_code}",
            "detail": r.text
        }), r.status_code

if __name__ == '__main__':
    # Start the client on port 8081 (change as needed)
    app.run(host="0.0.0.0", port=8081)
