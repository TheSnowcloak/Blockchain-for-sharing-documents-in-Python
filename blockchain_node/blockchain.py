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
import re
import socket
import ipaddress
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, render_template, send_from_directory, send_file, abort
from flask_cors import CORS
from collections import OrderedDict, deque
from collections.abc import Mapping
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
_keys_db_lock = threading.RLock()
VALIDATOR_IDENTITY_FILE = 'validator_identity.json'
MINING_SENDER   = "THE BLOCKCHAIN"

PENDING_FOLDER = './pending_uploads'
UPLOAD_FOLDER  = './uploads'
os.makedirs(PENDING_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER,  exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt','pdf','png','jpg','jpeg','gif','docx'}

SYNC_CHAIN_TIMEOUT = float(os.getenv("SYNC_CHAIN_TIMEOUT", "4"))
SYNC_DOWNLOAD_TIMEOUT = float(os.getenv("SYNC_DOWNLOAD_TIMEOUT", "4"))
SYNC_MAX_RETRIES = int(os.getenv("SYNC_MAX_RETRIES", "3"))
SYNC_BACKOFF_INITIAL = float(os.getenv("SYNC_BACKOFF_INITIAL", "0.5"))
SYNC_BACKOFF_MULTIPLIER = float(os.getenv("SYNC_BACKOFF_MULTIPLIER", "2"))
SYNC_FAILURE_LOG_SIZE = int(os.getenv("SYNC_FAILURE_LOG_SIZE", "200"))
SYNC_DEFERRED_RETRY_LIMIT = int(os.getenv("SYNC_DEFERRED_RETRY_LIMIT", "3"))
SYNC_DEFERRED_RETRY_DELAY = float(os.getenv("SYNC_DEFERRED_RETRY_DELAY", "15"))

_LOCAL_HOST_LOCK = threading.Lock()
_LOCAL_HOST_CACHE = None

def _ensure_safe_filename(name: str) -> str:
    safe_name = secure_filename(name)
    if not safe_name or safe_name != name:
        raise ValueError("Invalid filename")
    return safe_name


def _derive_canonical_stored_name(tx_id: str, file_name: str) -> str:
    """Return the canonical stored filename for a transaction."""

    if not tx_id:
        raise ValueError("tx_id is required")

    safe_file_name = _ensure_safe_filename(file_name)
    _, ext = os.path.splitext(safe_file_name)
    ext = ext.lower()
    canonical = f"{tx_id}{ext}" if ext else tx_id
    return _ensure_safe_filename(canonical)

def _is_safe_subpath(path_value: str, base_directory: str) -> bool:
    if not path_value:
        return False
    if os.path.isabs(path_value):
        return False
    normalized = os.path.normpath(path_value)
    if normalized.startswith('..'):
        return False
    abs_base = os.path.abspath(base_directory)
    abs_target = os.path.abspath(os.path.join('.', normalized.lstrip('./')))
    return abs_target.startswith(os.path.join(abs_base, ''))


def _coerce_node_entries(raw_value):
    """Return a flat list of node strings from a flexible payload."""

    def _split_simple(text: str):
        parts = re.split(r'[\s,;]+', text)
        cleaned = []
        for part in parts:
            candidate = part.strip()
            if not candidate:
                continue
            if '=' in candidate:
                candidate = candidate.split('=', 1)[1].strip()
                if not candidate:
                    continue
            cleaned.append(candidate)
        return cleaned

    if raw_value is None:
        return []

    if isinstance(raw_value, dict):
        nodes = []
        if 'nodes' in raw_value:
            nodes.extend(_coerce_node_entries(raw_value['nodes']))
        if 'node' in raw_value:
            nodes.extend(_coerce_node_entries(raw_value['node']))
        return nodes

    if isinstance(raw_value, (list, tuple, set)):
        nodes = []
        for item in raw_value:
            nodes.extend(_coerce_node_entries(item))
        return nodes

    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return []

        # Handle strings that look like JSON structures.
        if (text.startswith('[') and text.endswith(']')) or (text.startswith('{') and text.endswith('}')):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                pass
            else:
                return _coerce_node_entries(parsed)

        if text.startswith('"') and text.endswith('"') and len(text) >= 2:
            return _coerce_node_entries(text[1:-1])

        return _split_simple(text)

    return []

###################################
# Utility to unify IP:port format
###################################
_SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')


def _parse_netloc(address: str):
    text = (address or "").strip()
    if not text:
        raise ValueError("Empty address")
    if _SCHEME_RE.match(text):
        parsed = urlsplit(text)
    else:
        parsed = urlsplit(f'//{text}')
    if not parsed.hostname:
        raise ValueError(f"Invalid address: {address!r}")
    return parsed


def _format_host_for_netloc(host: str) -> str:
    host = host.strip()
    if not host:
        raise ValueError("Empty host")
    if ':' in host and not host.startswith('['):
        return f'[{host}]'
    return host


def _split_host_port(netloc: str):
    try:
        parsed = _parse_netloc(netloc)
    except ValueError as exc:
        raise ValueError(f"Invalid netloc: {netloc!r}") from exc
    host = parsed.hostname
    port = parsed.port
    if host is None:
        raise ValueError(f"Invalid netloc: {netloc!r}")
    return host, port


def normalize_netloc(address: str) -> str:
    """Normalize a user supplied address into ``host:port`` format."""

    parsed = _parse_netloc(address)
    host = parsed.hostname.strip()
    port = parsed.port or 5000
    return f"{_format_host_for_netloc(host)}:{port}"


def _get_configured_self_netlocs():
    sources = []
    config_value = app.config.get("LOCAL_NODE_NETLOCS")
    if config_value:
        sources.append(config_value)
    env_value = os.getenv("LOCAL_NODE_NETLOCS")
    if env_value:
        sources.append(env_value)

    configured = []
    seen = set()
    for raw in sources:
        for entry in _coerce_node_entries(raw):
            try:
                normalized = normalize_netloc(entry)
            except ValueError:
                logging.warning("Ignoring invalid LOCAL_NODE_NETLOCS entry: %s", entry)
                continue
            if normalized not in seen:
                configured.append(normalized)
                seen.add(normalized)
    return tuple(configured)


def _get_known_local_hosts():
    global _LOCAL_HOST_CACHE
    with _LOCAL_HOST_LOCK:
        if _LOCAL_HOST_CACHE is not None:
            return _LOCAL_HOST_CACHE

    hosts = {"localhost", "127.0.0.1", "::1"}
    for getter in (socket.gethostname, socket.getfqdn):
        try:
            value = getter()
        except OSError:
            continue
        if not value:
            continue
        hosts.add(value)
        try:
            _name, _alias, ip_list = socket.gethostbyname_ex(value)
        except (socket.gaierror, UnicodeError):
            ip_list = []
        hosts.update(ip_list)

    with _LOCAL_HOST_LOCK:
        _LOCAL_HOST_CACHE = tuple(hosts)
    return _LOCAL_HOST_CACHE


def _host_header_matches_local(host_netloc, configured_netlocs, resolver):
    try:
        host, _ = _split_host_port(host_netloc)
    except ValueError:
        return False

    allowed_hosts = set(_get_known_local_hosts())

    for netloc in configured_netlocs:
        try:
            cfg_host, _ = _split_host_port(netloc)
        except ValueError:
            continue
        allowed_hosts.add(cfg_host)
        for ip_item in resolver(cfg_host):
            allowed_hosts.add(ip_item)

    if host in allowed_hosts:
        return True

    for resolved in resolver(host):
        if resolved in allowed_hosts:
            return True

    return False

##############################################
# Encryption keys database (just for demonstration)
##############################################
def _load_keys_db_unlocked():
    if os.path.exists(KEYS_DB_FILE):
        with open(KEYS_DB_FILE,'r',encoding='utf-8') as f:
            return json.load(f)
    return {}


def _save_keys_db_unlocked(keys_dict):
    with open(KEYS_DB_FILE,'w',encoding='utf-8') as f:
        json.dump(keys_dict, f, indent=2)


def load_keys_db():
    with _keys_db_lock:
        return _load_keys_db_unlocked()


def save_keys_db(keys_dict):
    with _keys_db_lock:
        _save_keys_db_unlocked(keys_dict)


def store_encryption_keys(tx_id, key_b64, nonce_b64, tag_b64):
    with _keys_db_lock:
        db = _load_keys_db_unlocked()
        db[tx_id] = {
            "enc_key_b64":   key_b64,
            "enc_nonce_b64": nonce_b64,
            "enc_tag_b64":   tag_b64
        }
        _save_keys_db_unlocked(db)


def delete_encryption_keys(tx_id):
    with _keys_db_lock:
        db = _load_keys_db_unlocked()
        if tx_id in db:
            del db[tx_id]
            _save_keys_db_unlocked(db)
            return True
        return False


def get_encryption_keys(tx_id):
    db = load_keys_db()
    return db.get(tx_id)


###################################
# Blockchain class
###################################
class Blockchain:
    def __init__(self):
        self._lock = threading.RLock()
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.trusted_nodes = set()
        self._trusted_resolution_cache = {}
        self.sync_chain_timeout = SYNC_CHAIN_TIMEOUT
        self.sync_download_timeout = SYNC_DOWNLOAD_TIMEOUT
        self.sync_max_retries = max(1, SYNC_MAX_RETRIES)
        self.sync_backoff_initial = max(0.0, SYNC_BACKOFF_INITIAL)
        self.sync_backoff_multiplier = max(1.0, SYNC_BACKOFF_MULTIPLIER)
        self.deferred_retry_limit = max(0, SYNC_DEFERRED_RETRY_LIMIT)
        self.deferred_retry_delay = max(0.0, SYNC_DEFERRED_RETRY_DELAY)
        self.sync_failure_log = deque(maxlen=max(1, SYNC_FAILURE_LOG_SIZE))
        self._sync_failure_lock = threading.Lock()
        self._deferred_retry_lock = threading.Lock()
        self._pending_deferred_retries = {}

        self.validator_public_keys = {}
        self.quorum_threshold = 1
        self.validator_id = None
        self.validator_public_key_hex = None
        self.validator_private_key_hex = None
        self.validator_netloc = None
        self.validator_key_id = None

        self.load_validator_identity()

        if os.path.exists(DATA_FILE):
            self.load_data()
            if len(self.chain) == 0:
                self.create_block(proof=100, previous_hash='1', system_override=True)
        else:
            self.create_block(proof=100, previous_hash='1', system_override=True)
            self.save_data()

    @property
    def lock(self):
        return self._lock

    def _find_transaction_location_unlocked(self, tx_id):
        for transaction in self.transactions:
            if transaction.get("tx_id") == tx_id:
                return "pending"
        for block in self.chain:
            for transaction in block.get("transactions", []):
                if transaction.get("tx_id") == tx_id:
                    return block.get("index")
        return None

    def transaction_exists(self, tx_id):
        with self._lock:
            return self._find_transaction_location_unlocked(tx_id) is not None

    def get_transaction_by_id(self, tx_id):
        with self._lock:
            for transaction in self.transactions:
                if transaction.get("tx_id") == tx_id:
                    return dict(transaction)
            for block in self.chain:
                for transaction in block.get("transactions", []):
                    if transaction.get("tx_id") == tx_id:
                        return dict(transaction)
        return None

    def create_block(self, proof, previous_hash, system_override=False):
        with self._lock:
            for tx in self.transactions:
                file_path = tx.get("file_path")
                if not file_path:
                    tx.pop("stored_file_name", None)
                    continue

                target_path = file_path
                if file_path.startswith("./pending_uploads/"):
                    target_path = file_path.replace("pending_uploads", "uploads", 1)
                    old_abs = os.path.join(".", file_path)
                    new_abs = os.path.join(".", target_path)
                    if os.path.exists(old_abs):
                        os.makedirs(os.path.dirname(new_abs), exist_ok=True)
                        os.rename(old_abs, new_abs)
                elif not file_path.startswith("./uploads/"):
                    target_path = os.path.join("./uploads", os.path.basename(file_path))

                tx["file_path"] = target_path
                stored_name = os.path.basename(os.path.normpath(target_path)) if target_path else None
                if stored_name:
                    tx["stored_file_name"] = stored_name
                else:
                    tx.pop("stored_file_name", None)

            if not system_override and not self.is_authorized_validator():
                raise PermissionError("This node is not authorized to propose blocks.")

            block = {
                "index": len(self.chain) + 1,
                "timestamp": str(datetime.datetime.now()),
                "transactions": list(self.transactions),
                "proof": proof,
                "previous_hash": previous_hash,
            }

            if system_override:
                block["validator_id"] = self.validator_id or "GENESIS"
                block["validator_signatures"] = []
            else:
                block["validator_id"] = self.validator_id
                signature_hex, key_id = self._sign_block(block)
                block["validator_signatures"] = [{
                    "validator_id": self.validator_id,
                    "signature": signature_hex,
                    "key_id": key_id,
                }]

            self.chain.append(block)
            self.transactions = []
            self.save_data()
            return block

    def _build_signable_transaction(self, transaction_dict):
        signable_fields = (
            "tx_id",
            "sender",
            "recipient",
            "file_name",
            "stored_file_name",
            "alias",
            "recipient_alias",
            "is_sensitive",
        )
        return OrderedDict((field, transaction_dict.get(field, "")) for field in signable_fields)

    def _normalize_and_validate_file_owner(self, file_owner):
        if not file_owner:
            return None

        try:
            normalized = normalize_netloc(file_owner)
        except ValueError as exc:
            raise ValueError(f"Invalid file_owner value: {file_owner!r}") from exc

        allowed = set(_get_configured_self_netlocs())
        allowed.update(self.nodes)
        allowed.update(self.trusted_nodes)

        validator_netloc = self.validator_netloc
        if validator_netloc:
            try:
                allowed.add(normalize_netloc(validator_netloc))
            except ValueError:
                logging.warning("Validator netloc is invalid: %s", validator_netloc)

        if normalized not in allowed:
            raise ValueError("file_owner must reference this node or a registered peer")

        return normalized

    def add_transaction(
        self,
        tx_id,
        sender,
        recipient,
        file_name,
        file_path,
        alias,
        recipient_alias,
        signature,
        is_sensitive="0",
        file_owner=None,
        stored_file_name=None,
        allow_system_transaction=False,
    ):
        with self._lock:
            existing_location = self._find_transaction_location_unlocked(tx_id)
            if existing_location is not None:
                logging.info(f"Transaction {tx_id} already known. Duplicate ignored.")
                return existing_location, False, False

            safe_file_name = None
            canonical_stored_name = None

            if file_name:
                try:
                    safe_file_name = _ensure_safe_filename(file_name)
                except ValueError as exc:
                    raise ValueError("Invalid file_name supplied") from exc
                canonical_stored_name = _derive_canonical_stored_name(tx_id, safe_file_name)
            elif not allow_system_transaction:
                raise ValueError("Invalid file_name supplied")

            transaction = OrderedDict({
                "tx_id": tx_id,
                "sender": sender,
                "recipient": recipient,
                "alias": alias,
                "recipient_alias": recipient_alias,
                "is_sensitive": is_sensitive,
            })

            if safe_file_name is not None:
                transaction["file_name"] = safe_file_name

            if canonical_stored_name is not None:
                if stored_file_name:
                    try:
                        provided_stored = _ensure_safe_filename(stored_file_name)
                    except ValueError as exc:
                        raise ValueError("Invalid stored_file_name supplied") from exc
                else:
                    provided_stored = canonical_stored_name

                if provided_stored != canonical_stored_name:
                    logging.warning(
                        "Stored filename mismatch for tx %s; expected %s, received %s. Using canonical value.",
                        tx_id,
                        canonical_stored_name,
                        provided_stored,
                    )

                transaction["stored_file_name"] = canonical_stored_name

            if file_path:
                if canonical_stored_name is None:
                    raise ValueError("file_path supplied without file metadata")

                if _is_safe_subpath(file_path, PENDING_FOLDER):
                    canonical_path = os.path.join(PENDING_FOLDER, canonical_stored_name)
                elif _is_safe_subpath(file_path, UPLOAD_FOLDER):
                    canonical_path = os.path.join(UPLOAD_FOLDER, canonical_stored_name)
                else:
                    raise ValueError("Invalid file_path supplied")
                transaction["file_path"] = canonical_path

            if sender == MINING_SENDER and not allow_system_transaction:
                raise ValueError("Transactions using the mining sender must be created internally")

            if sender != MINING_SENDER:
                signable = self._build_signable_transaction(transaction)
                if not self.verify_signature(sender, signature, signable):
                    logging.error("Signature invalid!")
                    return None, False, False

            if file_owner:
                normalized_owner = self._normalize_and_validate_file_owner(file_owner)
                if normalized_owner:
                    transaction["file_owner"] = normalized_owner

            predicted_index = self.last_block["index"] + 1
            self.transactions.append(transaction)
            self.save_data()

            mined_block = None
            if len(self.transactions) >= 5:
                logging.info("Reached 5 pending TX. Auto-mining new block.")
                last_block = self.last_block
                prev_hash = self.hash(last_block)
                try:
                    mined_block = self.create_block(proof=100, previous_hash=prev_hash)
                except PermissionError as exc:
                    logging.error(f"Auto-mining skipped: {exc}")
                    mined_block = None

            if mined_block:
                return mined_block.get("index"), True, True

            return predicted_index, True, False

    def verify_signature(self, sender_pub_hex, signature_hex, transaction):
        try:
            payload = json.dumps(transaction, sort_keys=True)
            pub_key = RSA.importKey(binascii.unhexlify(sender_pub_hex))
            verifier = pkcs1_15.new(pub_key)
            digest = SHA256.new(payload.encode("utf-8"))
            verifier.verify(digest, binascii.unhexlify(signature_hex))
            return True
        except (ValueError, TypeError, binascii.Error) as exc:
            logging.error(f"Signature verify error: {exc}")
            return False

    @property
    def last_block(self):
        with self._lock:
            if not self.chain:
                raise ValueError("Blockchain is empty")
            return self.chain[-1]

    @staticmethod
    def hash(block):
        payload = json.dumps(block, sort_keys=True).encode()
        return SHA256.new(payload).hexdigest()

    _REQUIRED_BLOCK_FIELDS = {"index", "timestamp", "transactions", "proof", "previous_hash"}

    def _is_valid_block_structure(self, block, position):
        if not isinstance(block, Mapping):
            logging.warning("Invalid block at position %s: expected mapping, got %s", position, type(block).__name__)
            return False

        missing = self._REQUIRED_BLOCK_FIELDS.difference(block.keys())
        if missing:
            logging.warning(
                "Block at position %s missing required fields: %s",
                position,
                ", ".join(sorted(missing)),
            )
            return False

        transactions_value = block.get("transactions")
        if not isinstance(transactions_value, list):
            logging.warning(
                "Block at position %s has invalid transactions field type: %s",
                position,
                type(transactions_value).__name__,
            )
            return False

        validator_signatures = block.get("validator_signatures")
        if validator_signatures is not None and not isinstance(validator_signatures, list):
            logging.warning(
                "Block at position %s has invalid validator_signatures type: %s",
                position,
                type(validator_signatures).__name__,
            )
            return False

        return True

    def valid_chain(self, chain):
        if not isinstance(chain, (list, tuple)):
            logging.warning(
                "Invalid chain structure: expected list/tuple, got %s",
                type(chain).__name__ if chain is not None else type(chain),
            )
            return False

        if not chain:
            logging.warning("Invalid chain structure: sequence is empty")
            return False

        if not self._is_valid_block_structure(chain[0], 0):
            return False

        last_block = chain[0]
        if not self.verify_block_signatures(last_block):
            return False

        for position, block in enumerate(chain[1:], start=1):
            if not self._is_valid_block_structure(block, position):
                return False

            previous_hash = block["previous_hash"]
            computed_hash = self.hash(last_block)
            if previous_hash != computed_hash:
                logging.warning(
                    "Block at position %s has mismatched previous_hash: expected %s, got %s",
                    position,
                    computed_hash,
                    previous_hash,
                )
                return False

            if not self.verify_block_signatures(block):
                return False

            last_block = block

        return True

    def _record_sync_failure(self, operation, netloc, filename=None, error=None, attempt=None, stage="immediate"):
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "operation": operation,
            "netloc": netloc,
            "filename": filename,
            "error": str(error) if error is not None else None,
            "attempt": attempt,
            "stage": stage,
        }
        with self._sync_failure_lock:
            self.sync_failure_log.append(entry)
        target = f"{operation} sync failure for {netloc}"
        if filename:
            target += f"/{filename}"
        extra = f" attempt {attempt}" if attempt is not None else ""
        logging.warning(f"{target}{extra} during {stage}: {error}")

    def _fetch_chain_with_retry(self, netloc):
        url = f"http://{netloc}/chain"
        delay = self.sync_backoff_initial
        for attempt in range(1, self.sync_max_retries + 1):
            try:
                response = requests.get(url, timeout=self.sync_chain_timeout)
                if response.status_code == 200:
                    try:
                        payload = response.json()
                    except (ValueError, json.JSONDecodeError) as exc:
                        self._record_sync_failure(
                            "chain",
                            netloc,
                            error=exc,
                            attempt=attempt,
                        )
                        continue
                    return payload.get("chain", [])
                self._record_sync_failure("chain", netloc, error=f"HTTP {response.status_code}", attempt=attempt)
            except requests.exceptions.RequestException as exc:
                self._record_sync_failure("chain", netloc, error=exc, attempt=attempt)
            if attempt < self.sync_max_retries and delay > 0:
                time.sleep(delay)
                if self.sync_backoff_multiplier > 1:
                    delay *= self.sync_backoff_multiplier
        return None

    def _download_file_with_retry(self, netloc, tx, local_abs, stage="immediate", attempt_offset=0):
        filename = tx.get("stored_file_name") or tx.get("file_name")
        if not filename:
            return False
        url = f"http://{netloc}/file/{filename}"
        delay = self.sync_backoff_initial
        for attempt in range(1, self.sync_max_retries + 1):
            try:
                response = requests.get(url, stream=True, timeout=self.sync_download_timeout)
                if response.status_code == 200:
                    os.makedirs(os.path.dirname(local_abs), exist_ok=True)
                    with open(local_abs, "wb") as f:
                        for chunk in response.iter_content(4096):
                            f.write(chunk)
                    return True
                self._record_sync_failure(
                    "download",
                    netloc,
                    filename=filename,
                    error=f"HTTP {response.status_code}",
                    attempt=attempt + attempt_offset,
                    stage=stage,
                )
            except requests.exceptions.RequestException as exc:
                self._record_sync_failure(
                    "download",
                    netloc,
                    filename=filename,
                    error=exc,
                    attempt=attempt + attempt_offset,
                    stage=stage,
                )
            if attempt < self.sync_max_retries and delay > 0:
                time.sleep(delay)
                if self.sync_backoff_multiplier > 1:
                    delay *= self.sync_backoff_multiplier
        return False

    def _clear_deferred_retry(self, key):
        with self._deferred_retry_lock:
            self._pending_deferred_retries.pop(key, None)

    def _schedule_deferred_retry(self, netloc, tx, attempt):
        if self.deferred_retry_limit == 0 or attempt > self.deferred_retry_limit:
            return
        file_path = tx.get("file_path")
        if not file_path:
            return
        normalized_path = os.path.normpath(file_path)
        safe_relative_path = os.path.join(
            ".", normalized_path.lstrip("./")
        )
        if not _is_safe_subpath(safe_relative_path, UPLOAD_FOLDER):
            self._record_sync_failure(
                "download",
                netloc,
                filename=tx.get("stored_file_name") or tx.get("file_name"),
                error=f"Rejected unsafe file path: {file_path}",
                attempt=attempt,
                stage="deferred-validation",
            )
            return
        key = (netloc, file_path)
        with self._deferred_retry_lock:
            current_attempt = self._pending_deferred_retries.get(key, 0)
            if attempt <= current_attempt:
                return
            self._pending_deferred_retries[key] = attempt

        if self.deferred_retry_delay > 0:
            delay = self.deferred_retry_delay * (self.sync_backoff_multiplier ** (attempt - 1))
        else:
            delay = 0
        logging.info(f"Scheduling deferred retry #{attempt} for {file_path} from {netloc} in {delay:.2f}s")
        timer = threading.Timer(delay, self._deferred_retry_worker, args=(netloc, dict(tx), attempt))
        timer.daemon = True
        timer.start()

    def _deferred_retry_worker(self, netloc, tx, attempt):
        file_path = tx.get("file_path")
        if not file_path:
            return
        key = (netloc, file_path)
        normalized_path = os.path.normpath(file_path)
        safe_relative_path = os.path.join(
            ".", normalized_path.lstrip("./")
        )
        if not _is_safe_subpath(safe_relative_path, UPLOAD_FOLDER):
            self._record_sync_failure(
                "download",
                netloc,
                filename=tx.get("stored_file_name") or tx.get("file_name"),
                error=f"Rejected unsafe file path: {file_path}",
                attempt=attempt,
                stage="deferred-validation",
            )
            self._clear_deferred_retry(key)
            return
        local_abs = safe_relative_path
        if os.path.exists(local_abs):
            self._clear_deferred_retry(key)
            return
        success = self._download_file_with_retry(netloc, tx, local_abs, stage="deferred", attempt_offset=attempt - 1)
        if success:
            self._clear_deferred_retry(key)
            return

        next_attempt = attempt + 1
        if next_attempt <= self.deferred_retry_limit:
            self._schedule_deferred_retry(netloc, tx, next_attempt)
        else:
            self._record_sync_failure(
                "download",
                netloc,
                filename=tx.get("stored_file_name") or tx.get("file_name"),
                error="Exceeded deferred retry limit",
                attempt=attempt,
                stage="deferred",
            )
            self._clear_deferred_retry(key)

    def get_sync_failures(self, limit=None):
        with self._sync_failure_lock:
            records = list(self.sync_failure_log)
        if limit is not None and limit > 0:
            records = records[-limit:]
        return [dict(item) for item in records]

    def resolve_conflicts(self):
        replaced = False
        with self._lock:
            current_length = len(self.chain)
            trusted_nodes = list(self.trusted_nodes)
            untrusted_nodes = [n for n in self.nodes if n not in self.trusted_nodes]
        best_chain = None
        best_length = current_length

        for netloc in trusted_nodes:
            chain_data = self._fetch_chain_with_retry(netloc)
            if not chain_data:
                continue
            if not isinstance(chain_data, (list, tuple)) or not all(isinstance(block, Mapping) for block in chain_data):
                logging.warning("Skipping invalid chain response from trusted peer %s", netloc)
                continue
            if len(chain_data) > best_length and self.valid_chain(chain_data):
                best_chain = chain_data
                best_length = len(chain_data)

        if best_chain is None:
            for netloc in untrusted_nodes:
                chain_data = self._fetch_chain_with_retry(netloc)
                if not chain_data:
                    continue
                if not isinstance(chain_data, (list, tuple)) or not all(isinstance(block, Mapping) for block in chain_data):
                    logging.warning("Skipping invalid chain response from peer %s", netloc)
                    continue
                if len(chain_data) > best_length and self.valid_chain(chain_data):
                    best_chain = chain_data
                    best_length = len(chain_data)

        if best_chain is not None:
            with self._lock:
                chain_tx_ids = {
                    tx.get("tx_id")
                    for block in best_chain
                    if isinstance(block, dict)
                    for tx in block.get("transactions", [])
                    if isinstance(tx, dict) and tx.get("tx_id")
                }
                self.chain = best_chain
                current_pending = list(self.transactions)
                removed_transactions = []
                if chain_tx_ids:
                    filtered_transactions = []
                    for tx in current_pending:
                        tx_id = tx.get("tx_id") if isinstance(tx, dict) else None
                        if tx_id and tx_id in chain_tx_ids:
                            removed_transactions.append(tx)
                        else:
                            filtered_transactions.append(tx)
                    self.transactions = filtered_transactions
                else:
                    self.transactions = current_pending
                if removed_transactions:
                    seen_paths = set()
                    for tx in removed_transactions:
                        file_path_value = tx.get("file_path")
                        if isinstance(file_path_value, str) and _is_safe_subpath(file_path_value, PENDING_FOLDER):
                            normalized = os.path.normpath(file_path_value)
                            candidate = os.path.join(".", normalized.lstrip("./"))
                            seen_paths.add(os.path.abspath(candidate))
                        stored_name = tx.get("stored_file_name")
                        if isinstance(stored_name, str) and stored_name:
                            normalized_name = os.path.normpath(stored_name)
                            if not normalized_name.startswith(".."):
                                candidate_rel = os.path.join(PENDING_FOLDER, normalized_name)
                                if _is_safe_subpath(candidate_rel, PENDING_FOLDER):
                                    candidate = os.path.join(
                                        ".",
                                        os.path.normpath(candidate_rel).lstrip("./"),
                                    )
                                    seen_paths.add(os.path.abspath(candidate))
                    for path in seen_paths:
                        try:
                            os.remove(path)
                        except FileNotFoundError:
                            continue
                        except OSError:
                            logging.warning("Failed to remove pending file %s", path, exc_info=True)
                self.save_data()
            self.sync_files()
            replaced = True
        return replaced

    @staticmethod
    def derive_public_key_hex(private_key_hex):
        priv_key = RSA.importKey(binascii.unhexlify(private_key_hex))
        return binascii.hexlify(priv_key.publickey().exportKey(format='DER')).decode('ascii')

    @staticmethod
    def derive_key_id(public_key_hex):
        try:
            digest = SHA256.new(binascii.unhexlify(public_key_hex))
        except (binascii.Error, TypeError, ValueError):
            return None
        return digest.hexdigest()

    @classmethod
    def _normalize_single_validator_keys(cls, value):
        normalized = OrderedDict()
        if isinstance(value, dict):
            items = value.items()
        elif isinstance(value, list):
            items = []
            for entry in value:
                if not isinstance(entry, dict):
                    continue
                pub_hex = entry.get("public_key_hex") or entry.get("public_key")
                key_id = entry.get("key_id")
                items.append((key_id, pub_hex))
        elif isinstance(value, str):
            items = [(None, value)]
        elif value is None:
            items = []
        else:
            items = []

        for key_id, pub_hex in items:
            if not isinstance(pub_hex, str):
                continue
            resolved_id = str(key_id) if key_id else cls.derive_key_id(pub_hex)
            if not resolved_id:
                continue
            normalized[resolved_id] = pub_hex
        return normalized

    @classmethod
    def _normalize_validator_key_dict(cls, raw):
        normalized = {}
        if not isinstance(raw, dict):
            return normalized
        for validator_id, value in raw.items():
            normalized[str(validator_id)] = cls._normalize_single_validator_keys(value)
        return normalized

    def _ensure_validator_keys_mapping(self, validator_id):
        normalized = self._normalize_single_validator_keys(
            self.validator_public_keys.get(validator_id)
        )
        self.validator_public_keys[validator_id] = normalized
        return normalized

    def _record_validator_public_key(self, validator_id, public_key_hex):
        if not validator_id:
            raise ValueError("validator_id is required")
        if not isinstance(public_key_hex, str):
            raise ValueError("public_key_hex must be a string")

        key_id = self.derive_key_id(public_key_hex)
        if not key_id:
            raise ValueError("Invalid public key format")

        existing = self._ensure_validator_keys_mapping(validator_id)
        if existing.get(key_id) != public_key_hex:
            updated = OrderedDict(existing)
            updated[key_id] = public_key_hex
            self.validator_public_keys[validator_id] = updated
        return key_id

    @staticmethod
    def _block_signature_payload(block):
        payload = OrderedDict([
            ("index", block["index"]),
            ("timestamp", block["timestamp"]),
            ("transactions", block["transactions"]),
            ("proof", block["proof"]),
            ("previous_hash", block["previous_hash"]),
        ])
        return json.dumps(payload, sort_keys=True)

    def _sign_block(self, block):
        if not self.validator_private_key_hex:
            raise ValueError("Validator private key is not configured")
        payload = self._block_signature_payload(block)
        priv_key = RSA.importKey(binascii.unhexlify(self.validator_private_key_hex))
        signer = pkcs1_15.new(priv_key)
        signature = signer.sign(SHA256.new(payload.encode('utf-8')))
        signature_hex = binascii.hexlify(signature).decode('ascii')
        if self.validator_public_key_hex and not self.validator_key_id:
            self.validator_key_id = self.derive_key_id(self.validator_public_key_hex)
        return signature_hex, self.validator_key_id

    def verify_block_signatures(self, block):
        if block.get("index") == 1 and not block.get("validator_signatures"):
            return True

        signatures = block.get("validator_signatures", [])
        if not isinstance(signatures, list):
            return False

        payload = self._block_signature_payload(block)
        seen_validators = set()
        valid_count = 0

        for signature_entry in signatures:
            validator_id = signature_entry.get("validator_id")
            signature_hex = signature_entry.get("signature")
            key_id_hint = signature_entry.get("key_id")
            if not validator_id or not signature_hex or validator_id in seen_validators:
                continue

            keys_map = self._ensure_validator_keys_mapping(validator_id)
            if not keys_map:
                logging.warning(f"Missing public key for validator {validator_id}")
                continue

            if key_id_hint and key_id_hint in keys_map:
                candidate_keys = [(key_id_hint, keys_map[key_id_hint])]
            else:
                candidate_keys = list(keys_map.items())

            verified = False
            for candidate_id, pub_hex in candidate_keys:
                try:
                    pub_key = RSA.importKey(binascii.unhexlify(pub_hex))
                    verifier = pkcs1_15.new(pub_key)
                    verifier.verify(
                        SHA256.new(payload.encode('utf-8')),
                        binascii.unhexlify(signature_hex),
                    )
                    seen_validators.add(validator_id)
                    valid_count += 1
                    verified = True
                    break
                except (ValueError, TypeError, binascii.Error):
                    continue

            if not verified:
                logging.warning(
                    f"Invalid validator signature for {validator_id}: no known keys matched"
                )

        required = max(1, int(self.quorum_threshold))
        if valid_count < required:
            logging.warning(f"Block {block.get('index')} signature quorum not satisfied: {valid_count}/{required}")
            return False

        block_proposer = block.get("validator_id")
        if block_proposer and block_proposer not in seen_validators:
            logging.warning(f"Block proposer {block_proposer} is not among valid signatures for block {block.get('index')}")
            return False

        return True

    def is_authorized_validator(self):
        if not self.validator_id or not self.validator_private_key_hex:
            return False
        try:
            local_public = self.validator_public_key_hex or self.derive_public_key_hex(self.validator_private_key_hex)
        except (ValueError, TypeError, binascii.Error) as exc:
            logging.error(f"Failed to derive validator public key: {exc}")
            return False

        registry_entries = self._ensure_validator_keys_mapping(self.validator_id)
        if registry_entries and local_public not in registry_entries.values():
            logging.error(
                "Local validator public key does not match registered key. Rotate or update keys before mining."
            )
            return False

        if self.validator_netloc and normalize_netloc(self.validator_netloc) not in self.trusted_nodes:
            return False

        return True

    def set_quorum_threshold(self, threshold):
        self.quorum_threshold = max(1, int(threshold))
        self.save_data()

    def update_validator_public_key(self, validator_id, public_key_hex):
        key_id = self._record_validator_public_key(validator_id, public_key_hex)
        if self.validator_id == validator_id and self.validator_public_key_hex == public_key_hex:
            self.validator_key_id = key_id
            self.save_validator_identity()
        self.save_data()
        return key_id

    def set_validator_identity(self, validator_id, private_key_hex, netloc=None, public_key_hex=None):
        normalized_netloc = None
        if netloc:
            normalized_netloc = normalize_netloc(netloc)

        derived_public_key_hex = None
        if private_key_hex:
            try:
                derived_public_key_hex = self.derive_public_key_hex(private_key_hex)
            except (ValueError, TypeError, binascii.Error) as exc:
                raise ValueError("Could not derive public key from supplied private key") from exc
            if derived_public_key_hex is None:
                raise ValueError("Could not derive public key from supplied private key")

        resolved_public_key_hex = None
        if public_key_hex:
            if derived_public_key_hex and derived_public_key_hex.lower() != public_key_hex.lower():
                raise ValueError("Provided public key does not match the supplied private key")
            resolved_public_key_hex = public_key_hex
        else:
            resolved_public_key_hex = derived_public_key_hex

        self.validator_id = validator_id
        self.validator_private_key_hex = private_key_hex

        if normalized_netloc:
            self.validator_netloc = normalized_netloc
            if normalized_netloc not in self.trusted_nodes:
                self.add_trusted_node(normalized_netloc)

        self.validator_public_key_hex = resolved_public_key_hex

        if self.validator_id and self.validator_public_key_hex:
            try:
                key_id = self._record_validator_public_key(self.validator_id, self.validator_public_key_hex)
            except ValueError as exc:
                logging.error(f"Unable to record validator public key: {exc}")
                key_id = None
            self.validator_key_id = key_id
        else:
            self.validator_key_id = None

        self.save_validator_identity()
        self.save_data()

    def add_validator_signature(self, block_index, validator_id, signature_hex, key_id=None):
        if block_index < 1 or block_index > len(self.chain):
            return False, "Block not found"

        block = self.chain[block_index - 1]
        signatures = block.setdefault("validator_signatures", [])
        for entry in signatures:
            if entry.get("validator_id") == validator_id:
                return False, "Validator already signed this block"

        keys_map = self._ensure_validator_keys_mapping(validator_id)
        if not keys_map:
            return False, "Unknown validator"

        payload = self._block_signature_payload(block)
        if key_id and key_id in keys_map:
            candidate_keys = [(key_id, keys_map[key_id])]
        else:
            candidate_keys = list(keys_map.items())

        validated_key_id = None
        for candidate_id, pub_hex in candidate_keys:
            try:
                pub_key = RSA.importKey(binascii.unhexlify(pub_hex))
                verifier = pkcs1_15.new(pub_key)
                verifier.verify(
                    SHA256.new(payload.encode('utf-8')),
                    binascii.unhexlify(signature_hex),
                )
                validated_key_id = candidate_id
                break
            except (ValueError, TypeError, binascii.Error):
                continue

        if not validated_key_id:
            return False, "Invalid signature"

        signatures.append({
            "validator_id": validator_id,
            "signature": signature_hex,
            "key_id": validated_key_id,
        })
        self.save_data()
        return True, block

    def sync_files(self):
        with self._lock:
            trusted_snapshot = set(self.trusted_nodes)
            all_nodes = list(self.nodes.union(self.trusted_nodes))
            local_netloc = normalize_netloc(self.validator_netloc) if self.validator_netloc else None
        for netloc in all_nodes:
            try:
                normalized_source = normalize_netloc(netloc)
            except Exception as exc:
                logging.warning(
                    "Skipping peer %r due to invalid netloc: %s",
                    netloc,
                    exc,
                )
                continue

            try:
                chain_data = self._fetch_chain_with_retry(netloc)
            except Exception as exc:
                logging.warning(
                    "Failed to fetch chain from %s: %s",
                    normalized_source,
                    exc,
                )
                continue

            if not chain_data:
                continue

            if not isinstance(chain_data, (list, tuple)):
                logging.warning(
                    "Peer %s returned unexpected chain structure type %s",
                    normalized_source,
                    type(chain_data).__name__,
                )
                continue

            try:
                for position, block in enumerate(chain_data):
                    if self._is_valid_block_structure(block, position):
                        transactions = block.get("transactions", [])
                    else:
                        transactions = block.get("transactions")
                        if not isinstance(transactions, list):
                            logging.warning(
                                "Block at position %s from %s has invalid transactions type %s",
                                position,
                                normalized_source,
                                type(transactions).__name__,
                            )
                            continue

                    if not isinstance(transactions, list):
                        logging.warning(
                            "Block at position %s from %s has invalid transactions type %s",
                            position,
                            normalized_source,
                            type(transactions).__name__,
                        )
                        continue

                    for tx_index, tx in enumerate(transactions):
                        if not isinstance(tx, Mapping):
                            logging.warning(
                                "Block at position %s from %s has invalid transaction %s type %s",
                                position,
                                normalized_source,
                                tx_index,
                                type(tx).__name__,
                            )
                            continue

                        if (
                            tx.get("is_sensitive", "0") == "1"
                            and netloc not in trusted_snapshot
                        ):
                            continue

                        file_path = tx.get("file_path", "")
                        if not file_path:
                            continue

                        normalized_path = os.path.normpath(file_path)
                        safe_relative_path = os.path.join(
                            ".", normalized_path.lstrip("./")
                        )
                        if not _is_safe_subpath(safe_relative_path, UPLOAD_FOLDER):
                            self._record_sync_failure(
                                "download",
                                normalized_source,
                                filename=tx.get("stored_file_name")
                                or tx.get("file_name"),
                                error=f"Rejected unsafe file path: {file_path}",
                                stage="validation",
                            )
                            continue

                        local_abs = safe_relative_path
                        key = (netloc, file_path)
                        if os.path.exists(local_abs):
                            self._clear_deferred_retry(key)
                            continue

                        success = self._download_file_with_retry(netloc, tx, local_abs)
                        owner_netloc = tx.get("file_owner")
                        attempted_owner = False
                        owner_key = None
                        owner_normalized = None
                        if not success and owner_netloc:
                            try:
                                owner_normalized = normalize_netloc(owner_netloc)
                            except Exception as exc:
                                logging.warning(
                                    "Skipping owner retry for %s due to invalid netloc %r: %s",
                                    file_path,
                                    owner_netloc,
                                    exc,
                                )
                            else:
                                if (
                                    owner_normalized != normalized_source
                                    and owner_normalized != local_netloc
                                ):
                                    attempted_owner = True
                                    owner_key = (owner_normalized, file_path)
                                    success = self._download_file_with_retry(
                                        owner_normalized,
                                        tx,
                                        local_abs,
                                        attempt_offset=self.sync_max_retries,
                                    )
                                    if success:
                                        self._clear_deferred_retry(owner_key)

                        if success:
                            self._clear_deferred_retry(key)
                            if attempted_owner and owner_key:
                                self._clear_deferred_retry(owner_key)
                        else:
                            if attempted_owner and owner_key and owner_normalized:
                                self._schedule_deferred_retry(
                                    owner_normalized, tx, attempt=1
                                )
                            else:
                                self._schedule_deferred_retry(netloc, tx, attempt=1)
            except Exception as exc:
                logging.warning(
                    "Unexpected error while processing chain from %s: %s",
                    normalized_source,
                    exc,
                    exc_info=True,
                )
                continue

    def broadcast_new_transaction(self, tx_dict):
        with self._lock:
            if tx_dict.get("is_sensitive", "0") == "1":
                targets = list(self.trusted_nodes)
            else:
                targets = list(self.nodes.union(self.trusted_nodes))

        if tx_dict.get("is_sensitive", "0") == "1":
            logging.info("Broadcasting sensitive transaction only to trusted nodes.")

        for netloc in targets:
            try:
                url = f"http://{netloc}/transactions/new"
                payload = dict(tx_dict)
                payload["skip_broadcast"] = True
                if payload.get("file_path") and not payload.get("stored_file_name"):
                    payload["stored_file_name"] = os.path.basename(os.path.normpath(payload["file_path"]))
                requests.post(url, json=payload, timeout=3)
            except requests.exceptions.RequestException as exc:
                logging.warning(f"Broadcast to {netloc} failed: {exc}")

    def load_validator_identity(self):
        if not os.path.exists(VALIDATOR_IDENTITY_FILE):
            return
        try:
            with open(VALIDATOR_IDENTITY_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logging.error(f"Failed to load validator identity: {exc}")
            return

        self.validator_id = data.get("validator_id") or self.validator_id
        self.validator_private_key_hex = data.get("private_key_hex") or self.validator_private_key_hex
        self.validator_public_key_hex = data.get("public_key_hex") or self.validator_public_key_hex
        self.validator_key_id = data.get("key_id") or self.validator_key_id
        netloc = data.get("netloc")
        if netloc:
            self.validator_netloc = normalize_netloc(netloc)

        if self.validator_private_key_hex and not self.validator_public_key_hex:
            try:
                self.validator_public_key_hex = self.derive_public_key_hex(self.validator_private_key_hex)
            except (ValueError, TypeError, binascii.Error) as exc:
                logging.error(f"Unable to derive public key from private key: {exc}")
        if self.validator_public_key_hex and not self.validator_key_id:
            self.validator_key_id = self.derive_key_id(self.validator_public_key_hex)
    def save_validator_identity(self):
        data = {
            "validator_id": self.validator_id,
            "private_key_hex": self.validator_private_key_hex,
            "public_key_hex": self.validator_public_key_hex,
            "netloc": self.validator_netloc,
            "key_id": self.validator_key_id,
        }
        try:
            with open(VALIDATOR_IDENTITY_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except OSError as exc:
            logging.error(f"Failed to persist validator identity: {exc}")

    def save_data(self):
        with self._lock:
            data = {
                "chain": self.chain,
                "nodes": list(self.nodes),
                "trusted_nodes": list(self.trusted_nodes),
                "transactions": self.transactions,
                "validator_public_keys": {
                    vid: dict(keys)
                    for vid, keys in self.validator_public_keys.items()
                },
                "quorum_threshold": self.quorum_threshold,
            }
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        logging.info("Blockchain data saved.")

    def load_data(self):
        if not os.path.exists(DATA_FILE):
            with self._lock:
                self.chain = []
                self.nodes = set()
                self.trusted_nodes = set()
                self.transactions = []
                self.validator_public_keys = {}
                self.quorum_threshold = 1
            return
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        with self._lock:
            self.chain = data.get("chain", [])
            self.transactions = data.get("transactions", [])
            self.nodes = {normalize_netloc(item) for item in data.get("nodes", [])}
            self.trusted_nodes = {normalize_netloc(item) for item in data.get("trusted_nodes", [])}
            self._trusted_resolution_cache.clear()
            raw_keys = data.get("validator_public_keys", self.validator_public_keys)
            self.validator_public_keys = self._normalize_validator_key_dict(raw_keys)
            self.quorum_threshold = data.get("quorum_threshold", self.quorum_threshold)

    def add_node(self, address):
        with self._lock:
            normalized = normalize_netloc(address)
            self.nodes.add(normalized)
            self.save_data()

    def remove_node(self, address):
        try:
            normalized = normalize_netloc(address)
        except ValueError:
            return False

        with self._lock:
            if normalized in self.nodes:
                self.nodes.remove(normalized)
                self.save_data()
                return True
        return None

    def _clear_trusted_cache_entry(self, netloc):
        try:
            host, _ = _split_host_port(netloc)
        except ValueError:
            return
        self._trusted_resolution_cache.pop(host, None)

    def add_trusted_node(self, address):
        with self._lock:
            normalized = normalize_netloc(address)
            self.trusted_nodes.add(normalized)
            self._clear_trusted_cache_entry(normalized)
            self.save_data()

    def remove_trusted_node(self, address):
        try:
            normalized = normalize_netloc(address)
        except ValueError:
            return False

        with self._lock:
            if normalized in self.trusted_nodes:
                self.trusted_nodes.remove(normalized)
                self._clear_trusted_cache_entry(normalized)
                self.save_data()
                return True
        return None

    def get_trusted_netloc_ips(self, netloc):
        try:
            host, _ = _split_host_port(netloc)
        except ValueError:
            return ()
        with self._lock:
            cached = self._trusted_resolution_cache.get(host)
            if cached and cached.get("netloc") == netloc:
                return cached.get("ips", ())

        ips = self._resolve_host_to_ips(host)

        with self._lock:
            self._trusted_resolution_cache[host] = {
                "netloc": netloc,
                "ips": ips,
            }
        return ips

    @staticmethod
    def _resolve_host_to_ips(host):
        stripped_host = host.strip()
        if stripped_host.startswith('[') and stripped_host.endswith(']'):
            stripped_host = stripped_host[1:-1]

        try:
            ip_obj = ipaddress.ip_address(stripped_host)
        except ValueError:
            ip_list = []
            try:
                addrinfo_list = socket.getaddrinfo(
                    stripped_host,
                    None,
                    family=socket.AF_UNSPEC,
                    type=0,
                )
            except (socket.gaierror, UnicodeError):
                addrinfo_list = []

            for family, _socktype, _proto, _canonname, sockaddr in addrinfo_list:
                if not sockaddr:
                    continue
                raw_ip = sockaddr[0]
                try:
                    normalized_ip = ipaddress.ip_address(raw_ip)
                except ValueError:
                    continue
                ip_list.append(str(normalized_ip))
        else:
            ip_list = [str(ip_obj)]

        deduped = []
        for item in ip_list:
            if item not in deduped:
                deduped.append(item)
        return tuple(deduped)

# Create the global Blockchain instance
blockchain = Blockchain()
node_identifier = str(uuid4()).replace('-', '')

app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True


_TRUSTED_MANAGEMENT_FORBIDDEN_MESSAGE = "Caller is not authorized to manage trusted nodes"
_VALIDATOR_MANAGEMENT_FORBIDDEN_MESSAGE = "Caller is not authorized to manage validator identity"
_NODE_MANAGEMENT_FORBIDDEN_MESSAGE = "Caller is not authorized to manage nodes"
_MINING_FORBIDDEN_MESSAGE = "Caller is not authorized to mine blocks"


def _request_from_trusted():
    caller_ip = request.remote_addr
    if not caller_ip:
        return False

    with blockchain.lock:
        trusted_entries = list(blockchain.trusted_nodes)

    for netloc in trusted_entries:
        try:
            host, _ = _split_host_port(netloc)
        except ValueError:
            continue
        if host == caller_ip:
            return True

        resolved_ips = blockchain.get_trusted_netloc_ips(netloc)
        if caller_ip in resolved_ips:
            return True
    return False


def _request_from_localhost():
    caller_ip = request.remote_addr
    if not caller_ip:
        return False

    try:
        ip_obj = ipaddress.ip_address(caller_ip)
    except ValueError:
        return False

    return ip_obj.is_loopback


def _trusted_management_forbidden_response():
    return jsonify({"message": _TRUSTED_MANAGEMENT_FORBIDDEN_MESSAGE}), 403


def _node_management_forbidden_response():
    return jsonify({"message": _NODE_MANAGEMENT_FORBIDDEN_MESSAGE}), 403


def _require_node_management_authorization():
    if _request_from_trusted() or _request_from_localhost():
        return None
    return _node_management_forbidden_response()

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

@app.route('/validator/configure', methods=['GET', 'POST'])
def configure_validator():
    is_authorized_caller = _request_from_trusted() or _request_from_localhost()

    if not is_authorized_caller:
        return jsonify({"message": _VALIDATOR_MANAGEMENT_FORBIDDEN_MESSAGE}), 403

    if request.method == 'GET':
        return jsonify({
            "validator_id": blockchain.validator_id,
            "public_key_hex": blockchain.validator_public_key_hex,
            "netloc": blockchain.validator_netloc,
            "is_authorized": blockchain.is_authorized_validator()
        }), 200

    data = request.get_json() or {}
    validator_id = data.get('validator_id')
    private_key = data.get('private_key_hex') or data.get('private_key')
    netloc = data.get('netloc')
    public_key = data.get('public_key_hex') or data.get('public_key')

    if not validator_id or not private_key:
        return jsonify({"message": "validator_id and private_key_hex are required"}), 400

    try:
        blockchain.set_validator_identity(validator_id, private_key, netloc=netloc, public_key_hex=public_key)
    except ValueError as exc:
        return jsonify({"message": str(exc)}), 400

    return jsonify({
        "message": "Validator identity updated",
        "validator_id": blockchain.validator_id,
        "public_key_hex": blockchain.validator_public_key_hex,
        "netloc": blockchain.validator_netloc,
        "is_authorized": blockchain.is_authorized_validator()
    }), 200

@app.route('/mine', methods=['GET'])
def mine():
    """
    Example method to auto-mine a new block with a mining reward.
    """
    if not (_request_from_trusted() or _request_from_localhost()):
        return jsonify({"message": _MINING_FORBIDDEN_MESSAGE}), 403

    if not blockchain.is_authorized_validator():
        return jsonify({"message": "This node is not authorized to propose blocks."}), 403

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
        signature="",
        allow_system_transaction=True,
    )
    prev_hash = blockchain.hash(last_block)
    try:
        block = blockchain.create_block(proof, prev_hash)
    except PermissionError as exc:
        return jsonify({"message": str(exc)}), 403
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
    import copy
    with blockchain.lock:
        trusted_snapshot = list(blockchain.trusted_nodes)
        chain_snapshot = copy.deepcopy(blockchain.chain)

    def _trusted_host_matches_ip(netloc: str, ip: str) -> bool:
        try:
            host, _ = _split_host_port(netloc)
        except ValueError:
            return False
        return host == ip

    is_trusted = any(_trusted_host_matches_ip(netloc, caller_ip) for netloc in trusted_snapshot)

    pruned_chain = []
    for block in chain_snapshot:
        if not is_trusted:
            block["transactions"] = [
                tx for tx in block["transactions"]
                if tx.get("is_sensitive", "0") != "1"
            ]
        pruned_chain.append(block)

    return jsonify({"chain": pruned_chain, "length": len(pruned_chain)}),200

@app.route('/node/upload', methods=['POST'])
def node_upload():
    upfile = request.files.get('file')
    if not upfile:
        return jsonify({"error": "Missing file"}), 400

    sender = request.form.get('sender', '')
    recipient = request.form.get('recipient', '')
    signature = request.form.get('signature', '')
    tx_id = request.form.get('tx_id', '')
    alias = request.form.get('alias', '')
    recipient_alias = request.form.get('recipient_alias', '')
    is_sensitive = request.form.get('is_sensitive', '0')

    if sender == MINING_SENDER:
        return jsonify({"error": "Reserved sender identifier is not permitted"}), 400

    if not tx_id:
        return jsonify({"error": "Missing tx_id in form data"}), 400

    file_name = request.form.get('file_name', '')
    if not file_name:
        return jsonify({"error": "Missing file_name in form data"}), 400

    try:
        safe_file_name = _ensure_safe_filename(file_name)
    except ValueError:
        return jsonify({"error": "Invalid file_name supplied"}), 400

    try:
        canonical_stored_name = _derive_canonical_stored_name(tx_id, safe_file_name)
    except ValueError:
        return jsonify({"error": "Invalid transaction identifiers supplied"}), 400

    provided_path = request.form.get('file_path', '')
    if provided_path and not _is_safe_subpath(provided_path, PENDING_FOLDER):
        return jsonify({"error": "Invalid file_path supplied"}), 400

    pending_filename = canonical_stored_name
    canonical_file_path = os.path.join(PENDING_FOLDER, pending_filename)
    pending_abs = os.path.abspath(canonical_file_path)
    pending_root = os.path.abspath(PENDING_FOLDER)
    if not pending_abs.startswith(os.path.join(pending_root, '')):
        return jsonify({"error": "Failed to derive safe pending path"}), 400

    os.makedirs(os.path.dirname(pending_abs), exist_ok=True)
    saved_new_file = False
    if not os.path.exists(pending_abs):
        upfile.save(pending_abs)
        saved_new_file = True

    enc_key_b64 = request.form.get('enc_key_b64', '')
    enc_nonce_b64 = request.form.get('enc_nonce_b64', '')
    enc_tag_b64 = request.form.get('enc_tag_b64', '')
    has_encryption_payload = (
        is_sensitive == '1'
        and enc_key_b64
        and enc_nonce_b64
        and enc_tag_b64
    )

    if has_encryption_payload:
        try:
            base64.b64decode(enc_key_b64, validate=True)
            base64.b64decode(enc_nonce_b64, validate=True)
            base64.b64decode(enc_tag_b64, validate=True)
        except (binascii.Error, ValueError):
            if saved_new_file:
                try:
                    os.remove(pending_abs)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    logging.warning(
                        "Failed to remove pending upload with invalid encryption payload for tx %s: %s",
                        tx_id,
                        exc,
                    )
            return jsonify({"error": "Invalid encryption payload"}), 400

    host_header = request.host or ""
    if not host_header:
        return jsonify({"error": "Missing Host header"}), 400

    try:
        normalized_host_header = normalize_netloc(host_header)
        header_host, header_port = _split_host_port(normalized_host_header)
    except ValueError:
        return jsonify({"error": "Invalid Host header"}), 400

    configured_self_netlocs = list(_get_configured_self_netlocs())
    with blockchain.lock:
        validator_netloc = blockchain.validator_netloc
    if validator_netloc:
        try:
            normalized_validator = normalize_netloc(validator_netloc)
        except ValueError:
            logging.warning("Validator netloc is invalid: %s", validator_netloc)
        else:
            if normalized_validator not in configured_self_netlocs:
                configured_self_netlocs.insert(0, normalized_validator)

    if not configured_self_netlocs:
        return jsonify({"error": "LOCAL_NODE_NETLOCS must be configured"}), 400

    if not _host_header_matches_local(
        normalized_host_header,
        configured_self_netlocs,
        blockchain._resolve_host_to_ips,
    ):
        return jsonify({"error": "Host header does not identify this node"}), 400

    header_ips = set(blockchain._resolve_host_to_ips(header_host))
    header_ips.add(header_host)

    matched_owner = None
    for candidate in configured_self_netlocs:
        try:
            candidate_host, candidate_port = _split_host_port(candidate)
        except ValueError:
            continue
        if candidate_port is not None and candidate_port != header_port:
            continue
        if candidate_host == header_host:
            matched_owner = candidate
            break
        candidate_ips = set(blockchain._resolve_host_to_ips(candidate_host))
        candidate_ips.add(candidate_host)
        if header_ips & candidate_ips:
            matched_owner = candidate
            break

    file_owner = matched_owner or configured_self_netlocs[0]

    try:
        with blockchain.lock:
            location, added, mined = blockchain.add_transaction(
                tx_id=tx_id,
                sender=sender,
                recipient=recipient,
                file_name=safe_file_name,
                file_path=canonical_file_path,
                alias=alias,
                recipient_alias=recipient_alias,
                signature=signature,
                is_sensitive=is_sensitive,
                file_owner=file_owner,
                stored_file_name=pending_filename,
            )
    except ValueError as exc:
        if saved_new_file:
            try:
                os.remove(pending_abs)
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                logging.warning(
                    "Failed to remove pending upload for rejected tx %s: %s",
                    tx_id,
                    cleanup_exc,
                )
        try:
            delete_encryption_keys(tx_id)
        except Exception as cleanup_exc:
            logging.warning(
                "Failed to remove encryption metadata for rejected tx %s: %s",
                tx_id,
                cleanup_exc,
            )
        return jsonify({"error": str(exc)}), 400

    if location is None:
        if saved_new_file:
            try:
                os.remove(pending_abs)
            except FileNotFoundError:
                pass
            except OSError as exc:
                logging.warning(
                    "Failed to remove pending upload for rejected tx %s: %s",
                    tx_id,
                    exc,
                )
        try:
            delete_encryption_keys(tx_id)
        except Exception as exc:
            logging.warning(
                "Failed to remove encryption metadata for rejected tx %s: %s",
                tx_id,
                exc,
            )
        return jsonify({"error": "Invalid signature"}), 400

    if not added:
        if saved_new_file:
            try:
                os.remove(pending_abs)
            except FileNotFoundError:
                pass
            except OSError as exc:
                logging.warning(
                    "Failed to remove duplicate pending upload for tx %s: %s",
                    tx_id,
                    exc,
                )
        if location == "pending":
            message = "File already received and pending confirmation"
        else:
            message = f"File already received, block = {location}"
        return jsonify({
            "message": message,
            "location": location,
            "added": False,
            "mined": False,
        }), 200

    if has_encryption_payload and added:
        store_encryption_keys(tx_id, enc_key_b64, enc_nonce_b64, enc_tag_b64)

    if mined:
        message = f"File received and stored in block {location}"
    else:
        message = f"File received, pending block {location}"
    return jsonify({
        "message": message,
        "location": location,
        "added": True,
        "mined": mined,
    }), 201


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    data = request.get_json() or {}
    skip_broadcast = data.pop("skip_broadcast", False)

    if "tx_id" not in data:
        data["tx_id"] = str(uuid4().hex)

    required = ["tx_id", "sender", "recipient", "file_name", "file_path", "signature"]
    if not all(key in data for key in required):
        return "Missing values", 400

    if data.get("sender") == MINING_SENDER:
        return jsonify({"error": "Reserved sender identifier is not permitted"}), 400

    try:
        data["file_name"] = _ensure_safe_filename(data["file_name"])
    except ValueError:
        return "Invalid file_name", 400

    try:
        canonical_stored_name = _derive_canonical_stored_name(data["tx_id"], data["file_name"])
    except ValueError:
        return "Invalid stored_file_name", 400

    file_path_value = data["file_path"]
    if _is_safe_subpath(file_path_value, PENDING_FOLDER):
        data["file_path"] = os.path.join(PENDING_FOLDER, canonical_stored_name)
    elif _is_safe_subpath(file_path_value, UPLOAD_FOLDER):
        data["file_path"] = os.path.join(UPLOAD_FOLDER, canonical_stored_name)
    else:
        return "Invalid file_path", 400

    stored_name = data.get("stored_file_name")
    if stored_name:
        try:
            safe_stored = _ensure_safe_filename(stored_name)
        except ValueError:
            return "Invalid stored_file_name", 400
    else:
        safe_stored = canonical_stored_name

    if safe_stored != canonical_stored_name:
        logging.warning(
            "Stored filename mismatch for tx %s during /transactions/new; expected %s, received %s.",
            data["tx_id"],
            canonical_stored_name,
            safe_stored,
        )

    data["stored_file_name"] = canonical_stored_name

    try:
        with blockchain.lock:
            location, added, mined = blockchain.add_transaction(
                tx_id=data["tx_id"],
                sender=data['sender'],
                recipient=data['recipient'],
                file_name=data['file_name'],
                file_path=data['file_path'],
                alias=data.get('alias', ''),
                recipient_alias=data.get('recipient_alias', ''),
                signature=data['signature'],
                is_sensitive=data.get('is_sensitive', '0'),
                file_owner=data.get('file_owner'),
                stored_file_name=data.get('stored_file_name'),
            )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if location is None:
        return "Invalid signature", 400

    stored_tx = blockchain.get_transaction_by_id(data["tx_id"])
    if stored_tx and stored_tx.get("file_owner"):
        data['file_owner'] = stored_tx['file_owner']

    if added and location and location != "pending" and not skip_broadcast:
        blockchain.broadcast_new_transaction(data)

    if added:
        if mined:
            message = f"Transaction added to block {location}"
        else:
            message = f"Transaction will be added to block {location}"
        return jsonify({
            "message": message,
            "location": location,
            "added": True,
            "mined": mined,
        }), 201

    if location == "pending":
        message = "Transaction already pending confirmation"
    else:
        message = f"Transaction already accepted in block {location}"
    return jsonify({
        "message": message,
        "location": location,
        "added": False,
        "mined": False,
    }), 200

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    """
    Returns the current list of pending transactions (not yet in a block).
    """
    import copy
    with blockchain.lock:
        tx_snapshot = copy.deepcopy(blockchain.transactions)
    return jsonify({"transactions": tx_snapshot}),200

@app.route('/file/<filename>', methods=['GET'])
def get_file(filename):
    """
    Returns the file from ./uploads, either plaintext or ciphertext if is_sensitive=1.
    """
    try:
        safe_name = _ensure_safe_filename(filename)
    except ValueError:
        abort(400, "Invalid filename")
    upload_root = os.path.abspath(UPLOAD_FOLDER)
    try:
        return send_from_directory(upload_root, safe_name, as_attachment=False)
    except FileNotFoundError:
        abort(404, "File not found")

@app.route('/decrypt/<tx_id>', methods=['GET'])
def decrypt_file(tx_id):
    """
    DEMO endpoint that the Node can use to decrypt a sensitive file
    if we have stored the AES key, nonce, tag in keys_db.json.
    Returns the original content as a downloadable file.
    """
    import copy
    with blockchain.lock:
        chain_snapshot = copy.deepcopy(blockchain.chain)

    file_name = None
    stored_file_name = None
    for block in chain_snapshot:
        for tx in block["transactions"]:
            if tx.get("tx_id") == tx_id:
                if tx.get("is_sensitive","0") != "1":
                    return jsonify({"error":"Not a sensitive TX"}),400
                file_name = tx.get("file_name")
                stored_file_name = tx.get("stored_file_name") or file_name
                break
        if stored_file_name:
            break

    if not stored_file_name:
        return jsonify({"error":"Transaction not found or not sensitive."}),404

    enc_info = get_encryption_keys(tx_id)
    if not enc_info:
        return jsonify({"error":"No encryption info stored for this TX"}),404

    uploads_root = os.path.abspath(UPLOAD_FOLDER)
    up_abs = os.path.join(uploads_root, stored_file_name)
    if not os.path.exists(up_abs):
        return jsonify({"error":"File not found in ./uploads"}),404

    with open(up_abs, 'rb') as f:
        ciphertext = f.read()

    try:
        key_b = base64.b64decode(enc_info["enc_key_b64"], validate=True)
        nonce_b = base64.b64decode(enc_info["enc_nonce_b64"], validate=True)
        tag_b = base64.b64decode(enc_info["enc_tag_b64"], validate=True)
    except (binascii.Error, ValueError):
        return jsonify({"error": "Invalid encryption metadata"}), 400

    try:
        cipher = AES.new(key_b, AES.MODE_GCM, nonce=nonce_b)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag_b)
    except ValueError as e:
        return jsonify({"error":f"Decrypt error: {e}"}),400

    from io import BytesIO
    bio = BytesIO(plaintext)
    bio.seek(0)

    effective_name = file_name or stored_file_name
    ext = os.path.splitext(effective_name)[1].lower()
    ct_map = {
        '.pdf': 'application/pdf',
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.txt': 'text/plain'
    }
    content_type = ct_map.get(ext, 'application/octet-stream')
    dec_name = "decrypted_" + effective_name

    return send_file(bio,
                     as_attachment=True,
                     download_name=dec_name,
                     mimetype=content_type)

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    auth_error = _require_node_management_authorization()
    if auth_error:
        return auth_error

    candidates = []
    payload = request.get_json(silent=True)
    if payload is not None:
        candidates.extend(_coerce_node_entries(payload))

    if not candidates and request.form:
        candidates.extend(_coerce_node_entries(request.form.to_dict(flat=False)))

    if not candidates and request.args:
        candidates.extend(_coerce_node_entries(request.args.to_dict(flat=False)))

    if not candidates:
        raw_body = request.get_data(as_text=True).strip()
        if raw_body:
            candidates.extend(_coerce_node_entries(raw_body))

    filtered_candidates = [item.strip() for item in candidates if item and item.strip()]
    if not filtered_candidates:
        return jsonify({"message": "No nodes provided"}), 400

    normalized_candidates = []
    for candidate in filtered_candidates:
        try:
            normalized_candidates.append(normalize_netloc(candidate))
        except ValueError as exc:
            return jsonify({
                "message": f"Invalid node address: {candidate}",
                "details": str(exc),
            }), 400

    with blockchain.lock:
        for netloc in normalized_candidates:
            blockchain.add_node(netloc)
        nodes_snapshot = list(blockchain.nodes)

    return jsonify({
        "message": "Nodes added",
        "total_nodes": nodes_snapshot
    }),201

@app.route('/nodes/remove', methods=['POST'])
def remove_node():
    auth_error = _require_node_management_authorization()
    if auth_error:
        return auth_error
    d = request.get_json() or {}
    if 'node' not in d:
        return jsonify({"message":"Missing node address"}),400

    rm = d['node'].strip()
    with blockchain.lock:
        rem = blockchain.remove_node(rm)

    if rem is True:
        return jsonify({"message": f"Node {rm} removed"}),200

    if rem is False:
        return jsonify({
            "message": f"Invalid node address: {rm}",
            "details": "Unable to parse node address",
        }),400

    return jsonify({"message":"Node not found"}),404

@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    auth_error = _require_node_management_authorization()
    if auth_error:
        return auth_error
    with blockchain.lock:
        nodes_snapshot = list(blockchain.nodes)
    return jsonify({"total_nodes": nodes_snapshot}),200

@app.route('/trusted_nodes/register', methods=['POST'])
def register_trusted_nodes():
    if not _request_from_trusted():
        return _trusted_management_forbidden_response()
    node_netlocs = []

    payload = request.get_json(silent=True)
    if payload is not None:
        node_netlocs.extend(_coerce_node_entries(payload))

    if not node_netlocs and request.form:
        node_netlocs.extend(_coerce_node_entries(request.form.to_dict(flat=False)))

    if not node_netlocs and request.args:
        node_netlocs.extend(_coerce_node_entries(request.args.to_dict(flat=False)))

    if not node_netlocs:
        raw_body = request.get_data(as_text=True).strip()
        if raw_body:
            node_netlocs.extend(_coerce_node_entries(raw_body))

    filtered_netlocs = [item.strip() for item in node_netlocs if item and item.strip()]
    if not filtered_netlocs:
        return jsonify({"message": "No trusted nodes"}),400

    normalized_netlocs = []
    for candidate in filtered_netlocs:
        try:
            normalized_netlocs.append(normalize_netloc(candidate))
        except ValueError as exc:
            return jsonify({
                "message": f"Invalid trusted node address: {candidate}",
                "details": str(exc),
            }), 400

    with blockchain.lock:
        for netloc in normalized_netlocs:
            blockchain.add_trusted_node(netloc)
        trusted_snapshot = list(blockchain.trusted_nodes)

    return jsonify({
        "message": "Trusted nodes added",
        "trusted_nodes": trusted_snapshot
    }),201

@app.route('/trusted_nodes/remove', methods=['POST'])
def remove_trusted_node():
    if not _request_from_trusted():
        return _trusted_management_forbidden_response()
    d = request.get_json() or {}
    if 'node' not in d:
        return jsonify({"message":"Missing node address"}),400

    rm = d['node'].strip()
    with blockchain.lock:
        rem = blockchain.remove_trusted_node(rm)

    if rem is True:
        return jsonify({"message": f"Trusted node {rm} removed"}),200

    if rem is False:
        return jsonify({
            "message": f"Invalid trusted node address: {rm}",
            "details": "Unable to parse trusted node address",
        }),400

    return jsonify({"message":"Trusted node not found"}),404

@app.route('/trusted_nodes/get', methods=['GET'])
def get_trusted_nodes():
    with blockchain.lock:
        trusted_snapshot = list(blockchain.trusted_nodes)
    return jsonify({
        "trusted_nodes": trusted_snapshot
    }),200

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    auth_error = _require_node_management_authorization()
    if auth_error:
        return auth_error
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({"message":"Chain replaced"}),200
    return jsonify({"message":"Chain is authoritative"}),200

@app.route('/sync', methods=['GET'])
def manual_sync():
    auth_error = _require_node_management_authorization()
    if auth_error:
        return auth_error
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

@app.route('/sync/failures', methods=['GET'])
def sync_failures():
    limit = request.args.get('limit', type=int)
    return jsonify({"failures": blockchain.get_sync_failures(limit=limit)}), 200
@app.route('/trusted_nodes/keys', methods=['GET'])
def get_trusted_node_keys():
    if not _request_from_trusted():
        return jsonify({"message": "Trusted access required"}), 403
    return jsonify({
        "validator_public_keys": blockchain.validator_public_keys,
        "quorum_threshold": blockchain.quorum_threshold
    }), 200

@app.route('/trusted_nodes/keys/rotate', methods=['POST'])
def rotate_trusted_node_key():
    if not _request_from_trusted():
        return jsonify({"message": "Trusted access required"}), 403

    data = request.get_json() or {}
    validator_id = data.get('validator_id')
    public_key = data.get('public_key_hex') or data.get('public_key')
    netloc = data.get('netloc')

    if not validator_id or not public_key:
        return jsonify({"message": "validator_id and public_key_hex are required"}), 400

    try:
        key_id = blockchain.update_validator_public_key(validator_id, public_key)
    except ValueError as exc:
        return jsonify({"message": str(exc)}), 400
    if netloc:
        blockchain.add_trusted_node(netloc)

    return jsonify({
        "message": "Validator key updated",
        "validator_id": validator_id,
        "public_key_hex": public_key,
        "key_id": key_id,
    }), 200

@app.route('/consensus/quorum', methods=['GET', 'POST'])
def quorum_configuration():
    if request.method == 'GET':
        return jsonify({
            "quorum_threshold": blockchain.quorum_threshold,
            "known_validators": list(blockchain.validator_public_keys.keys())
        }), 200

    if not _request_from_trusted():
        return jsonify({"message": "Trusted access required"}), 403

    data = request.get_json() or {}
    threshold = data.get('threshold')

    try:
        threshold_value = int(threshold)
    except (TypeError, ValueError):
        return jsonify({"message": "threshold must be an integer >= 1"}), 400

    if threshold_value < 1:
        return jsonify({"message": "threshold must be >= 1"}), 400

    blockchain.set_quorum_threshold(threshold_value)
    return jsonify({
        "message": "Quorum threshold updated",
        "quorum_threshold": blockchain.quorum_threshold
    }), 200

@app.route('/blocks/<int:block_index>/approve', methods=['POST'])
def approve_block(block_index):
    if not _request_from_trusted():
        return jsonify({"message": "Trusted access required"}), 403

    data = request.get_json() or {}
    validator_id = data.get('validator_id')
    signature_hex = data.get('signature')
    key_id = data.get('key_id')

    if not validator_id or not signature_hex:
        return jsonify({"message": "validator_id and signature are required"}), 400

    success, result = blockchain.add_validator_signature(
        block_index, validator_id, signature_hex, key_id=key_id
    )
    if success:
        return jsonify({
            "message": "Signature recorded",
            "block": result
        }), 200

    status_code = 404 if result == "Block not found" else 400
    return jsonify({"message": result}), status_code

if __name__ == "__main__":
    t = threading.Thread(target=auto_sync_conflicts, args=(10,), daemon=True)
    t.start()
    # This node listens on port 5000 by default.
    app.run(host="0.0.0.0", port=5000)
