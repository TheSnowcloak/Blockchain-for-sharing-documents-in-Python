import binascii
import json
import importlib
import os
import sys
import uuid
from io import BytesIO
from pathlib import Path

import pytest
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Ensure repository root is on sys.path when running inside temporary dirs
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def isolated_blockchain(tmp_path, monkeypatch):
    """Create a Blockchain instance isolated within a temporary directory."""
    monkeypatch.chdir(tmp_path)

    # Reload the module so relative directories are created within tmp_path
    blockchain_module = importlib.import_module("blockchain_node.blockchain")
    blockchain_module = importlib.reload(blockchain_module)

    # Ensure module paths point inside the temporary directory
    blockchain_module.DATA_FILE = "blockchain_data.json"
    blockchain_module.KEYS_DB_FILE = "keys_db.json"

    os.makedirs(blockchain_module.PENDING_FOLDER, exist_ok=True)
    os.makedirs(blockchain_module.UPLOAD_FOLDER, exist_ok=True)

    bc = blockchain_module.Blockchain()
    blockchain_module.blockchain = bc
    blockchain_module.app.config["LOCAL_NODE_NETLOCS"] = "127.0.0.1:5000"
    bc.transactions = []
    bc.nodes = set()
    bc.trusted_nodes = set()

    # Configure a validator identity so tests can mine blocks without network setup.
    rsa_key = RSA.generate(1024)
    private_key_hex = binascii.hexlify(rsa_key.export_key(format='DER')).decode('ascii')
    public_key_hex = binascii.hexlify(rsa_key.publickey().export_key(format='DER')).decode('ascii')
    bc.set_validator_identity('test-validator', private_key_hex, public_key_hex=public_key_hex)

    return bc, blockchain_module


def _sign_transaction(module, private_key_hex, data):
    payload = {
        'tx_id': data['tx_id'],
        'sender': data['sender'],
        'recipient': data['recipient'],
        'file_name': data['file_name'],
        'alias': data.get('alias', ''),
        'recipient_alias': data.get('recipient_alias', ''),
        'is_sensitive': data.get('is_sensitive', '0'),
    }
    signable = module.blockchain._build_signable_transaction(payload)
    digest = SHA256.new(json.dumps(signable, sort_keys=True).encode('utf-8'))
    private_key = RSA.import_key(binascii.unhexlify(private_key_hex))
    signature = pkcs1_15.new(private_key).sign(digest)
    return binascii.hexlify(signature).decode('ascii')


def _generate_rsa_keypair():
    key = RSA.generate(1024)
    private_hex = binascii.hexlify(key.export_key(format='DER')).decode('ascii')
    public_hex = binascii.hexlify(key.publickey().export_key(format='DER')).decode('ascii')
    return private_hex, public_hex


def test_create_block_normalizes_missing_file(isolated_blockchain):
    bc, module = isolated_blockchain

    tx_id = "tx123"
    bc.add_transaction(
        tx_id=tx_id,
        sender=module.MINING_SENDER,
        recipient="recipient_pub",
        file_name="doc.txt",
        file_path="./pending_uploads/doc.txt",
        alias="",
        recipient_alias="",
        signature="",
        is_sensitive="0",
        file_owner="127.0.0.1:5000",
        allow_system_transaction=True,
    )

    block = bc.create_block(proof=200, previous_hash="hash")
    assert block["transactions"], "Transaction should be recorded in the new block"

    tx = block["transactions"][0]
    assert tx["file_path"] == "./uploads/doc.txt"
    assert tx["file_owner"] == "127.0.0.1:5000"
    assert tx["stored_file_name"] == "doc.txt"


def test_pending_transactions_persist_after_reload(isolated_blockchain):
    bc, module = isolated_blockchain

    tx_id = f"pending-{uuid.uuid4()}"
    _, added, mined = bc.add_transaction(
        tx_id=tx_id,
        sender=module.MINING_SENDER,
        recipient="recipient_pub",
        file_name="queued.txt",
        file_path="./pending_uploads/queued.txt",
        alias="",
        recipient_alias="",
        signature="",
        is_sensitive="0",
        file_owner="127.0.0.1:5000",
        allow_system_transaction=True,
    )

    assert added is True
    assert mined is False
    assert os.path.exists(module.DATA_FILE)

    reloaded_blockchain = module.Blockchain()
    matching_transactions = [
        tx for tx in reloaded_blockchain.transactions if tx.get("tx_id") == tx_id
    ]
    assert matching_transactions, "Pending transaction should persist after reload"
    assert matching_transactions[0]["file_name"] == "queued.txt"


def test_sync_files_downloads_from_recorded_owner(isolated_blockchain, monkeypatch):
    bc, module = isolated_blockchain

    tx = {
        "tx_id": "tx-owner",
        "sender": "sender",
        "recipient": "recipient",
        "file_name": "shared.txt",
        "file_path": "./uploads/shared.txt",
        "alias": "",
        "recipient_alias": "",
        "is_sensitive": "0",
        "file_owner": "owner-host:6001",
    }

    bc.chain = [{
        "index": 1,
        "timestamp": "now",
        "transactions": [tx],
        "proof": 100,
        "previous_hash": "hash",
    }]
    bc.nodes = {"peer-b:5000"}

    downloaded = Path("uploads/shared.txt")
    assert not downloaded.exists()

    class DummyResponse:
        def __init__(self, status, json_data=None, content=b""):
            self.status_code = status
            self._json = json_data
            self._content = content

        def json(self):
            if self._json is None:
                raise ValueError("No JSON body")
            return self._json

        def iter_content(self, chunk_size):
            yield self._content

    calls = []
    file_bytes = b"network-bytes"

    def fake_get(url, *args, **kwargs):
        calls.append(url)
        if url == "http://peer-b:5000/chain":
            return DummyResponse(200, {"chain": bc.chain})
        if url == "http://peer-b:5000/file/shared.txt":
            return DummyResponse(404)
        if url == "http://owner-host:6001/file/shared.txt":
            return DummyResponse(200, content=file_bytes)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(module.requests, "get", fake_get)

    bc.sync_files()

    assert downloaded.exists(), "File should be downloaded from the recorded owner"
    assert downloaded.read_bytes() == file_bytes
    assert "http://owner-host:6001/file/shared.txt" in calls


def test_sync_files_skips_owner_when_local_node(isolated_blockchain, monkeypatch):
    bc, module = isolated_blockchain

    bc.validator_netloc = "owner-host:6001"

    tx = {
        "tx_id": "tx-owner",
        "sender": "sender",
        "recipient": "recipient",
        "file_name": "shared.txt",
        "file_path": "./uploads/shared.txt",
        "alias": "",
        "recipient_alias": "",
        "is_sensitive": "0",
        "file_owner": "owner-host:6001",
    }

    bc.chain = [{
        "index": 1,
        "timestamp": "now",
        "transactions": [tx],
        "proof": 100,
        "previous_hash": "hash",
    }]
    bc.nodes = {"peer-b:5000"}

    downloaded = Path("uploads/shared.txt")
    assert not downloaded.exists()

    class DummyResponse:
        def __init__(self, status, json_data=None, content=b""):
            self.status_code = status
            self._json = json_data
            self._content = content

        def json(self):
            if self._json is None:
                raise ValueError("No JSON body")
            return self._json

        def iter_content(self, chunk_size):
            yield self._content

    calls = []
    scheduled = []

    def fake_get(url, *args, **kwargs):
        calls.append(url)
        if url == "http://peer-b:5000/chain":
            return DummyResponse(200, {"chain": bc.chain})
        if url == "http://peer-b:5000/file/shared.txt":
            return DummyResponse(404)
        raise AssertionError(f"Unexpected URL requested: {url}")

    def fake_schedule(self, target_netloc, tx_arg, attempt):
        scheduled.append((target_netloc, attempt))

    monkeypatch.setattr(module.requests, "get", fake_get)
    monkeypatch.setattr(module.Blockchain, "_schedule_deferred_retry", fake_schedule, raising=False)

    bc.sync_files()

    assert not downloaded.exists(), "File should not have been downloaded"
    assert "http://owner-host:6001/file/shared.txt" not in calls
    assert scheduled == [("peer-b:5000", 1)]


def test_upload_host_validation_and_sync_uses_validator_owner(isolated_blockchain, monkeypatch):
    bc, module = isolated_blockchain

    bc.validator_netloc = "owner-host:6001"
    bc.add_trusted_node("owner-host:6001")
    client = module.app.test_client()

    sender = bc.validator_public_key_hex
    private_key_hex = bc.validator_private_key_hex

    def build_form(tx_id):
        form = {
            "sender": sender,
            "recipient": "recipient",
            "alias": "",
            "recipient_alias": "",
            "is_sensitive": "0",
            "file_name": "sync.txt",
            "file_path": "./pending_uploads/ignored.txt",
            "tx_id": tx_id,
        }
        form["signature"] = _sign_transaction(module, private_key_hex, form)
        return form

    spoof_resp = client.post(
        "/node/upload",
        data={**build_form(uuid.uuid4().hex), "file": (BytesIO(b"spoof"), "sync.txt")},
        content_type="multipart/form-data",
        base_url="http://peer-b:5000",
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert spoof_resp.status_code == 400
    assert bc.transactions == []

    good_tx_id = uuid.uuid4().hex
    valid_resp = client.post(
        "/node/upload",
        data={**build_form(good_tx_id), "file": (BytesIO(b"payload"), "sync.txt")},
        content_type="multipart/form-data",
        base_url="http://owner-host:6001",
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert valid_resp.status_code == 201
    assert bc.transactions, "Accepted upload should be recorded"

    tx = bc.transactions[-1]
    assert tx["file_owner"] == "owner-host:6001"
    stored_name = tx["stored_file_name"]

    prev_hash = bc.hash(bc.last_block)
    bc.create_block(proof=100, previous_hash=prev_hash)
    chain_snapshot = list(bc.chain)

    uploaded_path = Path(module.UPLOAD_FOLDER) / stored_name
    assert uploaded_path.exists()
    uploaded_path.unlink()

    bc.validator_netloc = "remote-peer:5000"
    bc.nodes = {"peer-b:5000"}
    bc.trusted_nodes = set()

    file_bytes = b"genuine-sync"

    class DummyResponse:
        def __init__(self, status, json_data=None, content=b""):
            self.status_code = status
            self._json = json_data
            self._content = content

        def json(self):
            if self._json is None:
                raise ValueError("No JSON body")
            return self._json

        def iter_content(self, chunk_size):
            yield self._content

    calls = []

    def fake_get(url, *args, **kwargs):
        calls.append(url)
        if url == f"http://peer-b:5000/file/{stored_name}":
            return DummyResponse(404)
        if url == f"http://owner-host:6001/file/{stored_name}":
            return DummyResponse(200, content=file_bytes)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(module.requests, "get", fake_get)
    monkeypatch.setattr(bc, "_fetch_chain_with_retry", lambda netloc: chain_snapshot)

    bc.sync_files()

    final_path = Path(module.UPLOAD_FOLDER) / stored_name
    assert final_path.exists()
    assert final_path.read_bytes() == file_bytes
    assert f"http://owner-host:6001/file/{stored_name}" in calls


def test_resolve_conflicts_clears_pending_transactions(isolated_blockchain, monkeypatch):
    bc, module = isolated_blockchain

    genesis_block = {
        "index": 1,
        "timestamp": "now",
        "transactions": [],
        "proof": 100,
        "previous_hash": "0",
    }
    bc.chain = [genesis_block]

    pending_transactions = [
        {"tx_id": "tx-1", "payload": "data-1"},
        {"tx_id": "tx-2", "payload": "data-2"},
    ]
    bc.transactions = list(pending_transactions)

    new_block = {
        "index": 2,
        "timestamp": "later",
        "transactions": pending_transactions,
        "proof": 200,
        "previous_hash": "hash-1",
    }
    best_chain = [genesis_block, new_block]

    bc.trusted_nodes = {"peer-a:5000"}

    monkeypatch.setattr(bc, "_fetch_chain_with_retry", lambda netloc: best_chain)
    monkeypatch.setattr(bc, "valid_chain", lambda chain: True)

    saved_states = []

    def fake_save_data():
        saved_states.append(list(bc.transactions))

    monkeypatch.setattr(bc, "save_data", fake_save_data)
    monkeypatch.setattr(bc, "sync_files", lambda: None)

    replaced = bc.resolve_conflicts()

    assert replaced is True
    assert bc.chain == best_chain
    assert bc.transactions == []
    assert saved_states == [[]]


def test_resolve_conflicts_removes_pending_files(isolated_blockchain, monkeypatch):
    bc, module = isolated_blockchain

    genesis_block = {
        "index": 1,
        "timestamp": "now",
        "transactions": [],
        "proof": 100,
        "previous_hash": "0",
    }
    bc.chain = [genesis_block]

    stored_basename = "pending_doc.txt"
    pending_rel = os.path.join(module.PENDING_FOLDER, stored_basename)
    pending_path = Path(pending_rel)
    pending_path.write_bytes(b"pending-bytes")

    pending_tx = {
        "tx_id": "tx-pending",
        "sender": "sender",
        "recipient": "recipient",
        "file_name": "doc.txt",
        "file_path": pending_rel,
        "stored_file_name": stored_basename,
        "alias": "",
        "recipient_alias": "",
        "is_sensitive": "0",
        "file_owner": "peer-a:5000",
    }
    bc.transactions = [dict(pending_tx)]

    uploaded_path = Path(module.UPLOAD_FOLDER) / stored_basename
    uploaded_path.write_bytes(b"uploaded-bytes")

    chain_tx = dict(pending_tx)
    chain_tx["file_path"] = os.path.join(module.UPLOAD_FOLDER, stored_basename)

    best_chain = [
        genesis_block,
        {
            "index": 2,
            "timestamp": "later",
            "transactions": [chain_tx],
            "proof": 200,
            "previous_hash": "hash-1",
        },
    ]

    bc.trusted_nodes = {"peer-a:5000"}

    monkeypatch.setattr(bc, "_fetch_chain_with_retry", lambda netloc: best_chain)
    monkeypatch.setattr(bc, "valid_chain", lambda chain: True)

    sync_called = {}

    def fake_sync():
        sync_called["called"] = True
        assert uploaded_path.exists()
        assert not pending_path.exists()

    monkeypatch.setattr(bc, "sync_files", fake_sync)

    replaced = bc.resolve_conflicts()

    assert replaced is True
    assert bc.chain == best_chain
    assert bc.transactions == []
    assert sync_called == {"called": True}
    pending_dir = Path(module.PENDING_FOLDER)
    assert pending_dir.exists()
    assert not any(pending_dir.iterdir())


def test_resolve_conflicts_removes_late_pending_upload(isolated_blockchain, monkeypatch):
    bc, module = isolated_blockchain

    pending_name = "late_pending.txt"
    pending_path = Path(module.PENDING_FOLDER) / pending_name
    pending_path.write_text("pending-bytes")

    tx_id = "tx-late"
    pending_tx = {
        "tx_id": tx_id,
        "sender": "sender",
        "recipient": "recipient",
        "file_name": pending_name,
        "file_path": f"./pending_uploads/{pending_name}",
        "alias": "",
        "recipient_alias": "",
        "is_sensitive": "0",
        "stored_file_name": pending_name,
    }

    bc.nodes = {"peer-a:5000"}
    bc.trusted_nodes = {"peer-a:5000"}

    best_chain = list(bc.chain)
    best_chain.append(
        {
            "index": len(bc.chain) + 1,
            "timestamp": "now",
            "transactions": [dict(pending_tx)],
            "proof": 200,
            "previous_hash": "hash",
        }
    )

    appended = False

    def fake_fetch(netloc):
        nonlocal appended
        assert netloc == "peer-a:5000"
        if not appended:
            bc.transactions.append(dict(pending_tx))
            appended = True
        return best_chain

    monkeypatch.setattr(bc, "_fetch_chain_with_retry", fake_fetch)
    monkeypatch.setattr(bc, "valid_chain", lambda chain: True)

    sync_calls = []
    monkeypatch.setattr(bc, "sync_files", lambda: sync_calls.append(True))

    replaced = bc.resolve_conflicts()

    assert replaced is True
    assert not any(tx.get("tx_id") == tx_id for tx in bc.transactions)
    assert not pending_path.exists()
    assert sync_calls, "sync_files should still be invoked"


def test_set_validator_identity_auto_trusts_netloc(isolated_blockchain):
    bc, module = isolated_blockchain

    rsa_key = RSA.generate(1024)
    private_key_hex = binascii.hexlify(rsa_key.export_key(format='DER')).decode('ascii')
    public_key_hex = binascii.hexlify(rsa_key.publickey().export_key(format='DER')).decode('ascii')

    bc.trusted_nodes = set()

    bc.set_validator_identity(
        "validator-with-netloc",
        private_key_hex,
        netloc="https://validator-host:7000/",
        public_key_hex=public_key_hex,
    )

    assert "validator-host:7000" in bc.trusted_nodes
    assert bc.is_authorized_validator()


def test_sync_files_rejects_paths_outside_uploads(isolated_blockchain, monkeypatch, tmp_path):
    bc, module = isolated_blockchain

    tampered_path = "./uploads/../../evil.txt"
    tx = {
        "tx_id": "tx-unsafe",
        "sender": "sender",
        "recipient": "recipient",
        "file_name": "evil.txt",
        "file_path": tampered_path,
        "alias": "",
        "recipient_alias": "",
        "is_sensitive": "0",
        "file_owner": "peer-a:5000",
    }

    bc.chain = [{
        "index": 1,
        "timestamp": "now",
        "transactions": [tx],
        "proof": 100,
        "previous_hash": "hash",
    }]
    bc.nodes = {"peer-a:5000"}

    class DummyResponse:
        def __init__(self, status, json_data=None):
            self.status_code = status
            self._json = json_data

        def json(self):
            if self._json is None:
                raise ValueError("No JSON body")
            return self._json

        def iter_content(self, chunk_size):
            raise AssertionError("File download should not be attempted for unsafe paths")

    calls = []

    def fake_get(url, *args, **kwargs):
        calls.append(url)
        if url == "http://peer-a:5000/chain":
            return DummyResponse(200, {"chain": bc.chain})
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(module.requests, "get", fake_get)

    bc.sync_files()

    assert not (tmp_path / "evil.txt").exists(), "Tampered file must not be written outside uploads"
    assert all("/file/" not in call for call in calls if call != "http://peer-a:5000/chain")

    failures = bc.get_sync_failures()
    assert any(
        entry.get("stage") == "validation"
        and "unsafe file path" in (entry.get("error") or "").lower()
        for entry in failures
    ), "Unsafe path rejection should be recorded"


def test_file_route_and_sync_use_stored_filename(isolated_blockchain, monkeypatch):
    bc, module = isolated_blockchain

    file_bytes = b"stored-file"
    stored_basename = "stored_report.txt"
    pending_rel = os.path.join(module.PENDING_FOLDER, stored_basename)
    os.makedirs(os.path.dirname(pending_rel), exist_ok=True)
    with open(pending_rel, "wb") as handle:
        handle.write(file_bytes)

    bc.nodes = {"peer-a:5000"}

    bc.add_transaction(
        tx_id="tx-stored",
        sender=module.MINING_SENDER,
        recipient="recipient",
        file_name="report.txt",
        file_path=pending_rel,
        alias="",
        recipient_alias="",
        signature="",
        is_sensitive="0",
        file_owner="peer-a:5000",
        stored_file_name=stored_basename,
        allow_system_transaction=True,
    )

    block = bc.create_block(proof=200, previous_hash="hash")
    tx = block["transactions"][0]
    stored_name = tx["stored_file_name"]

    upload_path = Path(module.UPLOAD_FOLDER) / stored_name
    assert upload_path.exists()
    assert upload_path.read_bytes() == file_bytes

    client = module.app.test_client()
    response = client.get(f"/file/{stored_name}")
    assert response.status_code == 200
    assert response.data == file_bytes

    upload_path.unlink()
    assert not upload_path.exists()

    block_module_chain = list(bc.chain)
    bc.nodes = {"peer-a:5000"}

    class DummyResponse:
        def __init__(self, status, json_data=None, content=b""):
            self.status_code = status
            self._json = json_data
            self._content = content

        def json(self):
            if self._json is None:
                raise ValueError("No JSON body")
            return self._json

        def iter_content(self, chunk_size):
            yield self._content

    def fake_get(url, *args, **kwargs):
        if url == "http://peer-a:5000/chain":
            return DummyResponse(200, {"chain": block_module_chain})
        if url == f"http://peer-a:5000/file/{stored_name}":
            return DummyResponse(200, content=file_bytes)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(module.requests, "get", fake_get)

    bc.sync_files()

    assert upload_path.exists()
    assert upload_path.read_bytes() == file_bytes


def test_validator_key_rotation_preserves_signature_history(isolated_blockchain):
    bc, module = isolated_blockchain

    prev_hash = module.Blockchain.hash(bc.last_block)
    block_one = bc.create_block(proof=111, previous_hash=prev_hash)
    assert block_one["validator_signatures"], "Block should contain validator signatures"

    first_signature = block_one["validator_signatures"][0]
    original_key_id = first_signature.get("key_id")
    assert original_key_id, "Signatures must include the originating key identifier"

    original_keys = dict(bc.validator_public_keys[bc.validator_id])
    assert original_key_id in original_keys

    new_key = RSA.generate(1024)
    new_private_hex = binascii.hexlify(new_key.export_key(format='DER')).decode('ascii')
    new_public_hex = binascii.hexlify(new_key.publickey().export_key(format='DER')).decode('ascii')

    bc.update_validator_public_key(bc.validator_id, new_public_hex)
    bc.set_validator_identity(bc.validator_id, new_private_hex, public_key_hex=new_public_hex)

    prev_hash = module.Blockchain.hash(bc.last_block)
    block_two = bc.create_block(proof=222, previous_hash=prev_hash)
    latest_signature = block_two["validator_signatures"][0]
    rotated_key_id = latest_signature.get("key_id")

    assert rotated_key_id and rotated_key_id != original_key_id

    keys_after_rotation = dict(bc.validator_public_keys[bc.validator_id])
    assert original_key_id in keys_after_rotation
    assert rotated_key_id in keys_after_rotation

    assert bc.verify_block_signatures(block_one)
    assert bc.verify_block_signatures(block_two)

    bc.validator_public_keys[bc.validator_id] = {original_key_id: keys_after_rotation[original_key_id]}

    assert bc.verify_block_signatures(block_one)
    assert not bc.verify_block_signatures(block_two)


def test_transactions_endpoint_reports_location_states(isolated_blockchain):
    bc, module = isolated_blockchain
    client = module.app.test_client()

    sender_private_hex, sender_public_hex = _generate_rsa_keypair()

    tx_id = "tx-shared-123"
    base_payload = {
        "tx_id": tx_id,
        "sender": sender_public_hex,
        "recipient": "recipient-public",
        "file_name": "document.txt",
        "file_path": f"{module.PENDING_FOLDER}/document.txt",
        "alias": "",
        "recipient_alias": "",
        "is_sensitive": "0",
    }
    signature = _sign_transaction(module, sender_private_hex, base_payload)
    base_payload["signature"] = signature

    genesis_index = bc.last_block["index"]

    first_response = client.post(
        "/transactions/new",
        json={**base_payload, "skip_broadcast": True},
    )
    assert first_response.status_code == 201
    first_body = first_response.get_json()
    assert first_body["added"] is True
    assert first_body["mined"] is False
    assert first_body["location"] == genesis_index + 1
    assert "will be added" in first_body["message"]

    second_response = client.post(
        "/transactions/new",
        json={**base_payload, "skip_broadcast": True},
    )
    assert second_response.status_code == 200
    second_body = second_response.get_json()
    assert second_body["added"] is False
    assert second_body["location"] == "pending"
    assert "pending" in second_body["message"].lower()

    prev_hash = module.Blockchain.hash(module.blockchain.last_block)
    block = module.blockchain.create_block(proof=200, previous_hash=prev_hash)
    assert block["index"] == genesis_index + 1

    third_response = client.post(
        "/transactions/new",
        json={**base_payload, "skip_broadcast": True},
    )
    assert third_response.status_code == 200
    third_body = third_response.get_json()
    assert third_body["added"] is False
    assert third_body["location"] == block["index"]
    assert "already accepted" in third_body["message"]
