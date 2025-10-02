import binascii
import importlib
import os
import sys
from pathlib import Path

import pytest
from Crypto.PublicKey import RSA

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
    bc.transactions = []
    bc.nodes = set()
    bc.trusted_nodes = set()

    # Configure a validator identity so tests can mine blocks without network setup.
    rsa_key = RSA.generate(1024)
    private_key_hex = binascii.hexlify(rsa_key.export_key(format='DER')).decode('ascii')
    public_key_hex = binascii.hexlify(rsa_key.publickey().export_key(format='DER')).decode('ascii')
    bc.set_validator_identity('test-validator', private_key_hex, public_key_hex=public_key_hex)

    return bc, blockchain_module


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
    )

    block = bc.create_block(proof=200, previous_hash="hash")
    assert block["transactions"], "Transaction should be recorded in the new block"

    tx = block["transactions"][0]
    assert tx["file_path"] == "./uploads/doc.txt"
    assert tx["file_owner"] == "127.0.0.1:5000"
    assert tx["stored_file_name"] == "doc.txt"


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
