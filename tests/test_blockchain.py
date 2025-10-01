import importlib
import os
import sys
from pathlib import Path
import pytest

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
    bc.transactions = []
    bc.nodes = set()
    bc.trusted_nodes = set()

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
