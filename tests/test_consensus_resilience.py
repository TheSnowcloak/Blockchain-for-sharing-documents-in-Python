import importlib
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def isolated_blockchain(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    module = importlib.import_module("blockchain_node.blockchain")
    module = importlib.reload(module)

    module.DATA_FILE = "blockchain_data.json"
    module.KEYS_DB_FILE = "keys_db.json"

    os.makedirs(module.PENDING_FOLDER, exist_ok=True)
    os.makedirs(module.UPLOAD_FOLDER, exist_ok=True)

    blockchain = module.Blockchain()
    module.blockchain = blockchain
    blockchain.transactions = []
    blockchain.nodes = set()
    blockchain.trusted_nodes = set()

    return blockchain


def test_resolve_conflicts_skips_garbage_responses(isolated_blockchain, monkeypatch):
    blockchain = isolated_blockchain
    blockchain.nodes.add("malicious:5000")

    original_chain = [dict(block) for block in blockchain.chain]

    monkeypatch.setattr(blockchain, "_fetch_chain_with_retry", lambda netloc: ["garbage"])

    replaced = blockchain.resolve_conflicts()

    assert replaced is False
    assert [dict(block) for block in blockchain.chain] == original_chain
