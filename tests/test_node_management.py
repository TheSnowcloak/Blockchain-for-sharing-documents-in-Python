import importlib
import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def isolated_app(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    module_name = "blockchain_node.blockchain"
    module = importlib.import_module(module_name)
    module = importlib.reload(module)

    module.DATA_FILE = "blockchain_data.json"
    module.KEYS_DB_FILE = "keys_db.json"

    os.makedirs(module.PENDING_FOLDER, exist_ok=True)
    os.makedirs(module.UPLOAD_FOLDER, exist_ok=True)

    blockchain_instance = module.Blockchain()
    module.blockchain = blockchain_instance
    blockchain_instance.transactions = []
    blockchain_instance.nodes = set()
    blockchain_instance.trusted_nodes = set()

    return module


def _trusted_environ():
    return {"REMOTE_ADDR": "127.0.0.1"}


def test_nodes_register_accepts_json_string_payload(isolated_app):
    module = isolated_app
    client = module.app.test_client()

    response = client.post(
        "/nodes/register",
        data='"example.com:6000"',
        content_type="application/json",
        environ_base=_trusted_environ(),
    )

    assert response.status_code == 201
    body = response.get_json()
    assert body["message"] == "Nodes added"
    assert "example.com:6000" in module.blockchain.nodes


def test_nodes_register_rejects_invalid_netloc(isolated_app):
    module = isolated_app
    client = module.app.test_client()

    initial_nodes = set(module.blockchain.nodes)

    response = client.post(
        "/nodes/register",
        data='"http://:5000"',
        content_type="application/json",
        environ_base=_trusted_environ(),
    )

    assert response.status_code == 400
    body = response.get_json()
    assert "Invalid node address" in body["message"]
    assert module.blockchain.nodes == initial_nodes


def test_trusted_register_rejects_invalid_netloc(isolated_app):
    module = isolated_app
    module.blockchain.add_trusted_node("127.0.0.1:5000")
    client = module.app.test_client()

    initial_trusted = set(module.blockchain.trusted_nodes)

    response = client.post(
        "/trusted_nodes/register",
        data='"http://:5000"',
        content_type="application/json",
        environ_base=_trusted_environ(),
    )

    assert response.status_code == 400
    body = response.get_json()
    assert "Invalid trusted node address" in body["message"]
    assert module.blockchain.trusted_nodes == initial_trusted


def test_nodes_remove_invalid_address_returns_400(isolated_app):
    module = isolated_app
    client = module.app.test_client()

    module.blockchain.add_node("127.0.0.1:5000")
    initial_nodes = set(module.blockchain.nodes)

    response = client.post(
        "/nodes/remove",
        json={"node": "http://:5000"},
        environ_base=_trusted_environ(),
    )

    assert response.status_code == 400
    body = response.get_json()
    assert "Invalid node address" in body["message"]
    assert module.blockchain.nodes == initial_nodes


def test_nodes_remove_valid_address_succeeds(isolated_app):
    module = isolated_app
    client = module.app.test_client()

    module.blockchain.add_node("127.0.0.1:5000")

    response = client.post(
        "/nodes/remove",
        json={"node": "127.0.0.1:5000"},
        environ_base=_trusted_environ(),
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["message"] == "Node 127.0.0.1:5000 removed"
    assert "127.0.0.1:5000" not in module.blockchain.nodes


def test_trusted_nodes_remove_invalid_address_returns_400(isolated_app):
    module = isolated_app
    client = module.app.test_client()

    module.blockchain.add_trusted_node("127.0.0.1:5000")
    initial_trusted = set(module.blockchain.trusted_nodes)

    response = client.post(
        "/trusted_nodes/remove",
        json={"node": "http://:5000"},
        environ_base=_trusted_environ(),
    )

    assert response.status_code == 400
    body = response.get_json()
    assert "Invalid trusted node address" in body["message"]
    assert module.blockchain.trusted_nodes == initial_trusted


def test_trusted_nodes_remove_valid_address_succeeds(isolated_app):
    module = isolated_app
    client = module.app.test_client()

    module.blockchain.add_trusted_node("127.0.0.1:5000")

    response = client.post(
        "/trusted_nodes/remove",
        json={"node": "127.0.0.1:5000"},
        environ_base=_trusted_environ(),
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["message"] == "Trusted node 127.0.0.1:5000 removed"
    assert "127.0.0.1:5000" not in module.blockchain.trusted_nodes
