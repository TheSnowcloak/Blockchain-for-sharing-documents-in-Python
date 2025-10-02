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


def test_hostname_resolution_allows_trusted_access(isolated_app, monkeypatch):
    module = isolated_app
    blockchain = module.blockchain

    trusted_netloc = "trusted.example.com:5000"
    blockchain.add_trusted_node(trusted_netloc)

    resolved_ip = "203.0.113.7"
    lookup_calls = []

    def fake_gethostbyname_ex(host):
        lookup_calls.append(host)
        if host != "trusted.example.com":
            raise AssertionError(f"Unexpected lookup for host {host}")
        return host, [], [resolved_ip]

    monkeypatch.setattr(module.socket, "gethostbyname_ex", fake_gethostbyname_ex)

    client = module.app.test_client()

    response = client.get(
        "/trusted_nodes/keys",
        environ_base={"REMOTE_ADDR": resolved_ip},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert isinstance(body, dict)
    assert "validator_public_keys" in body

    second = client.get(
        "/trusted_nodes/keys",
        environ_base={"REMOTE_ADDR": resolved_ip},
    )
    assert second.status_code == 200
    assert lookup_calls == ["trusted.example.com"], "DNS lookup should be cached after first resolution"


def test_ipv6_bracketed_trusted_registration(isolated_app):
    module = isolated_app
    blockchain = module.blockchain

    blockchain.add_trusted_node("[::1]:5000")
    assert "[::1]:5000" in blockchain.trusted_nodes

    client = module.app.test_client()

    response = client.get(
        "/trusted_nodes/keys",
        environ_base={"REMOTE_ADDR": "::1"},
    )

    assert response.status_code == 200
    assert "::1" in blockchain.get_trusted_netloc_ips("[::1]:5000")


def test_ipv6_trusted_chain_returns_unpruned(isolated_app):
    module = isolated_app
    blockchain = module.blockchain

    blockchain.add_trusted_node("[::1]:5000")

    with blockchain.lock:
        blockchain.chain = [
            {
                "index": 1,
                "timestamp": "2024-01-01T00:00:00",
                "transactions": [
                    {"tx_id": "sensitive", "is_sensitive": "1"},
                    {"tx_id": "public", "is_sensitive": "0"},
                ],
                "proof": 100,
                "previous_hash": "1",
            }
        ]

    client = module.app.test_client()

    trusted_response = client.get(
        "/chain",
        environ_base={"REMOTE_ADDR": "::1"},
    )
    assert trusted_response.status_code == 200
    trusted_body = trusted_response.get_json()
    assert trusted_body["chain"][0]["transactions"][0]["tx_id"] == "sensitive"
    assert len(trusted_body["chain"][0]["transactions"]) == 2

    untrusted_response = client.get(
        "/chain",
        environ_base={"REMOTE_ADDR": "203.0.113.5"},
    )
    assert untrusted_response.status_code == 200
    untrusted_body = untrusted_response.get_json()
    assert len(untrusted_body["chain"][0]["transactions"]) == 1
    assert untrusted_body["chain"][0]["transactions"][0]["tx_id"] == "public"


def test_untrusted_caller_blocked_from_trusted_management(isolated_app):
    module = isolated_app
    client = module.app.test_client()

    response = client.post(
        "/trusted_nodes/register",
        json={"nodes": ["203.0.113.99:5000"]},
        environ_base={"REMOTE_ADDR": "198.51.100.42"},
    )

    assert response.status_code == 403
    assert response.get_json()["message"] == "Caller is not authorized to manage trusted nodes"

    module.blockchain.add_trusted_node("198.51.100.10:5000")

    removal = client.post(
        "/trusted_nodes/remove",
        json={"node": "203.0.113.99:5000"},
        environ_base={"REMOTE_ADDR": "203.0.113.99"},
    )

    assert removal.status_code == 403
    assert removal.get_json()["message"] == "Caller is not authorized to manage trusted nodes"


def test_trusted_caller_can_manage_trusted_nodes(isolated_app):
    module = isolated_app
    blockchain = module.blockchain

    trusted_admin = "192.0.2.15:5000"
    blockchain.add_trusted_node(trusted_admin)

    client = module.app.test_client()

    registration = client.post(
        "/trusted_nodes/register",
        json={"nodes": ["203.0.113.200:5000"]},
        environ_base={"REMOTE_ADDR": "192.0.2.15"},
    )

    assert registration.status_code == 201
    assert "203.0.113.200:5000" in blockchain.trusted_nodes

    blockchain.add_trusted_node("203.0.113.201:5000")

    removal = client.post(
        "/trusted_nodes/remove",
        json={"node": "203.0.113.201:5000"},
        environ_base={"REMOTE_ADDR": "192.0.2.15"},
    )

    assert removal.status_code == 200
    assert "203.0.113.201:5000" not in blockchain.trusted_nodes
