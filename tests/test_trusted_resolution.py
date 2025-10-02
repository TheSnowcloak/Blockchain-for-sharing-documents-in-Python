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
