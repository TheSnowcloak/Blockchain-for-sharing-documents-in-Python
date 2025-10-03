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

    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        lookup_calls.append((host, port, family, type, proto, flags))
        if host != "trusted.example.com":
            raise AssertionError(f"Unexpected lookup for host {host}")
        return [
            (
                module.socket.AF_INET,
                module.socket.SOCK_STREAM,
                6,
                "",
                (resolved_ip, 0),
            )
        ]

    monkeypatch.setattr(module.socket, "getaddrinfo", fake_getaddrinfo)

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
    assert lookup_calls == [
        ("trusted.example.com", None, module.socket.AF_UNSPEC, 0, 0, 0)
    ], "DNS lookup should be cached after first resolution"


def test_hostname_with_ipv6_only_resolution(isolated_app, monkeypatch):
    module = isolated_app
    blockchain = module.blockchain

    trusted_netloc = "ipv6-only.example.com:5000"
    blockchain.add_trusted_node(trusted_netloc)

    ipv6_address = "2001:db8::1234"
    lookup_calls = []

    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        lookup_calls.append((host, port, family, type, proto, flags))
        if host != "ipv6-only.example.com":
            raise AssertionError(f"Unexpected lookup for host {host}")
        return [
            (
                module.socket.AF_INET6,
                module.socket.SOCK_STREAM,
                6,
                "",
                (ipv6_address, 0, 0, 0),
            )
        ]

    monkeypatch.setattr(module.socket, "getaddrinfo", fake_getaddrinfo)

    client = module.app.test_client()

    response = client.get(
        "/trusted_nodes/keys",
        environ_base={"REMOTE_ADDR": ipv6_address},
    )
    assert response.status_code == 200

    cached_ips = blockchain.get_trusted_netloc_ips(trusted_netloc)
    assert ipv6_address in cached_ips
    assert lookup_calls == [
        ("ipv6-only.example.com", None, module.socket.AF_UNSPEC, 0, 0, 0)
    ], "DNS lookup should be cached after first resolution"


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

    forbidden_message = module._TRUSTED_MANAGEMENT_FORBIDDEN_MESSAGE

    response = client.post(
        "/trusted_nodes/register",
        json={"nodes": ["203.0.113.99:5000"]},
        environ_base={"REMOTE_ADDR": "198.51.100.42"},
    )

    assert response.status_code == 403
    assert response.get_json()["message"] == forbidden_message

    module.blockchain.add_trusted_node("198.51.100.10:5000")

    removal = client.post(
        "/trusted_nodes/remove",
        json={"node": "203.0.113.99:5000"},
        environ_base={"REMOTE_ADDR": "203.0.113.99"},
    )

    assert removal.status_code == 403
    assert removal.get_json()["message"] == forbidden_message


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


def test_validator_configure_rejects_untrusted_caller(isolated_app):
    module = isolated_app
    client = module.app.test_client()

    response_get = client.get(
        "/validator/configure",
        environ_base={"REMOTE_ADDR": "198.51.100.77"},
    )
    assert response_get.status_code == 403
    assert response_get.get_json()["message"] == module._VALIDATOR_MANAGEMENT_FORBIDDEN_MESSAGE

    response_post = client.post(
        "/validator/configure",
        json={
            "validator_id": "validator-1",
            "private_key_hex": "00",
        },
        environ_base={"REMOTE_ADDR": "198.51.100.77"},
    )
    assert response_post.status_code == 403
    assert response_post.get_json()["message"] == module._VALIDATOR_MANAGEMENT_FORBIDDEN_MESSAGE


def test_validator_configure_allows_trusted_caller(isolated_app):
    module = isolated_app
    blockchain = module.blockchain

    blockchain.add_trusted_node("192.0.2.99:5000")

    client = module.app.test_client()

    response_get = client.get(
        "/validator/configure",
        environ_base={"REMOTE_ADDR": "192.0.2.99"},
    )
    assert response_get.status_code == 200

    response_post = client.post(
        "/validator/configure",
        json={
            "validator_id": "validator-1",
            "private_key_hex": "deadbeef",
            "netloc": "192.0.2.99:5000",
            "public_key_hex": "cafebabe",
        },
        environ_base={"REMOTE_ADDR": "192.0.2.99"},
    )

    assert response_post.status_code == 200
    payload = response_post.get_json()
    assert payload["validator_id"] == "validator-1"
    assert payload["netloc"] == "192.0.2.99:5000"
    assert payload["public_key_hex"] == "cafebabe"


def test_validator_configure_allows_localhost(isolated_app):
    module = isolated_app
    client = module.app.test_client()

    response_get = client.get(
        "/validator/configure",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert response_get.status_code == 200

    response_post = client.post(
        "/validator/configure",
        json={
            "validator_id": "validator-local",
            "private_key_hex": "feedface",
        },
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response_post.status_code == 200
    assert module.blockchain.validator_id == "validator-local"
