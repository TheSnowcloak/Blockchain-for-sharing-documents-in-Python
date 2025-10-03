import binascii

from Crypto.PublicKey import RSA

pytest_plugins = ("tests.test_trusted_resolution",)


def _generate_key_pair_hex():
    key = RSA.generate(1024)
    private_hex = binascii.hexlify(key.export_key(format="DER")).decode("ascii")
    public_hex = binascii.hexlify(key.publickey().export_key(format="DER")).decode("ascii")
    return private_hex, public_hex


def test_validator_config_rejects_mismatched_public_key(isolated_app):
    module = isolated_app
    client = module.app.test_client()

    private_hex, public_hex = _generate_key_pair_hex()
    mismatch_tail = "0" if public_hex[-1] != "0" else "1"
    mismatched_public_hex = f"{public_hex[:-1]}{mismatch_tail}"

    response = client.post(
        "/validator/configure",
        json={
            "validator_id": "validator-1",
            "private_key_hex": private_hex,
            "public_key_hex": mismatched_public_hex,
        },
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 400
    body = response.get_json()
    assert "match" in body["message"].lower()

    successful = client.post(
        "/validator/configure",
        json={
            "validator_id": "validator-1",
            "private_key_hex": private_hex,
            "public_key_hex": public_hex,
        },
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert successful.status_code == 200
    success_body = successful.get_json()
    assert success_body["validator_id"] == "validator-1"
    assert success_body["public_key_hex"].lower() == public_hex.lower()
