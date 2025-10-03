import io
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from Blockchain_client import blockchain_client


@pytest.fixture
def configured_client(tmp_path, monkeypatch):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()

    monkeypatch.setitem(blockchain_client.app.config, 'UPLOAD_FOLDER', str(upload_dir))
    blockchain_client.app.config['TESTING'] = True

    monkeypatch.setattr(blockchain_client, 'sign_transaction', lambda *_args, **_kwargs: 'signature')

    return blockchain_client.app.test_client(), upload_dir


def _form_data():
    return {
        'sender_public_key': 'pub',
        'sender_private_key': 'priv',
        'recipient_public_key': 'recipient',
        'is_sensitive': '0',
    }


def test_failed_upload_removes_temp_file(configured_client, monkeypatch):
    client, upload_dir = configured_client

    files_seen = []

    class FakeResponse:
        status_code = 400
        text = 'node failure'

        def json(self):
            return {}

    def fake_post(url, files, data, timeout):
        files_seen.append([p.name for p in upload_dir.iterdir()])
        return FakeResponse()

    monkeypatch.setattr(blockchain_client.requests, 'post', fake_post)

    data = _form_data()
    data['file'] = (io.BytesIO(b'payload'), 'doc.txt')

    response = client.post('/upload', data=data, content_type='multipart/form-data')

    assert response.status_code == 400
    assert files_seen and files_seen[0], 'temporary file should exist during upload'
    assert not list(upload_dir.iterdir())


def test_successful_upload_removes_temp_file(configured_client, monkeypatch):
    client, upload_dir = configured_client

    files_seen = []

    class FakeResponse:
        status_code = 201
        text = 'ok'

        @staticmethod
        def json():
            return {'status': 'ok'}

    def fake_post(url, files, data, timeout):
        files_seen.append([p.name for p in upload_dir.iterdir()])
        return FakeResponse()

    monkeypatch.setattr(blockchain_client.requests, 'post', fake_post)

    data = _form_data()
    data['file'] = (io.BytesIO(b'payload'), 'doc.txt')

    response = client.post('/upload', data=data, content_type='multipart/form-data')

    assert response.status_code == 201
    assert response.get_json() == {'status': 'ok'}
    assert files_seen and files_seen[0], 'temporary file should exist during upload'
    assert not list(upload_dir.iterdir())
