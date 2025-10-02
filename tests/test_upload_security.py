import hashlib
import json
import os
import unittest
from unittest import mock
import uuid
from io import BytesIO

from blockchain_node import blockchain as node_module


class UploadSecurityTestCase(unittest.TestCase):
    def setUp(self):
        self.client = node_module.app.test_client()
        node_module.blockchain.transactions = []
        self._created_paths = []
        self._keys_db_backup = None
        for folder in (node_module.PENDING_FOLDER, node_module.UPLOAD_FOLDER):
            if not os.path.isdir(folder):
                continue
            for name in os.listdir(folder):
                path = os.path.join(folder, name)
                if os.path.isfile(path):
                    try:
                        os.remove(path)
                    except FileNotFoundError:
                        pass
        if os.path.exists(node_module.KEYS_DB_FILE):
            with open(node_module.KEYS_DB_FILE, 'r', encoding='utf-8') as fh:
                self._keys_db_backup = fh.read()
            os.remove(node_module.KEYS_DB_FILE)

    def tearDown(self):
        for path in self._created_paths:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        node_module.blockchain.transactions = []
        if os.path.exists(node_module.KEYS_DB_FILE):
            os.remove(node_module.KEYS_DB_FILE)
        if self._keys_db_backup is not None:
            with open(node_module.KEYS_DB_FILE, 'w', encoding='utf-8') as fh:
                fh.write(self._keys_db_backup)

    def test_malicious_filename_rejected_and_node_file_intact(self):
        target_file = os.path.join('blockchain_node', 'blockchain.py')
        with open(target_file, 'rb') as fh:
            before_hash = hashlib.sha256(fh.read()).hexdigest()

        data = {
            'sender': node_module.MINING_SENDER,
            'recipient': 'recipient',
            'signature': '',
            'tx_id': uuid.uuid4().hex,
            'alias': '',
            'recipient_alias': '',
            'is_sensitive': '0',
            'file_name': '../blockchain_node/blockchain.py',
            'file_path': '../blockchain_node/blockchain.py',
        }

        response = self.client.post(
            '/node/upload',
            data={**data, 'file': (BytesIO(b'evil'), 'blockchain.py')},
            content_type='multipart/form-data',
        )

        self.assertEqual(response.status_code, 400)

        with open(target_file, 'rb') as fh:
            after_hash = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(before_hash, after_hash)

    def test_canonical_path_generated_under_pending_folder(self):
        data = {
            'sender': node_module.MINING_SENDER,
            'recipient': 'recipient',
            'signature': '',
            'tx_id': uuid.uuid4().hex,
            'alias': '',
            'recipient_alias': '',
            'is_sensitive': '0',
            'file_name': 'document.txt',
            'file_path': './pending_uploads/will_be_ignored.txt',
        }

        response = self.client.post(
            '/node/upload',
            data={**data, 'file': (BytesIO(b'content'), 'document.txt')},
            content_type='multipart/form-data',
        )

        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(node_module.blockchain.transactions)
        tx = node_module.blockchain.transactions[-1]

        self.assertTrue(
            tx['file_path'].startswith('./pending_uploads/'),
            msg=f"Unexpected pending path: {tx['file_path']}"
        )
        self.assertNotEqual(
            tx['file_path'],
            './pending_uploads/will_be_ignored.txt',
            msg="Server should ignore client supplied path",
        )

        saved_abs = os.path.abspath(os.path.join('.', tx['file_path'].lstrip('./')))
        self._created_paths.append(saved_abs)
        self.assertTrue(os.path.exists(saved_abs))

    def test_invalid_signature_upload_cleans_pending_and_keys(self):
        dummy_uuid_hex = 'feedfacefeedfacefeedfacefeedface'
        expected_filename = 'document.txt'
        expected_pending_name = f"{dummy_uuid_hex}_{expected_filename}"
        expected_pending_path = os.path.abspath(
            os.path.join(node_module.PENDING_FOLDER, expected_pending_name)
        )

        data = {
            'sender': 'not-miner',
            'recipient': 'recipient',
            'signature': '',
            'tx_id': uuid.uuid4().hex,
            'alias': '',
            'recipient_alias': '',
            'is_sensitive': '1',
            'file_name': expected_filename,
            'file_path': './pending_uploads/ignored.txt',
            'enc_key_b64': 'Zm9v',
            'enc_nonce_b64': 'YmFy',
            'enc_tag_b64': 'YmF6',
        }

        dummy_uuid = type('DummyUUID', (), {'hex': dummy_uuid_hex})()

        with mock.patch.object(node_module, 'uuid4', return_value=dummy_uuid):
            response = self.client.post(
                '/node/upload',
                data={**data, 'file': (BytesIO(b'content'), expected_filename)},
                content_type='multipart/form-data',
            )

        self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(os.path.exists(expected_pending_path))
        self.assertFalse(os.path.exists(node_module.KEYS_DB_FILE))

    def test_duplicate_upload_is_idempotent(self):
        tx_id = uuid.uuid4().hex
        file_name = 'document.txt'
        first_uuid_hex = '11111111111111111111111111111111'
        second_uuid_hex = '22222222222222222222222222222222'
        first_uuid = type('DummyUUID', (), {'hex': first_uuid_hex})()
        second_uuid = type('DummyUUID', (), {'hex': second_uuid_hex})()

        data = {
            'sender': node_module.MINING_SENDER,
            'recipient': 'recipient',
            'signature': '',
            'tx_id': tx_id,
            'alias': '',
            'recipient_alias': '',
            'is_sensitive': '1',
            'file_name': file_name,
            'file_path': './pending_uploads/ignored.txt',
            'enc_key_b64': 'Zmlyc3QtY2lwaGVyLWtleQ==',
            'enc_nonce_b64': 'Zmlyc3Qtbm9uY2U=',
            'enc_tag_b64': 'Zmlyc3QtdGFn',
        }

        with mock.patch.object(node_module, 'uuid4', side_effect=[first_uuid, second_uuid]):
            response_first = self.client.post(
                '/node/upload',
                data={**data, 'file': (BytesIO(b'ciphertext-1'), file_name)},
                content_type='multipart/form-data',
            )

            self.assertEqual(response_first.status_code, 201, response_first.data)

            pending_files_after_first = set(os.listdir(node_module.PENDING_FOLDER))
            expected_pending_name = f"{first_uuid_hex}_{file_name}"
            self.assertIn(expected_pending_name, pending_files_after_first)
            first_pending_path = os.path.abspath(
                os.path.join(node_module.PENDING_FOLDER, expected_pending_name)
            )
            self._created_paths.append(first_pending_path)
            self.assertTrue(os.path.exists(first_pending_path))

            with open(node_module.KEYS_DB_FILE, 'r', encoding='utf-8') as fh:
                first_keys_state = json.load(fh)

            self.assertIn(tx_id, first_keys_state)
            self.assertEqual(
                first_keys_state[tx_id]['enc_key_b64'],
                'Zmlyc3QtY2lwaGVyLWtleQ==',
            )

            data['enc_key_b64'] = 'c2Vjb25kLWNpcGhlci1rZXk='
            data['enc_nonce_b64'] = 'c2Vjb25kLW5vbmNl'
            data['enc_tag_b64'] = 'c2Vjb25kLXRhZw=='

            response_second = self.client.post(
                '/node/upload',
                data={**data, 'file': (BytesIO(b'ciphertext-2'), file_name)},
                content_type='multipart/form-data',
            )

        self.assertEqual(response_second.status_code, 200, response_second.data)
        self.assertIn(b'File already received', response_second.data)

        after_second = set(os.listdir(node_module.PENDING_FOLDER))
        self.assertEqual(after_second, pending_files_after_first)

        with open(node_module.KEYS_DB_FILE, 'r', encoding='utf-8') as fh:
            final_keys_state = json.load(fh)

        self.assertEqual(final_keys_state, first_keys_state)


if __name__ == '__main__':
    unittest.main()
