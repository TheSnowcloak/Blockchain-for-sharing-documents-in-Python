import base64
import copy
import hashlib
import json
import os
import unittest
from unittest import mock
import uuid
from io import BytesIO

from blockchain_node import blockchain as node_module

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class UploadSecurityTestCase(unittest.TestCase):
    def setUp(self):
        self.client = node_module.app.test_client()
        node_module.blockchain.transactions = []
        self._original_validator_netloc = node_module.blockchain.validator_netloc
        self._original_local_netlocs = node_module.app.config.get('LOCAL_NODE_NETLOCS')
        self._original_env_local_netlocs = os.environ.get('LOCAL_NODE_NETLOCS')
        node_module.app.config['LOCAL_NODE_NETLOCS'] = 'localhost:5000'
        os.environ['LOCAL_NODE_NETLOCS'] = 'localhost:5000'
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
        node_module.blockchain.validator_netloc = self._original_validator_netloc
        if self._original_local_netlocs is None:
            node_module.app.config.pop('LOCAL_NODE_NETLOCS', None)
        else:
            node_module.app.config['LOCAL_NODE_NETLOCS'] = self._original_local_netlocs
        if self._original_env_local_netlocs is None:
            os.environ.pop('LOCAL_NODE_NETLOCS', None)
        else:
            os.environ['LOCAL_NODE_NETLOCS'] = self._original_env_local_netlocs
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

    def test_host_header_validation_and_file_owner_defaults(self):
        node_module.blockchain.validator_netloc = 'validator.local:6001'

        base_data = {
            'sender': node_module.MINING_SENDER,
            'recipient': 'recipient',
            'signature': '',
            'alias': '',
            'recipient_alias': '',
            'is_sensitive': '0',
            'file_name': 'document.txt',
            'file_path': './pending_uploads/ignored.txt',
        }

        spoof_response = self.client.post(
            '/node/upload',
            data={**base_data, 'tx_id': uuid.uuid4().hex, 'file': (BytesIO(b'data'), 'document.txt')},
            content_type='multipart/form-data',
            base_url='http://peer-b:5000',
            environ_overrides={'REMOTE_ADDR': '127.0.0.1'},
        )

        self.assertEqual(spoof_response.status_code, 400, spoof_response.data)
        self.assertIn('Host header', spoof_response.get_json()['error'])
        self.assertFalse(node_module.blockchain.transactions)

        valid_tx_id = uuid.uuid4().hex
        valid_response = self.client.post(
            '/node/upload',
            data={**base_data, 'tx_id': valid_tx_id, 'file': (BytesIO(b'legit'), 'document.txt')},
            content_type='multipart/form-data',
            base_url='http://validator.local:6001',
            environ_overrides={'REMOTE_ADDR': '127.0.0.1'},
        )

        self.assertEqual(valid_response.status_code, 201, valid_response.data)
        self.assertTrue(node_module.blockchain.transactions)
        tx = node_module.blockchain.transactions[-1]
        self.assertEqual(tx['file_owner'], 'validator.local:6001')

        pending_abs = os.path.abspath(os.path.join('.', tx['file_path'].lstrip('./')))
        if os.path.exists(pending_abs):
            self._created_paths.append(pending_abs)

    def test_host_header_matching_client_ip_requires_configuration(self):
        client_ip = '198.51.100.25'

        original_config_present = 'LOCAL_NODE_NETLOCS' in node_module.app.config
        original_config_value = node_module.app.config.get('LOCAL_NODE_NETLOCS')

        def restore_config():
            if original_config_present:
                node_module.app.config['LOCAL_NODE_NETLOCS'] = original_config_value
            else:
                node_module.app.config.pop('LOCAL_NODE_NETLOCS', None)

        self.addCleanup(restore_config)
        node_module.app.config.pop('LOCAL_NODE_NETLOCS', None)

        original_env_value = os.environ.pop('LOCAL_NODE_NETLOCS', None)

        def restore_env():
            if original_env_value is None:
                os.environ.pop('LOCAL_NODE_NETLOCS', None)
            else:
                os.environ['LOCAL_NODE_NETLOCS'] = original_env_value

        self.addCleanup(restore_env)

        node_module.blockchain.validator_netloc = ''

        base_data = {
            'sender': node_module.MINING_SENDER,
            'recipient': 'recipient',
            'signature': '',
            'alias': '',
            'recipient_alias': '',
            'is_sensitive': '0',
            'file_name': 'document.txt',
            'file_path': './pending_uploads/ignored.txt',
        }

        initial_tx_id = uuid.uuid4().hex

        response = self.client.post(
            '/node/upload',
            data={**base_data, 'tx_id': initial_tx_id, 'file': (BytesIO(b'data'), 'document.txt')},
            content_type='multipart/form-data',
            base_url=f'http://{client_ip}:5000',
            environ_overrides={'REMOTE_ADDR': client_ip},
        )

        self.assertEqual(response.status_code, 400, response.data)
        payload = response.get_json()
        self.assertIsNotNone(payload)
        self.assertIn('LOCAL_NODE_NETLOCS must be configured', payload.get('error', ''))
        self.assertFalse(node_module.blockchain.transactions)

        for name in os.listdir(node_module.PENDING_FOLDER):
            path = os.path.join(node_module.PENDING_FOLDER, name)
            if os.path.isfile(path):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass

        node_module.app.config['LOCAL_NODE_NETLOCS'] = f'{client_ip}:5000'
        os.environ['LOCAL_NODE_NETLOCS'] = f'{client_ip}:5000'

        allowed_tx_id = uuid.uuid4().hex
        response_allowed = self.client.post(
            '/node/upload',
            data={**base_data, 'tx_id': allowed_tx_id, 'file': (BytesIO(b'pass'), 'document.txt')},
            content_type='multipart/form-data',
            base_url=f'http://{client_ip}:5000',
            environ_overrides={'REMOTE_ADDR': client_ip},
        )

        self.assertEqual(response_allowed.status_code, 201, response_allowed.data)
        self.assertTrue(node_module.blockchain.transactions)
        tx = node_module.blockchain.transactions[-1]
        self.assertEqual(tx['file_owner'], f'{client_ip}:5000')

        pending_abs = os.path.abspath(os.path.join('.', tx['file_path'].lstrip('./')))
        if os.path.exists(pending_abs):
            self._created_paths.append(pending_abs)

    def test_invalid_file_owner_does_not_break_sync(self):
        tx_id = uuid.uuid4().hex
        invalid_owner = 'http://example.com:badport'
        payload = {
            'tx_id': tx_id,
            'sender': node_module.MINING_SENDER,
            'recipient': 'recipient',
            'file_name': 'document.txt',
            'file_path': './uploads/nonexistent.txt',
            'signature': '',
            'file_owner': invalid_owner,
        }

        response = self.client.post('/transactions/new', json=payload)
        self.assertEqual(response.status_code, 201, response.data)

        stored_tx = node_module.blockchain.get_transaction_by_id(tx_id)
        self.assertIsNotNone(stored_tx)
        self.assertNotEqual(stored_tx.get('file_owner'), invalid_owner)
        self.assertNotIn('file_owner', stored_tx)

        original_nodes = set(node_module.blockchain.nodes)
        original_trusted = set(node_module.blockchain.trusted_nodes)

        def restore_network():
            node_module.blockchain.nodes = set(original_nodes)
            node_module.blockchain.trusted_nodes = set(original_trusted)

        self.addCleanup(restore_network)

        node_module.blockchain.nodes = {'peer-a:5000'}
        node_module.blockchain.trusted_nodes = set()

        remote_tx = dict(stored_tx)
        remote_tx['file_owner'] = invalid_owner
        block_payload = [{'transactions': [remote_tx]}]

        with mock.patch.object(node_module.blockchain, '_fetch_chain_with_retry', return_value=block_payload) as mock_fetch, \
            mock.patch.object(node_module.blockchain, '_download_file_with_retry', return_value=False) as mock_download, \
            mock.patch.object(node_module.blockchain, '_schedule_deferred_retry') as mock_schedule, \
            mock.patch.object(node_module.blockchain, '_clear_deferred_retry') as mock_clear:

            node_module.blockchain.sync_files()

        mock_fetch.assert_called_once_with('peer-a:5000')
        self.assertEqual(mock_download.call_count, 1)
        mock_schedule.assert_called_once()
        scheduled_args = mock_schedule.call_args.args
        scheduled_kwargs = mock_schedule.call_args.kwargs
        self.assertEqual(scheduled_args[0], 'peer-a:5000')
        self.assertEqual(scheduled_kwargs.get('attempt'), 1)
        mock_clear.assert_not_called()

    def test_malformed_encryption_payload_rejected_and_decrypt_succeeds_for_valid_upload(self):
        malformed_tx_id = uuid.uuid4().hex
        invalid_payload = {
            'sender': node_module.MINING_SENDER,
            'recipient': 'recipient',
            'signature': '',
            'tx_id': malformed_tx_id,
            'alias': '',
            'recipient_alias': '',
            'is_sensitive': '1',
            'file_name': 'secret.txt',
            'file_path': './pending_uploads/ignored.txt',
            'enc_key_b64': '***not-base64***',
            'enc_nonce_b64': 'also_bad',
            'enc_tag_b64': '!!!',
        }

        malformed_response = self.client.post(
            '/node/upload',
            data={**invalid_payload, 'file': (BytesIO(b'cipher'), 'secret.txt')},
            content_type='multipart/form-data',
        )

        self.assertEqual(malformed_response.status_code, 400, malformed_response.data)
        self.assertFalse(os.path.exists(node_module.KEYS_DB_FILE))
        self.assertFalse(node_module.blockchain.transactions)

        plaintext = b'secret document payload'
        aes_key = get_random_bytes(32)
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        nonce = cipher.nonce

        valid_tx_id = uuid.uuid4().hex
        valid_file_name = 'valid.bin'
        valid_payload = {
            'sender': node_module.MINING_SENDER,
            'recipient': 'recipient',
            'signature': '',
            'tx_id': valid_tx_id,
            'alias': '',
            'recipient_alias': '',
            'is_sensitive': '1',
            'file_name': valid_file_name,
            'file_path': './pending_uploads/ignored.txt',
            'enc_key_b64': base64.b64encode(aes_key).decode('ascii'),
            'enc_nonce_b64': base64.b64encode(nonce).decode('ascii'),
            'enc_tag_b64': base64.b64encode(tag).decode('ascii'),
        }

        valid_response = self.client.post(
            '/node/upload',
            data={**valid_payload, 'file': (BytesIO(ciphertext), valid_file_name)},
            content_type='multipart/form-data',
        )

        self.assertEqual(valid_response.status_code, 201, valid_response.data)

        original_chain = copy.deepcopy(node_module.blockchain.chain)
        try:
            previous_hash = node_module.blockchain.hash(node_module.blockchain.last_block)
            node_module.blockchain.create_block(
                proof=777,
                previous_hash=previous_hash,
                system_override=True,
            )

            tx_record = None
            for block in node_module.blockchain.chain:
                for tx in block.get('transactions', []):
                    if tx.get('tx_id') == valid_tx_id:
                        tx_record = tx
                        break
                if tx_record:
                    break

            self.assertIsNotNone(tx_record, 'Expected transaction in blockchain after mining')

            stored_name = tx_record.get('stored_file_name') or tx_record.get('file_name')
            upload_path = os.path.abspath(os.path.join(node_module.UPLOAD_FOLDER, stored_name))
            if os.path.exists(upload_path):
                self._created_paths.append(upload_path)

            decrypt_response = self.client.get(f'/decrypt/{valid_tx_id}')
            self.assertEqual(decrypt_response.status_code, 200, decrypt_response.data)
            self.assertEqual(decrypt_response.data, plaintext)
        finally:
            node_module.blockchain.chain = original_chain
            node_module.blockchain.transactions = []


if __name__ == '__main__':
    unittest.main()
