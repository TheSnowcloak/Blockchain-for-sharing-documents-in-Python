import hashlib
import os
import unittest
import uuid
from io import BytesIO

from blockchain_node import blockchain as node_module


class UploadSecurityTestCase(unittest.TestCase):
    def setUp(self):
        self.client = node_module.app.test_client()
        node_module.blockchain.transactions = []
        self._created_paths = []

    def tearDown(self):
        for path in self._created_paths:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        node_module.blockchain.transactions = []

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


if __name__ == '__main__':
    unittest.main()
