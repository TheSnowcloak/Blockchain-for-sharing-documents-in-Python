import importlib
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path


class KeysDbConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.repo_root = Path(__file__).resolve().parents[1]
        self.orig_cwd = os.getcwd()
        self.tempdir = tempfile.TemporaryDirectory()
        os.chdir(self.tempdir.name)

        if str(self.repo_root) not in sys.path:
            sys.path.insert(0, str(self.repo_root))

        module_name = "blockchain_node.blockchain"
        if module_name in sys.modules:
            del sys.modules[module_name]
        self.module = importlib.import_module(module_name)

    def tearDown(self):
        module_name = "blockchain_node.blockchain"
        if module_name in sys.modules:
            del sys.modules[module_name]
        os.chdir(self.orig_cwd)
        self.tempdir.cleanup()

    def test_concurrent_store_operations_preserve_records(self):
        tx_one = "tx-one"
        tx_two = "tx-two"

        start_event = threading.Event()

        def worker(tx_id, suffix):
            start_event.wait(timeout=1.0)
            self.module.store_encryption_keys(
                tx_id,
                key_b64=f"key-{suffix}",
                nonce_b64=f"nonce-{suffix}",
                tag_b64=f"tag-{suffix}",
            )

        threads = [
            threading.Thread(target=worker, args=(tx_one, "a")),
            threading.Thread(target=worker, args=(tx_two, "b")),
        ]

        for thread in threads:
            thread.start()

        start_event.set()

        for thread in threads:
            thread.join(timeout=2.0)

        db = self.module.load_keys_db()
        self.assertIn(tx_one, db)
        self.assertIn(tx_two, db)

        keys_file = Path(self.module.KEYS_DB_FILE)
        self.assertTrue(keys_file.exists(), "keys_db.json was not created")
        with keys_file.open("r", encoding="utf-8") as handle:
            persisted = json.load(handle)

        self.assertEqual(set(persisted.keys()), {tx_one, tx_two})
        self.assertEqual(persisted[tx_one]["enc_key_b64"], "key-a")
        self.assertEqual(persisted[tx_two]["enc_key_b64"], "key-b")


if __name__ == "__main__":
    unittest.main()
