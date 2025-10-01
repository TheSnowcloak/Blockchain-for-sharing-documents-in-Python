import importlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path


class UploadConsensusHammerTest(unittest.TestCase):
    """Exercise concurrent uploads and consensus resolution."""

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
        self.Blockchain = self.module.Blockchain

    def tearDown(self):
        module_name = "blockchain_node.blockchain"
        if module_name in sys.modules:
            del sys.modules[module_name]
        os.chdir(self.orig_cwd)
        self.tempdir.cleanup()

    def test_concurrent_transactions_and_consensus(self):
        blockchain = self.Blockchain()

        uploads_per_thread = 23
        upload_threads = 3
        consensus_iterations = 200
        total_expected = uploads_per_thread * upload_threads

        def upload_worker(prefix: str):
            for index in range(uploads_per_thread):
                tx_id = f"{prefix}-{index}-{uuid.uuid4().hex}"
                blockchain.add_transaction(
                    tx_id=tx_id,
                    sender=self.module.MINING_SENDER,
                    recipient=f"recipient-{prefix}",
                    file_name=f"file-{prefix}-{index}.dat",
                    file_path=f"./pending_uploads/{prefix}-{index}.dat",
                    alias=f"alias-{prefix}",
                    recipient_alias=f"recipient-alias-{prefix}",
                    signature="",
                    is_sensitive="0",
                )

        def consensus_worker():
            for _ in range(consensus_iterations):
                blockchain.resolve_conflicts()
                time.sleep(0.001)

        threads = [
            threading.Thread(target=upload_worker, args=(f"u{i}",))
            for i in range(upload_threads)
        ]
        consensus_thread = threading.Thread(target=consensus_worker)

        consensus_thread.start()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        consensus_thread.join()

        with blockchain.lock:
            chain_ids = [
                tx["tx_id"]
                for block in blockchain.chain
                for tx in block["transactions"]
            ]
            pending_ids = [tx["tx_id"] for tx in blockchain.transactions]

        all_ids = chain_ids + pending_ids
        self.assertEqual(len(all_ids), len(set(all_ids)))
        self.assertEqual(len(all_ids), total_expected)

        with blockchain.lock:
            blockchain.save_data()

        data_file = Path(self.module.DATA_FILE)
        self.assertTrue(data_file.exists())
        with data_file.open("r", encoding="utf-8") as handle:
            persisted = json.load(handle)

        persisted_chain_ids = [
            tx["tx_id"]
            for block in persisted.get("chain", [])
            for tx in block.get("transactions", [])
        ]
        persisted_pending_ids = [
            tx["tx_id"] for tx in persisted.get("transactions", [])
        ]
        self.assertEqual(
            sorted(all_ids),
            sorted(persisted_chain_ids + persisted_pending_ids),
        )
        self.assertEqual(
            len(persisted_chain_ids) + len(persisted_pending_ids),
            total_expected,
        )


if __name__ == "__main__":
    unittest.main()
