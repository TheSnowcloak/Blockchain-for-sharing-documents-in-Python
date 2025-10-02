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

    def test_consensus_allows_other_threads_to_acquire_lock(self):
        blockchain = self.Blockchain()
        blockchain.add_node("127.0.0.1:5000")

        fetch_started = threading.Event()
        release_fetch = threading.Event()
        other_thread_acquired = threading.Event()
        original_fetch = blockchain._fetch_chain_with_retry

        def slow_fetch(netloc):
            fetch_started.set()
            release_fetch.wait(timeout=1.0)
            return []

        blockchain._fetch_chain_with_retry = slow_fetch

        try:
            consensus_thread = threading.Thread(target=blockchain.resolve_conflicts)
            consensus_thread.start()

            self.assertTrue(fetch_started.wait(timeout=1.0), "Consensus did not reach fetch stage")

            def competitor():
                if blockchain.lock.acquire(timeout=0.5):
                    other_thread_acquired.set()
                    blockchain.lock.release()

            competitor_thread = threading.Thread(target=competitor)
            competitor_thread.start()
            competitor_thread.join()

            release_fetch.set()
            consensus_thread.join(timeout=2.0)
            self.assertFalse(consensus_thread.is_alive(), "Consensus thread did not finish")
        finally:
            blockchain._fetch_chain_with_retry = original_fetch

        self.assertTrue(
            other_thread_acquired.is_set(),
            "Another thread could not obtain the blockchain lock during consensus",
        )


if __name__ == "__main__":
    unittest.main()
