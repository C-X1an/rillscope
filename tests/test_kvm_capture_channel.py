"""Real socket/CAS framing controls, without QEMU, root or product timing."""
import hashlib
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import archive_capture
import kvm_capture_channel as channel


class CaptureChannel(unittest.TestCase):
    def setUp(self):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='kc-', dir=ROOT / '.local-runs')
        self.base = Path(self.temporary.name)
        self.synced = []
        self.sync_patch = patch.object(channel, 'fsync_directory', create=True, side_effect=self.synced.append)
        self.sync_patch.start()
        source = self.base / 'raw'; source.mkdir()
        (source / 'original.bin').write_bytes(b'original retained bytes\0\xff')
        archive_capture.pack(source, self.base / 'packed')
        self.archive = self.base / 'packed/capture.zip'; self.data = self.archive.read_bytes()
        self.left, right = socket.socketpair()
        self.receiver = channel.Receiver(right, self.base / 'received')

    def tearDown(self):
        self.left.close(); self.receiver.close(); self.sync_patch.stop(); self.temporary.cleanup()

    def frame(self, data=None, **changed):
        data = self.data if data is None else data
        row = {'schema_version': 1, 'stage': 'instrument', 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'reference_qualified': False, **changed}
        return json.dumps(row).encode() + b'\n' + data

    def feed(self, data):
        self.left.sendall(data); self.left.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + 3
        while not self.receiver.eof:
            self.assertLess(time.monotonic(), deadline, 'receiver must finish or reject bounded input')
            self.receiver.drain()

    def test_all_three_real_archives_are_verified_before_acknowledgement(self):
        failures = []; acknowledgements = []
        def sender():
            try:
                for stage, _, _ in channel.STAGES:
                    acknowledgements.append(channel.send_archive(self.archive, stage,
                        time.monotonic() + 5, connection=self.left))
            except Exception as error: failures.append(error)
        thread = threading.Thread(target=sender); thread.start()
        deadline = time.monotonic() + 6
        while thread.is_alive() and time.monotonic() < deadline:
            self.receiver.drain(); time.sleep(.001)
        thread.join(timeout=.1)
        self.assertFalse(thread.is_alive()); self.assertEqual(failures, [])
        self.assertEqual([row['stage'] for row in acknowledgements], ['instrument', 'tail', 'cancel'])
        self.assertEqual(len(self.receiver.records), 3)
        for stage, _, _ in channel.STAGES:
            saved = self.base / 'received' / stage
            self.assertEqual((saved / 'capture.zip').read_bytes(), self.data)
            self.assertFalse((saved / 'capture.zip.pending').exists())
            restored = self.base / ('restored-' + stage)
            archive_capture.restore(saved / 'capture.zip', restored)
            self.assertEqual((restored / 'original.bin').read_bytes(), b'original retained bytes\0\xff')
            self.assertIn(saved, self.synced, 'directory entries must be synced before acknowledgement')
        self.assertIn(self.base / 'received', self.synced)

    def test_wrong_order_and_boolean_size_reject_before_opening_a_file(self):
        for changes in ({'stage': 'tail'}, {'bytes': True}, {'bytes': channel.archive_capture.MAX_ARCHIVE + 1},
                        {'unexpected': 'field'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                row = json.loads(self.frame(**changes).split(b'\n', 1)[0])
                channel.header(row, 'instrument')
        self.assertEqual(list((self.base / 'received').iterdir()), [])

    def test_corrupt_outer_hash_never_commits_or_acknowledges(self):
        with self.assertRaisesRegex(ValueError, 'digest'): self.feed(self.frame(sha256='0' * 64))
        self.assertEqual(self.receiver.records, [])
        self.assertTrue((self.base / 'received/instrument/capture.zip.pending').is_file())
        self.assertFalse((self.base / 'received/instrument/capture.zip').exists())

    def test_matching_outer_hash_does_not_replace_full_cas_inspection(self):
        with self.assertRaises((ValueError, archive_capture.zipfile.BadZipFile)):
            self.feed(self.frame(data=b'this is not a CAS archive'))
        self.assertEqual(self.receiver.records, [])
        self.assertFalse((self.base / 'received/instrument/capture.zip').exists())

    def test_truncated_capture_keeps_original_partial_bytes_without_ack(self):
        with self.assertRaisesRegex(ValueError, 'during a frame'): self.feed(self.frame()[:-7])
        self.receiver.close()
        self.assertEqual((self.base / 'received/instrument/capture.zip.pending').read_bytes(), self.data[:-7])
        self.assertEqual(self.receiver.records, [])

    def test_repeated_stage_cannot_clobber_acknowledged_bytes(self):
        with self.assertRaisesRegex(ValueError, 'order'): self.feed(self.frame() + self.frame())
        self.assertEqual((self.base / 'received/instrument/capture.zip').read_bytes(), self.data)
        self.assertEqual(len(self.receiver.records), 1)

    def test_header_growth_is_bounded(self):
        with self.assertRaisesRegex(ValueError, 'header exceeds'): self.feed(b'x' * (channel.HEADER_LIMIT + 1))
        self.assertEqual(list((self.base / 'received').iterdir()), [])

    def test_sender_cannot_succeed_without_live_ack_within_deadline(self):
        with self.assertRaisesRegex(ValueError, 'deadline'):
            channel.send_archive(self.archive, 'instrument', time.monotonic() - 1, connection=self.left)

    def test_directory_sync_failure_keeps_bytes_and_prevents_ack(self):
        def sync(path):
            if path == self.base / 'received/instrument': raise OSError('deliberate directory fsync failure')
        with patch.object(channel, 'fsync_directory', side_effect=sync), self.assertRaisesRegex(OSError, 'fsync'):
            self.feed(self.frame())
        self.assertEqual((self.base / 'received/instrument/capture.zip').read_bytes(), self.data)
        self.assertEqual(self.receiver.records, [])
        self.assertEqual(self.receiver.pending_ack, b'')

    def test_missing_output_parent_rejects_without_creating_ancestors(self):
        left, right = socket.socketpair()
        try:
            with self.assertRaisesRegex(ValueError, 'existing output parent'):
                channel.Receiver(right, self.base / 'new-parent/received')
            self.assertFalse((self.base / 'new-parent').exists())
        finally: left.close(); right.close()


if __name__ == '__main__': unittest.main()
