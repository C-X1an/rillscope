"""Real socket/CAS unit controls; synthetic manifests are never benchmark proof."""
import copy
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
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import kvm_capture_channel as pilot_channel
import kvm_reference_channel as channel
from workloads import descriptors, sort_null_descriptors

COMMIT = 'b' * 40
FILES = [['Cargo.toml', 'a' * 64]]
SOURCE = {'files': FILES, 'sha256': hashlib.sha256(json.dumps(FILES, separators=(',', ':')).encode()).hexdigest()}
SEEDS = [20261014, 20261015, 20261016, 20261017, 20261018]


def manifest(stage):
    row = {'source': copy.deepcopy(SOURCE), 'warmups': 5, 'repetitions': 30, 'seeds': SEEDS.copy()}
    if stage == 'cancel': return dict(row, schema_version=2, system='Linux')
    full = stage == 'grid'
    return dict(row, schema_version=3, commit=COMMIT, dirty=False,
        profile='full' if full else 'sort-null-supplement',
        chosen_workloads=descriptors() if full else sort_null_descriptors(),
        expected_cases=410 if full else 40, expected_observations=43050 if full else 4200)


class ReferenceChannel(unittest.TestCase):
    def setUp(self):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='kr-', dir=ROOT / '.local-runs')
        self.base = Path(self.temporary.name); self.synced = []
        self.sync = patch.object(pilot_channel, 'fsync_directory', side_effect=self.synced.append)
        self.sync.start()
        self.left, right = socket.socketpair()
        self.receiver = channel.Receiver(right, self.base / 'received', commit=COMMIT,
                                         source_sha256=SOURCE['sha256'])

    def tearDown(self):
        self.left.close(); self.receiver.close(); self.sync.stop(); self.temporary.cleanup()

    def archive(self, stage, *, changed=None):
        source = self.base / ('raw-' + str(len(list(self.base.glob('raw-*')))))
        source.mkdir(); value = manifest(stage)
        if changed is not None: value.update(changed)
        (source / 'manifest.json').write_text(json.dumps(value), encoding='utf-8')
        (source / 'original-failed-or-partial.bin').write_bytes(b'actual-unit-bytes\x00\xff')
        package = source.with_name('packed-' + source.name)
        archive_capture.pack(source, package)
        return package / 'capture.zip'

    def frame(self, archive, stage='grid', **changed):
        data = archive.read_bytes()
        row = {'schema_version': 1, 'method': 'rillscope-full-capture-v1', 'stage': stage,
            'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'commit': COMMIT,
            'source_sha256': SOURCE['sha256'], 'reference_qualified': False, **changed}
        return json.dumps(row).encode() + b'\n' + data

    def feed(self, data):
        self.left.sendall(data); self.left.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + 3
        while not self.receiver.eof:
            self.assertLess(time.monotonic(), deadline)
            self.receiver.drain()

    def test_all_three_cas_frames_bind_exact_source_and_full_method(self):
        packages = [(stage, self.archive(stage)) for stage in ('grid', 'cancel', 'sort-null')]
        errors = []; acknowledgements = []
        def sender():
            try:
                for stage, archive in packages:
                    acknowledgements.append(channel.send_archive(archive, stage, time.monotonic() + 5,
                        commit=COMMIT, source_sha256=SOURCE['sha256'], connection=self.left))
            except Exception as error: errors.append(error)
        thread = threading.Thread(target=sender); thread.start()
        deadline = time.monotonic() + 7
        while thread.is_alive() and time.monotonic() < deadline:
            self.receiver.drain(); time.sleep(.001)
        thread.join(timeout=.1)
        self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
        self.assertEqual([row['stage'] for row in acknowledgements], ['grid', 'cancel', 'sort-null'])
        self.assertEqual(self.receiver.completion()['missing_stages'], [])
        self.assertEqual(self.receiver.completion()['status'], 'VERIFIED HOST BYTES')
        for stage, original in packages:
            target = self.base / 'received' / stage
            self.assertEqual((target / 'capture.zip').read_bytes(), original.read_bytes())
            self.assertIn(target, self.synced)
        self.assertTrue(all(row['reference_qualified'] is False for row in self.receiver.records))

    def test_pilot_other_source_unknown_fields_and_boolean_lengths_reject_before_open(self):
        archive = self.archive('grid'); row = json.loads(self.frame(archive).split(b'\n', 1)[0])
        for changes in ({'method': 'unqualified-kvm-feasibility-pilot'}, {'stage': 'instrument'},
                        {'commit': 'c' * 40}, {'source_sha256': 'd' * 64}, {'bytes': True},
                        {'bytes': archive_capture.MAX_ARCHIVE + 1}, {'reference_qualified': True}, {'other': 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                channel.header(dict(row, **changes), commit=COMMIT, source_sha256=SOURCE['sha256'])
        self.assertEqual(list((self.base / 'received').iterdir()), [])

    def test_reduced_or_changed_declared_full_scope_never_gets_ack(self):
        archive = self.archive('grid', changed={'expected_cases': 6, 'expected_observations': 630,
                                                'profile': 'instrumentation-pilot'})
        with self.assertRaisesRegex(ValueError, 'scope'): self.feed(self.frame(archive))
        self.assertEqual(self.receiver.records, []); self.assertEqual(self.receiver.pending_ack, b'')
        self.assertEqual((self.base / 'received/grid/capture.zip.pending').read_bytes(), archive.read_bytes())

    def test_changed_source_map_fails_even_with_a_matching_claimed_hash(self):
        archive = self.archive('grid', changed={'source': {'sha256': SOURCE['sha256'], 'files': [['Cargo.toml', 'f' * 64]]}})
        with self.assertRaisesRegex(ValueError, 'source'): self.feed(self.frame(archive))
        self.assertEqual(self.receiver.records, [])

    def test_available_later_failure_bytes_are_retained_without_hiding_missing_stages(self):
        archive = self.archive('sort-null'); self.feed(self.frame(archive, 'sort-null'))
        report = self.receiver.completion()
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertEqual(report['missing_stages'], ['grid', 'cancel'])
        self.assertFalse(report['reference_qualified'])
        self.assertEqual((self.base / 'received/sort-null/capture.zip').read_bytes(), archive.read_bytes())

    def test_duplicate_or_backward_stage_cannot_replace_original_bytes(self):
        archive = self.archive('grid')
        with self.assertRaisesRegex(ValueError, 'order'): self.feed(self.frame(archive) * 2)
        self.assertEqual((self.base / 'received/grid/capture.zip').read_bytes(), archive.read_bytes())
        self.assertEqual(len(self.receiver.records), 1)

    def test_all_record_validation_is_not_inferred_from_declared_scope_or_byte_ack(self):
        archive = self.archive('grid'); self.feed(self.frame(archive))
        # The unit CAS deliberately has no observations/results. Bytes remain useful;
        # exact scope declarations cannot turn those missing records into qualification.
        self.assertEqual(self.receiver.completion()['all_record_validation'], 'NOT RUN')
        self.assertFalse(self.receiver.completion()['reference_qualified'])

    def test_duplicate_json_header_field_rejects_before_creating_a_stage(self):
        archive = self.archive('grid'); frame = self.frame(archive)
        duplicated = b'{"schema_version":1,' + frame[1:]
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.feed(duplicated)
        self.assertEqual(list((self.base / 'received').iterdir()), [])

    def test_missing_original_experiment_manifest_preserves_pending_bytes_without_ack(self):
        source = self.base / 'raw-missing'; source.mkdir()
        (source / 'failure.bin').write_bytes(b'original partial output before manifest')
        archive_capture.pack(source, self.base / 'packed-missing')
        archive = self.base / 'packed-missing/capture.zip'
        with self.assertRaisesRegex(ValueError, 'manifest'): self.feed(self.frame(archive))
        self.assertEqual(self.receiver.records, []); self.assertEqual(self.receiver.pending_ack, b'')
        self.assertEqual((self.base / 'received/grid/capture.zip.pending').read_bytes(), archive.read_bytes())


if __name__ == '__main__': unittest.main()
