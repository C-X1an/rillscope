"""Small original-byte fixtures only; no allocation/VM/canonical execution."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import retain_canonical_reference as retain


def encode(value): return (json.dumps(value, indent=2) + '\n').encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def put(path, raw): path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)


def fixture(root, failed=False, channel=True):
    source, owner, out = root / '.local-runs/attempt', root / '.local-runs/enclosing', root / '.local-runs/bundle.zip'
    plan = b'{"fixture":"literal plan; no collector executed"}\n'
    put(root / '.local-runs/plan.json', plan); put(source / 'declared-plan.json', plan)
    slot = '.local-runs/canonical-reservations/vm-201-123'
    driver = {'status': 'FAIL' if failed else 'COLLECTED CANONICAL ATTEMPT',
        'vm': {'channel': {'reservation_slot': slot} if channel else None}, 'fixture': True}
    put(source / 'driver-result.json', encode(driver)); put(source / 'vm/preparation/seed.json', b'{"fixture":true}\n')
    put(source / 'vm/artifact/serial.txt', b'Literal failed/success-shaped bytes; never actual boot\n')
    repeated = b'SYNTHETIC OPAQUE INNER CAPTURE BYTES; no archive or query\n' * 10
    put(source / 'vm/artifact/channel/packages/grid/capture.zip', repeated)
    put(source / 'vm/artifact/recovery/owner/retained/capture-0/capture.zip', repeated)
    put(source / 'vm/work.raw', b'WORK DISK MUST NOT BE SELECTED')
    put(source / 'vm/disk.qcow2', b'ROOT DISK MUST NOT BE SELECTED')
    put(source / 'native-home/.cargo/cache', b'TOOL CACHE MUST NOT BE SELECTED')
    put(root / slot / 'positive-reservation.json', b'{"fixture":"not a genuine grant"}\n')
    put(root / slot / 'grant.json.raw', b'literal non-grant bytes\n')
    stdout, stderr = b'Literal original owner stdout\n', b'Literal original owner error\n' if failed else b''
    put(owner / 'stdout.txt', stdout); put(owner / 'stderr.txt', stderr)
    proof = {'schema_version': 1, 'command': [sys.executable, 'scripts/run_canonical_reference.py',
        '--config', '.local-runs/plan.json', '--out', '.local-runs/attempt', '--run-as', 'runner'],
        'cwd': str(root), 'exit_code': 124 if failed else 0, 'verification_status': 'FAIL' if failed else 'PASS',
        'execution_outcome': 'TIMEOUT' if failed else 'EXECUTED',
        'source_before': {'sha256': 'a' * 64, 'files': []}, 'source_after_sha256': 'a' * 64,
        'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0},
        'stdout': {'file': 'stdout.txt', 'sha256': sha(stdout)}, 'stderr': {'file': 'stderr.txt', 'sha256': sha(stderr)},
        'fixture': 'SYNTHETIC BYTE-CUSTODY RECORD; no terminal process or source authentication'}
    put(owner / 'receipt.json', encode(proof))
    return source, owner / 'receipt.json', out


class CanonicalByteRetention(unittest.TestCase):
    def execute(self, root, source, owner, out, **kwargs):
        # Only the real guest/controller guard and unsupported Windows directory
        # fsync are adapted. File descriptor/hash/ZIP operations run for real.
        with patch.object(retain, 'ROOT', root), patch.object(archive_capture, 'ROOT', root), \
            patch.object(retain, 'actual_controller'), patch.object(retain, 'fsync_directory'):
            return retain.retain(source, owner, out, kwargs.get('seconds', 60))

    def test_original_bytes_include_external_reservation_and_deduplicate_captures(self):
        with tempfile.TemporaryDirectory(prefix='rill-canonical-unit-') as name:
            root = Path(name).resolve(); source, owner, out = fixture(root)
            result = self.execute(root, source, owner, out)
            self.assertEqual(result['status'], 'RETAINED AVAILABLE ORIGINAL BYTES')
            self.assertLess(result['objects'], result['files'])
            self.assertIs(result['reference_qualified'], False)
            with zipfile.ZipFile(out) as bundle:
                manifest = json.loads(bundle.read('manifest.json')); files = {row['path']: row for row in manifest['files']}
                self.assertIn('reservation/grant.json.raw', files)
                self.assertIn('owner/receipt.json', files)
                self.assertNotIn('attempt/vm/work.raw', files)
                self.assertFalse(any('/.cargo/' in name or name.endswith('disk.qcow2') for name in files))
                for path, row in files.items():
                    content = bundle.read('objects/' + row['sha256'])
                    self.assertEqual((len(content), sha(content)), (row['bytes'], row['sha256']))
                a = files['attempt/vm/artifact/channel/packages/grid/capture.zip']
                b = files['attempt/vm/artifact/recovery/owner/retained/capture-0/capture.zip']
                self.assertEqual(a['sha256'], b['sha256'])
                self.assertEqual(bundle.namelist().count('objects/' + a['sha256']), 1)

    def test_failed_prefix_without_channel_is_kept_as_failed_and_missing_reservation(self):
        with tempfile.TemporaryDirectory(prefix='rill-canonical-unit-') as name:
            root = Path(name).resolve(); source, owner, out = fixture(root, failed=True, channel=False)
            result = self.execute(root, source, owner, out)
            self.assertEqual(result['owner_exit_code'], 124)
            self.assertEqual(result['owner_verification_status'], 'FAIL')
            self.assertIn('reservation', result['missing_selected_paths'])
            self.assertEqual(result['all_record_validation'], 'NOT RUN')

    def test_changed_owner_stream_or_unfinished_cleanup_cannot_start_bundle(self):
        for change in ('stream', 'cleanup'):
            with self.subTest(change=change), tempfile.TemporaryDirectory(prefix='rill-canonical-unit-') as name:
                root = Path(name).resolve(); source, owner, out = fixture(root)
                if change == 'stream': (owner.parent / 'stdout.txt').write_bytes(b'changed\n')
                else:
                    row = json.loads(owner.read_bytes()); row['process_cleanup']['remaining_active_processes'] = False
                    owner.write_bytes(encode(row))
                with self.assertRaises(ValueError): self.execute(root, source, owner, out)
                self.assertFalse(out.exists())

    def test_existing_output_or_compressed_cap_failure_stays_explicit(self):
        with tempfile.TemporaryDirectory(prefix='rill-canonical-unit-') as name:
            root = Path(name).resolve(); source, owner, out = fixture(root)
            with patch.object(retain, 'MAX_ARCHIVE', 1):
                with self.assertRaises(ValueError): self.execute(root, source, owner, out)
            self.assertFalse(out.exists())
            self.assertTrue(out.with_name(out.name + '.pending').exists())
            self.assertNotEqual(json.loads(out.with_suffix('.json').read_bytes())['status'], 'RETAINED AVAILABLE ORIGINAL BYTES')

    def test_source_and_archive_paths_cannot_overlap(self):
        with tempfile.TemporaryDirectory(prefix='rill-canonical-unit-') as name:
            root = Path(name).resolve(); source, owner, out = fixture(root)
            with self.assertRaises(ValueError): self.execute(root, source, owner, source / 'bundle.zip')

    def test_real_unavailable_controller_fails_before_reading_metadata(self):
        with patch.object(retain, 'actual_controller', side_effect=ValueError('BLOCKED: actual scoped controller')), \
            patch.object(retain, 'read_bounded_file') as read:
            self.assertEqual(retain.main(['--source', 'unused', '--owner-receipt', 'unused', '--out', 'unused', '--budget-seconds', '30']), 77)
            read.assert_not_called()

    def test_later_owner_or_driver_snapshot_cannot_replace_the_already_read_original(self):
        for changed in ('owner', 'driver'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(prefix='rill-canonical-unit-') as name:
                root = Path(name).resolve(); source, owner, out = fixture(root)
                original = retain.read_bounded_file; injected = []
                def read(path, *args, **kwargs):
                    content = original(path, *args, **kwargs)
                    if Path(path) == source / 'driver-result.json' and not injected:
                        injected.append(changed)
                        target = owner if changed == 'owner' else source / 'driver-result.json'
                        value = json.loads(target.read_bytes()); value['fixture_revision'] = 'changed after original read'
                        target.write_bytes(encode(value))
                    return content
                with patch.object(retain, 'read_bounded_file', side_effect=read):
                    with self.assertRaisesRegex(ValueError, 'snapshot differs'): self.execute(root, source, owner, out)
                self.assertEqual(injected, [changed])
                self.assertFalse(out.exists())

    def test_final_result_persistence_cannot_renew_original_retention_cutoff(self):
        with tempfile.TemporaryDirectory(prefix='rill-canonical-unit-') as name:
            root = Path(name).resolve(); source, owner, out = fixture(root); clock = [100.0]
            original = retain.write_json
            def write(path, value):
                original(path, value)
                if value.get('status') == 'RETAINED AVAILABLE ORIGINAL BYTES': clock[0] = 131.0
            with patch.object(retain.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(retain, 'write_json', side_effect=write):
                with self.assertRaisesRegex(ValueError, 'terminal persistence'):
                    self.execute(root, source, owner, out, seconds=30)
            self.assertTrue(out.exists(), 'verified original bytes must remain after terminal metadata overrun')
            self.assertEqual(json.loads(out.with_suffix('.json').read_bytes())['status'], 'FAIL')

    def test_archive_destination_must_not_alias_its_result_json_sidecar(self):
        with tempfile.TemporaryDirectory(prefix='rill-canonical-unit-') as name:
            root = Path(name).resolve(); source, owner, out = fixture(root); out = out.with_suffix('.json')
            with self.assertRaises(ValueError): self.execute(root, source, owner, out)
            self.assertFalse(out.exists())
            self.assertFalse(out.with_name(out.name + '.pending').exists())

    def test_directory_enumeration_is_bounded_before_sorting_all_entries(self):
        with tempfile.TemporaryDirectory(prefix='rill-canonical-unit-') as name:
            root = Path(name).resolve(); source, owner, out = fixture(root); watched = source / 'vm/artifact'
            for number in range(100): (watched / ('extra-' + str(number))).write_bytes(b'fixture\n')
            iterdir = Path.iterdir; consumed = []
            def counted(path):
                for child in iterdir(path):
                    if path == watched: consumed.append(child.name)
                    yield child
            with patch.object(retain, 'MAX_FILES', 10), patch.object(Path, 'iterdir', counted):
                with self.assertRaises(ValueError): self.execute(root, source, owner, out)
            self.assertLessEqual(len(consumed), 21)
            self.assertFalse(out.exists())


if __name__ == '__main__': unittest.main()
