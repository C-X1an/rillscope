"""Actual bounded archive bytes from synthetic failed-owner fixtures only."""
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
import retain_canonical_diagnostic as retention
from evidence import source_identity


class DiagnosticRetentionControls(unittest.TestCase):
    def fixture(self, base, cleanup=0, stdout_file='stdout.txt'):
        source = base / 's'; source.mkdir(); owner = base / 'o'; owner.mkdir()
        (source / 'diagnostic-result.json').write_bytes(b'{"status":"FAIL","fixture":true}\n')
        (source / 'vm').mkdir(); (source / 'vm/work.raw').write_bytes(b'NOT A REAL DISK; excluded fixture')
        (source / 'vm/rustup-init').write_bytes(b'NOT AN INSTALLER; excluded fixture')
        (owner / 'stdout.txt').write_bytes(b'synthetic failed-owner output\n'); (owner / 'stderr.txt').write_bytes(b'')
        identity = source_identity(ROOT)['sha256']
        row = {'command': ['python3', 'scripts/canonical_reference_diagnostic.py', '--out',
            source.relative_to(ROOT).as_posix(), '--run-as', 'runner'], 'cwd': str(ROOT),
            'exit_code': 1, 'verification_status': 'FAIL', 'source_before': {'sha256': identity},
            'source_after_sha256': identity, 'process_cleanup': {'status': 'PASS', 'remaining_active_processes': cleanup},
            'stdout': {'file': stdout_file, 'sha256': hashlib.sha256((owner / 'stdout.txt').read_bytes()).hexdigest()},
            'stderr': {'file': 'stderr.txt', 'sha256': hashlib.sha256(b'').hexdigest()}}
        path = owner / 'receipt.json'; path.write_text(json.dumps(row), encoding='utf-8')
        return source, path

    def test_failed_owner_and_original_bytes_survive_while_disks_and_installers_are_excluded(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='dr-', dir=local) as directory:
            base = Path(directory); source, owner = self.fixture(base); out = base / 'e.zip'
            with patch.object(retention, 'actual_controller'), patch.object(retention, 'fsync_directory'):
                result = retention.retain(source, owner, out, 30)
            self.assertEqual(result['owner_exit_code'], 1)
            self.assertEqual(result['owner_verification_status'], 'FAIL'); self.assertIs(result['reference_qualified'], False)
            with zipfile.ZipFile(out) as archive:
                names = set(archive.namelist())
                self.assertNotIn('source/vm/work.raw', names); self.assertNotIn('source/vm/rustup-init', names)
                self.assertEqual(archive.read('owner/stdout.txt'), b'synthetic failed-owner output\n')
                manifest = json.loads(archive.read('manifest.json'))
                self.assertEqual(manifest['owner_verification_status'], 'FAIL')
                self.assertIn('utilities', manifest['missing_selected_paths'])

    def test_incomplete_or_bool_cleanup_cannot_start_archive(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        for cleanup in (1, False):
            with tempfile.TemporaryDirectory(prefix='dc-', dir=local) as directory:
                base = Path(directory); source, owner = self.fixture(base, cleanup=cleanup); out = base / 'e.zip'
                with patch.object(retention, 'actual_controller'):
                    with self.assertRaises(ValueError): retention.retain(source, owner, out, 30)
                self.assertFalse(out.exists()); self.assertFalse(out.with_name('e.zip.pending').exists())

    def test_owner_raw_path_traversal_is_rejected_before_reading_it(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='dt-', dir=local) as directory:
            base = Path(directory); source, owner = self.fixture(base, stdout_file='../outside')
            with patch.object(retention, 'actual_controller'), patch.object(retention, 'verify_receipt') as verify:
                with self.assertRaisesRegex(ValueError, 'closed original owner raw'):
                    retention.retain(source, owner, base / 'e.zip', 30)
                verify.assert_not_called()

    def test_missing_actual_runtime_precedes_all_paths(self):
        with patch.object(retention, 'actual_controller', side_effect=ValueError('BLOCKED: actual scoped controller')), \
            patch.object(retention.archive_capture, 'owned') as owned:
            with self.assertRaises(ValueError): retention.retain(Path('missing'), Path('missing'), Path('out'), 30)
            owned.assert_not_called()


if __name__ == '__main__': unittest.main()
