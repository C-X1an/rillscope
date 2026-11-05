"""Tiny real byte/mode export fixtures; Linux cross-UID control is separate."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import export_canonical_failure as export
from .test_retain_canonical_reference import fixture


class FailureExportTests(unittest.TestCase):
    def run_export(self, root, selected, out, **kwargs):
        with patch.object(archive_capture, 'ROOT', root):
            return export.export_prefix(selected, out, budget_seconds=kwargs.get('seconds', 10), owner_sha256=None)

    def test_copy_preserves_all_selected_bytes_and_original_modes_without_exposing_sources(self):
        with tempfile.TemporaryDirectory(prefix='rill-failure-export-unit-') as name:
            root = Path(name).resolve(); selected = root / '.local-runs/private'; selected.mkdir(parents=True)
            (selected / 'a.raw').write_bytes(b'literal failed prefix\n')
            (selected / 'b.raw').write_bytes(b'literal failed prefix\n')
            os.chmod(selected, 0o700); os.chmod(selected / 'a.raw', 0o600)
            before = {p: p.stat() for p in (selected, selected / 'a.raw', selected / 'b.raw')}
            out = root / '.local-runs/readable.zip'
            result = self.run_export(root, [('owner', selected), ('absent', selected / 'missing')], out)
            self.assertIs(result['reference_qualified'], False); self.assertEqual(result['files'], 2)
            self.assertEqual(result['objects'], 1); self.assertEqual(result['missing_selected_paths'], ['absent'])
            self.assertEqual(result['archive_sha256'], hashlib.sha256(out.read_bytes()).hexdigest())
            with zipfile.ZipFile(out) as bundle:
                manifest = json.loads(bundle.read('manifest.json')); self.assertIs(manifest['reference_qualified'], False)
                self.assertIsNone(manifest['owner_receipt_sha256'])
                for row in manifest['files']:
                    data = bundle.read('objects/' + row['sha256'])
                    self.assertEqual(data, b'literal failed prefix\n')
                    self.assertEqual(hashlib.sha256(data).hexdigest(), row['sha256'])
                    path = selected / Path(row['path']).name
                    self.assertEqual(row['mode'], before[path].st_mode & 0o7777)
            for path, old in before.items():
                now = path.stat()
                self.assertEqual((old.st_mode, old.st_uid, old.st_gid, old.st_mtime_ns),
                                 (now.st_mode, now.st_uid, now.st_gid, now.st_mtime_ns))

    def test_explicit_byte_count_depth_and_compressed_bounds_fail_without_overwriting_originals(self):
        for limit, value, expected in [('MAX_FILE', 2, 'regular'), ('MAX_BYTES', 2, 'aggregate'),
                                       ('MAX_FILES', 0, 'bound'), ('MAX_DEPTH', 1, 'depth'),
                                       ('MAX_ARCHIVE', 16, 'compressed')]:
            with self.subTest(limit=limit), tempfile.TemporaryDirectory(prefix='rill-failure-limit-unit-') as name:
                root = Path(name).resolve(); selected = root / '.local-runs/private'; selected.mkdir(parents=True)
                original = selected / 'raw'; original.write_bytes(b'unmodified original bytes')
                with patch.object(export, limit, value), self.assertRaisesRegex(ValueError, expected):
                    self.run_export(root, [('selected', selected)], root / '.local-runs/out.zip')
                self.assertEqual(original.read_bytes(), b'unmodified original bytes')

    def test_forbidden_output_alias_existing_output_and_expired_budget_reject(self):
        with tempfile.TemporaryDirectory(prefix='rill-failure-path-unit-') as name:
            root = Path(name).resolve(); selected = root / '.local-runs/private'; selected.mkdir(parents=True)
            (selected / 'raw').write_bytes(b'original')
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                self.run_export(root, [('owner', selected)], selected / 'out.zip')
            with self.assertRaisesRegex(ValueError, 'forbidden'):
                self.run_export(root, [('target', selected)], root / '.local-runs/out.zip')
            with self.assertRaisesRegex(ValueError, 'finite'):
                self.run_export(root, [('owner', selected)], root / '.local-runs/out.zip', seconds=0)
            existing = root / '.local-runs/existing.zip'; existing.write_bytes(b'prior original output')
            with self.assertRaisesRegex(ValueError, 'new separate'):
                self.run_export(root, [('owner', selected)], existing)
            self.assertEqual(existing.read_bytes(), b'prior original output')

    def test_cli_requires_stopped_original_owner_and_exports_original_owner_and_plan_context(self):
        with tempfile.TemporaryDirectory(prefix='rill-failure-owner-unit-') as name:
            root = Path(name).resolve(); selected, receipt, _ = fixture(root, failed=True)
            out = root / '.local-runs/failure.zip'
            args = ['--source', str(selected), '--owner-receipt', str(receipt), '--out', str(out), '--budget-seconds', '10']
            with patch.object(export, 'ROOT', root), patch.object(archive_capture, 'ROOT', root), patch.object(export, 'actual_controller'):
                self.assertEqual(export.main(args), 0)
                with zipfile.ZipFile(out) as bundle:
                    names = {row['path'] for row in json.loads(bundle.read('manifest.json'))['files']}
                    self.assertIn('owner/receipt.json', names); self.assertIn('input/declared-plan.json', names)
                    self.assertIn('attempt/vm/artifact/serial.txt', names)
                    self.assertFalse(any('work.raw' in item or 'qcow2' in item for item in names))
                row = json.loads(receipt.read_bytes()); row['process_cleanup']['remaining_active_processes'] = False
                receipt.write_text(json.dumps(row), encoding='utf-8'); args[5] = str(root / '.local-runs/rejected.zip')
                self.assertEqual(export.main(args), 1)
                self.assertFalse((root / '.local-runs/rejected.zip').exists())

    def test_owner_receipt_changed_after_validation_cannot_be_exported_under_old_stop_binding(self):
        self.changed_after_validation('receipt.json')

    def test_owner_stdout_changed_after_validation_cannot_be_exported_under_old_raw_binding(self):
        self.changed_after_validation('stdout.txt')

    def changed_after_validation(self, name):
        with tempfile.TemporaryDirectory(prefix='rill-failure-snapshot-unit-') as directory:
            root = Path(directory).resolve(); selected, receipt, _ = fixture(root, failed=True)
            out = root / '.local-runs/failure.zip'; actual_export = export.export_prefix
            def changed(*args, **kwargs):
                if name == 'receipt.json':
                    row = json.loads(receipt.read_bytes()); row['process_cleanup']['remaining_active_processes'] = 1
                    receipt.write_text(json.dumps(row), encoding='utf-8')
                else: (receipt.parent / name).write_bytes(b'changed after original raw validation')
                return actual_export(*args, **kwargs)
            with patch.object(export, 'ROOT', root), patch.object(archive_capture, 'ROOT', root), \
                    patch.object(export, 'actual_controller'), patch.object(export, 'export_prefix', changed):
                self.assertEqual(export.main(['--source', str(selected), '--owner-receipt', str(receipt),
                    '--out', str(out), '--budget-seconds', '10']), 1)
            self.assertFalse(out.exists()); self.assertFalse(out.with_suffix('.json').exists())


if __name__ == '__main__': unittest.main()
