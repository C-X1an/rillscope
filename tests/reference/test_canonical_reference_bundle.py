"""Actual tiny bundle restoration and adversarial index controls; no execution."""
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import canonical_reference_bundle as bundles
from tests.reference import test_retain_canonical_reference as custody


def fixture(root, failed=False):
    source, owner, archive = custody.fixture(root, failed=failed)
    result = custody.CanonicalByteRetention().execute(root, source, owner, archive)
    return archive, result


def rewrite(archive, operation):
    with zipfile.ZipFile(archive) as original:
        files = {row.filename: original.read(row.filename) for row in original.infolist()}
    operation(files)
    replacement = archive.with_name('changed.zip')
    with zipfile.ZipFile(replacement, 'x', compression=zipfile.ZIP_DEFLATED) as target:
        for name, raw in files.items(): target.writestr(name, raw)
    return replacement


class CanonicalBundleRestoration(unittest.TestCase):
    def test_exact_mapped_original_bytes_restore_without_running_a_capture(self):
        with tempfile.TemporaryDirectory(prefix='rill-bundle-unit-') as name:
            root = Path(name).resolve(); archive, custody_result = fixture(root); out = root / '.local-runs/restored'
            with patch.object(archive_capture, 'ROOT', root):
                result = bundles.extract(archive, out, max_bytes=custody_result['logical_bytes'], budget_seconds=60)
            self.assertEqual(result['status'], 'RESTORED ORIGINAL INCLUDED BYTES')
            self.assertEqual(result['completed_files'], custody_result['files'])
            self.assertIs(result['reference_qualified'], False)
            with zipfile.ZipFile(archive) as source:
                manifest = json.loads(source.read('manifest.json'))
                for row in manifest['files']:
                    self.assertEqual((out / row['path']).read_bytes(), source.read('objects/' + row['sha256']))
            self.assertFalse((out / 'attempt/vm/work.raw').exists())

    def test_explicit_budget_rejects_before_output_creation_and_prefix_restores_only_chosen_bytes(self):
        with tempfile.TemporaryDirectory(prefix='rill-bundle-unit-') as name:
            root = Path(name).resolve(); archive, custody_result = fixture(root)
            with patch.object(archive_capture, 'ROOT', root):
                rejected = root / '.local-runs/rejected'
                with self.assertRaises(ValueError): bundles.extract(archive, rejected, max_bytes=1, budget_seconds=60)
                self.assertFalse(rejected.exists())
                out = root / '.local-runs/owner-only'
                result = bundles.extract(archive, out, max_bytes=custody_result['logical_bytes'], budget_seconds=60, prefixes=['owner'])
            self.assertEqual(result['completed_files'], 3)
            self.assertTrue((out / 'owner/receipt.json').is_file())
            self.assertFalse((out / 'attempt').exists())

    def test_upstream_failure_is_never_repaired_by_byte_restoration(self):
        with tempfile.TemporaryDirectory(prefix='rill-bundle-unit-') as name:
            root = Path(name).resolve(); archive, result = fixture(root, failed=True); out = root / '.local-runs/restored'
            with patch.object(archive_capture, 'ROOT', root): bundles.extract(archive, out, max_bytes=result['logical_bytes'], budget_seconds=60)
            owner = json.loads((out / 'owner/receipt.json').read_bytes())
            self.assertEqual((owner['exit_code'], owner['verification_status']), (124, 'FAIL'))
            self.assertEqual(json.loads((out / 'restore-result.json').read_bytes())['all_record_validation'], 'NOT RUN')

    def test_bad_directory_count_is_rejected_before_zip_parser_allocation(self):
        with tempfile.TemporaryDirectory(prefix='rill-bundle-unit-') as name:
            root = Path(name).resolve(); archive, result = fixture(root)
            with archive.open('r+b') as source:
                source.seek(-22, 2); values = list(struct.unpack('<4s4H2LH', source.read(22)))
                values[3] = values[4] = 65535; source.seek(-22, 2); source.write(struct.pack('<4s4H2LH', *values))
            with patch.object(archive_capture, 'ROOT', root), \
                patch.object(bundles.zipfile, 'ZipFile', side_effect=AssertionError('unbounded ZIP parser reached')) as parser:
                with self.assertRaisesRegex(ValueError, 'before ZIP parsing'):
                    bundles.CanonicalBundle(archive, time.monotonic() + 60)
                parser.assert_not_called()

    def test_untrusted_manifest_path_aliases_traversal_depth_and_size_are_rejected(self):
        mutations = [lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows[0].update(path='attempt/../outside'),
            lambda rows: rows[0].update(path='attempt/' + '/'.join(['deep'] * 33) + '/file.json'),
            lambda rows: rows[0].update(bytes=True),
            lambda rows: rows[0].update(bytes=bundles.MAX_FILE + 1),
            lambda rows: rows.append({**rows[0], 'path': rows[0]['path'].replace('attempt', 'Attempt', 1)})]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix='rill-bundle-unit-') as name:
                root = Path(name).resolve(); archive, result = fixture(root)
                def change(files):
                    manifest = json.loads(files['manifest.json']); mutation(manifest['files'])
                    files['manifest.json'] = custody.encode(manifest)
                changed = rewrite(archive, change)
                with patch.object(archive_capture, 'ROOT', root):
                    with self.assertRaises(ValueError): bundles.CanonicalBundle(changed, time.monotonic() + 60)

    def test_changed_object_lengths_are_rejected_without_partial_output(self):
        with tempfile.TemporaryDirectory(prefix='rill-bundle-unit-') as name:
            root = Path(name).resolve(); archive, result = fixture(root)
            def change(files):
                key = next(name for name in files if name.startswith('objects/')); files[key] += b'changed'
            changed = rewrite(archive, change); out = root / '.local-runs/rejected'
            with patch.object(archive_capture, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'length differs'):
                    bundles.extract(changed, out, max_bytes=result['logical_bytes'], budget_seconds=60)
            self.assertFalse(out.exists())

    def test_selector_normalization_spends_original_cutoff_before_archive_or_output(self):
        with tempfile.TemporaryDirectory(prefix='rill-bundle-unit-') as name:
            root = Path(name).resolve(); archive, result = fixture(root); out = root / '.local-runs/rejected'
            now = [1000.0]; original = bundles.relative
            def normalize(value):
                now[0] += .02
                return original(value)
            selectors = ['owner/m' + str(index) for index in range(99)] + ['owner']
            with patch.object(archive_capture, 'ROOT', root), patch.object(bundles, 'relative', side_effect=normalize), \
                patch.object(bundles.time, 'monotonic', side_effect=lambda: now[0]):
                with self.assertRaisesRegex(ValueError, 'cutoff'):
                    bundles.extract(archive, out, max_bytes=result['logical_bytes'], budget_seconds=1, prefixes=selectors)
            self.assertFalse(out.exists())
            self.assertLess(now[0], 1001.1)

    def test_selector_count_is_bounded_before_materializing_an_arbitrary_iterator(self):
        with tempfile.TemporaryDirectory(prefix='rill-bundle-unit-') as name:
            root = Path(name).resolve(); archive, result = fixture(root); out = root / '.local-runs/rejected'; consumed = []
            def selectors():
                for index in range(10000):
                    consumed.append(index)
                    yield 'owner/m' + str(index)
            with patch.object(archive_capture, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'selector count'):
                    bundles.extract(archive, out, max_bytes=result['logical_bytes'], budget_seconds=60, prefixes=selectors())
            self.assertEqual(len(consumed), bundles.MAX_PREFIXES + 1)
            self.assertFalse(out.exists())


if __name__ == '__main__': unittest.main()
