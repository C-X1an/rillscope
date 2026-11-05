"""Literal file-I/O and corruption controls for the bounded read-only CAS view."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from capture_read_view import CaptureReadView
import capture_read_view


class CaptureReadViewTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / '.local-runs'
        self.base.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='capture-read-', dir=self.base)
        self.folder = Path(self.tmp.name).resolve()
        self.assertTrue(self.folder.is_relative_to(self.base.resolve()))
        self.values = {'a.txt': 'alpha\r\nβ\n'.encode(), 'sub/empty': b'',
                       'sub/rows.json': b'[[null,1],[null,1]]\n',
                       'binary.dat': bytes(range(256))}
        self.archive = self.folder / 'capture.zip'
        self.create(self.archive, self.values)
        self.mount = self.folder / 'view'

    def tearDown(self):
        self.assertTrue(self.folder.resolve().is_relative_to(self.base.resolve()))
        self.tmp.cleanup()

    def create(self, target, values, corrupt=None):
        rows = [{'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                for name, data in sorted(values.items())]
        listing = b''.join(json.dumps(row, separators=(',', ':')).encode() + b'\n' for row in rows)
        metadata = {'format': 'rillscope-cas-capture-v1', 'files': len(rows),
                    'objects': len({row['sha256'] for row in rows}),
                    'bytes': sum(row['bytes'] for row in rows),
                    'manifest_sha256': hashlib.sha256(listing).hexdigest()}
        with zipfile.ZipFile(target, 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
            for row in rows:
                data = values[row['path']]
                if row['path'] == corrupt:
                    data = b'changed bytes'
                bundle.writestr('objects/' + row['sha256'], data)
            bundle.writestr('manifest.jsonl', listing)
            bundle.writestr('metadata.json', json.dumps(metadata))

    def test_literal_bytes_lengths_directories_and_real_paths(self):
        sentinel = self.folder / 'real.txt'
        sentinel.write_bytes(b'outside mount')
        with CaptureReadView(self.archive, self.mount) as view:
            self.assertEqual(view.metadata['files'], 4)
            self.assertTrue(self.mount.is_dir())
            self.assertEqual({p.name for p in self.mount.iterdir()},
                             {'a.txt', 'sub', 'binary.dat'})
            self.assertTrue((self.mount / 'sub').is_dir())
            for name, data in self.values.items():
                path = self.mount / name
                self.assertTrue(path.is_file())
                self.assertEqual(path.stat().st_size, len(data))
                self.assertEqual(path.read_bytes(), data)
            self.assertEqual((self.mount / 'sub/rows.json').read_bytes(),
                             b'[[null,1],[null,1]]\n')
            self.assertEqual(sentinel.read_bytes(), b'outside mount')
        self.assertFalse(self.mount.exists())

    def test_text_newlines_and_binary_seek_match_normal_io(self):
        with CaptureReadView(self.archive, self.mount):
            self.assertEqual((self.mount / 'a.txt').read_text(encoding='utf-8'), 'alpha\nβ\n')
            with (self.mount / 'binary.dat').open('rb') as stream:
                self.assertEqual(stream.read(3), b'\x00\x01\x02')
                self.assertEqual(stream.seek(250), 250)
                self.assertEqual(stream.read(), bytes(range(250, 256)))
                self.assertEqual(stream.tell(), 256)

    def test_writes_missing_files_and_directory_opens_fail(self):
        with CaptureReadView(self.archive, self.mount):
            path = self.mount / 'a.txt'
            for mode in ('w', 'wb', 'a', 'x', 'r+'):
                with self.assertRaises(PermissionError):
                    path.open(mode)
            with path.open('rb') as stream:
                with self.assertRaises(io.UnsupportedOperation):
                    stream.write(b'changed')
            with self.assertRaises(FileNotFoundError):
                (self.mount / 'missing').read_bytes()
            with self.assertRaises(IsADirectoryError):
                (self.mount / 'sub').open('rb')
        self.assertFalse(self.mount.exists())

    def test_exception_and_rejected_nested_view_restore_path_methods(self):
        original = (Path.open, Path.stat, Path.iterdir)
        with self.assertRaisesRegex(RuntimeError, 'body failed'):
            with CaptureReadView(self.archive, self.mount):
                with self.assertRaisesRegex(ValueError, 'cannot nest'):
                    with CaptureReadView(self.archive, self.folder / 'second'):
                        self.fail('nested capture view entered')
                self.assertEqual((self.mount / 'a.txt').read_bytes(), self.values['a.txt'])
                raise RuntimeError('body failed')
        self.assertEqual((Path.open, Path.stat, Path.iterdir), original)

    def test_existing_mount_never_masks_physical_files(self):
        self.mount.mkdir()
        marker = self.mount / 'kept'
        marker.write_bytes(b'original')
        with self.assertRaisesRegex(ValueError, 'new, non-overlapping'):
            with CaptureReadView(self.archive, self.mount):
                self.fail('existing mount was hidden')
        self.assertEqual(marker.read_bytes(), b'original')

    def test_object_corruption_fails_and_original_remains_readable(self):
        bad = self.folder / 'corrupt.zip'
        self.create(bad, self.values, corrupt='sub/rows.json')
        with CaptureReadView(self.archive, self.mount):
            self.assertEqual((self.mount / 'sub/rows.json').read_bytes(),
                             b'[[null,1],[null,1]]\n')
        with self.assertRaisesRegex(ValueError, 'object digest/size'):
            with CaptureReadView(bad, self.mount):
                self.fail('corrupt object accepted')
        with CaptureReadView(self.archive, self.mount):
            self.assertEqual((self.mount / 'sub/rows.json').read_bytes(),
                             b'[[null,1],[null,1]]\n')

    def test_archive_change_fails_after_methods_are_restored(self):
        original = (Path.open, Path.stat, Path.iterdir)
        with self.assertRaisesRegex(ValueError, 'archive changed'):
            with CaptureReadView(self.archive, self.mount):
                self.assertEqual((self.mount / 'a.txt').read_bytes(), self.values['a.txt'])
                with self.archive.open('ab') as stream:
                    stream.write(b'changed archive')
        self.assertEqual((Path.open, Path.stat, Path.iterdir), original)

    def test_oversized_archive_rejects_before_hashing(self):
        with mock.patch.object(capture_read_view.archive_capture, 'MAX_ARCHIVE', 1):
            with mock.patch.object(capture_read_view, '_sha') as hasher:
                with self.assertRaisesRegex(ValueError, 'archive exceeds'):
                    with CaptureReadView(self.archive, self.mount):
                        self.fail('oversized archive accepted')
                hasher.assert_not_called()

    def test_shared_process_rejects_before_opening_archive(self):
        with mock.patch.object(capture_read_view.threading, 'active_count', return_value=2):
            with mock.patch.object(capture_read_view, '_sha') as hasher:
                with self.assertRaisesRegex(ValueError, 'single-threaded'):
                    with CaptureReadView(self.archive, self.mount):
                        self.fail('shared process accepted')
                hasher.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)

