"""Public exporter boundary tests. A missing symlink privilege fails explicitly."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('export_policy', ROOT / 'scripts/export_policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

class PublicBoundary(unittest.TestCase):
    def test_real_staging_and_zip_have_exact_regular_allowlist(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'source'
            root.mkdir()
            (root / 'README.md').write_bytes(b'Synthetic public source\n')
            (root / 'src').mkdir()
            (root / 'src/lib.rs').write_bytes(b'#![forbid(unsafe_code)]\n')
            allowed = {'README.md', 'src/lib.rs'}
            target = Path(folder) / 'export'
            manifest = policy.export(root, allowed, target)
            self.assertEqual({row['path'] for row in manifest['files']}, allowed)
            with zipfile.ZipFile(Path(folder) / 'export.zip') as archive:
                self.assertEqual(set(archive.namelist()), allowed)
                for name in allowed:
                    self.assertEqual(archive.read(name), (root / name).read_bytes())
                    self.assertEqual((target / name).read_bytes(), (root / name).read_bytes())
            with self.assertRaises(ValueError): policy.export(root, allowed, target)
            (root / 'unlisted.txt').write_text('Forbidden addition')
            with self.assertRaises(ValueError): policy.export(root, allowed, Path(folder) / 'rejected')
            self.assertFalse((Path(folder) / 'rejected').exists())

    def test_exact_allowlist_and_missing_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'README.md').write_text('Synthetic public source')
            self.assertEqual(policy.audit(root, {'README.md'})['errors'], [])
            self.assertTrue(policy.audit(root, {'README.md', 'missing.rs'})['errors'])
            (root / 'unknown.txt').write_text('Unlisted file')
            self.assertTrue(policy.audit(root, {'README.md'})['errors'])

    def test_even_allowlisted_env_resume_marker_and_credentials_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for filename, content in [('.ENV', b'synthetic'), ('README.md', policy.CANARY), ('resume.docx', b'synthetic'),
                                      ('token.txt', ('gh' + 'p_' + 'A'*40).encode())]:
                path = root / filename
                path.write_bytes(content)
                self.assertTrue(policy.audit(root, {filename})['errors'])
                path.unlink()

    def test_symbolic_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source.txt'
            source.write_text('Synthetic target')
            (root / 'link.txt').symlink_to(source)
            self.assertTrue(policy.audit(root, {'source.txt', 'link.txt'})['errors'])
            with self.assertRaises(ValueError): policy.export(root, {'source.txt', 'link.txt'}, root.parent / 'rejected-export')

if __name__ == '__main__': unittest.main()
