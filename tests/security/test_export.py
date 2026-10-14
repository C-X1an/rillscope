"""Public exporter boundary tests. A missing symlink privilege fails explicitly."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('export_policy', ROOT / 'scripts/export_policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

class PublicBoundary(unittest.TestCase):
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

if __name__ == '__main__': unittest.main()
