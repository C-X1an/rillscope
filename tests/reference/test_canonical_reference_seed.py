"""Source-only inventory controls; literal metadata is not an actual VM seed."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_seed as seed


def literal_seed():
    files = [{'path': path, 'bytes': 1, 'mode': 0o644, 'sha256': 'c' * 64}
        for path in sorted(seed.REQUIRED_FILES)]
    installer = next(row for row in files if row['path'] == seed.INSTALLER_RELATIVE)
    installer.update(sha256=seed.INSTALLER_SHA256, mode=0o555)
    return {'schema_version': 1, 'method': seed.allocation.METHOD, 'commit': 'a' * 40,
        'source_sha256': 'b' * 64, 'files': files, 'rustup_version': '1.28.2',
        'installer_sha256': seed.INSTALLER_SHA256, 'installer_url': seed.INSTALLER_URL,
        'setup_seconds': 3000, 'tail_seconds': 60, 'retention_seconds': 180,
        'mode': 'canonical', 'first_party_build_transported': False, 'reference_qualified': False}


class SourceSeedControls(unittest.TestCase):
    def test_closed_literal_source_only_modes_and_pinned_installer(self):
        row = literal_seed(); self.assertEqual(seed.validate_seed(row), row)
        row['mode'] = 'native-setup-diagnostic'; self.assertEqual(seed.validate_seed(row), row)
        for key, value in [('mode', 'full'), ('mode', []), ('schema_version', True), ('setup_seconds', True),
            ('first_party_build_transported', True), ('reference_qualified', True),
            ('installer_sha256', '0' * 64), ('installer_url', 'https://example.invalid/installer'),
            ('rustup_version', 'latest'), ('unexpected', 1)]:
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(literal_seed()); changed[key] = value
                with self.assertRaises(ValueError): seed.validate_seed(changed)

    def test_duplicate_traversal_build_cache_missing_git_and_writable_files_rejected(self):
        for path in ('/absolute', '../outside', 'C:/outside', 'a\\b', 'x/../y', 'target/executable',
            '.cargo/bin/rustc', '.local-runs/old-build/executable'):
            with self.subTest(path=path):
                row = literal_seed(); row['files'].append({'path': path, 'bytes': 1, 'mode': 0o644, 'sha256': 'c' * 64})
                row['files'].sort(key=lambda item: item['path'])
                with self.assertRaises(ValueError): seed.validate_seed(row)
        row = literal_seed(); row['files'].append(copy.deepcopy(row['files'][0]))
        with self.assertRaises(ValueError): seed.validate_seed(row)
        row = literal_seed(); row['files'] = [item for item in row['files'] if item['path'] != '.git/HEAD']
        with self.assertRaises(ValueError): seed.validate_seed(row)
        row = literal_seed(); row['files'][0]['mode'] = 0o666
        with self.assertRaises(ValueError): seed.validate_seed(row)

    def test_actual_file_inventory_hashes_and_rejects_target_or_other_generated_files(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='seed-inventory-', dir=local) as directory:
            root = Path(directory); (root / 'source.rs').write_bytes(b'original source\n')
            rows = seed.seed_files(root)
            self.assertEqual(rows[0]['path'], 'source.rs')
            self.assertEqual(rows[0]['sha256'], hashlib.sha256(b'original source\n').hexdigest())
            (root / 'target').mkdir()
            with self.assertRaises(ValueError): seed.seed_files(root)
            (root / 'target').rmdir(); (root / '.local-runs').mkdir()
            (root / '.local-runs/unexpected').write_bytes(b'old build')
            with self.assertRaises(ValueError): seed.seed_files(root)

    def test_seed_preparation_cannot_run_on_windows_before_source_or_files(self):
        with patch.object(seed.platform, 'system', return_value='Windows'), patch.object(seed, 'source_check') as source:
            with self.assertRaisesRegex(ValueError, 'actual existing owned Linux root'):
                seed.prepare_seed(Path('missing'), Path('missing-installer'), commit='a' * 40,
                    source_sha256='b' * 64, setup_seconds=3000, tail_seconds=60,
                    retention_seconds=180, mode='canonical', checked=None)
            source.assert_not_called()


if __name__ == '__main__': unittest.main()
