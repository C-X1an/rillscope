"""Literal independent source/public scopes; no VM or native execution claim."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_recovered_records as records
from .test_canonical_reference_seed import literal_seed


def fixture():
    data = {'Cargo.toml': b'literal package\n', 'Cargo.lock': b'literal lock\n',
        'rust-toolchain.toml': b'literal pinned toolchain\n',
        'scripts/canonical_reference_guest_start.py': b'literal source; never executed\n',
        'verification/spec-lock.json': b'{"locked":true}\n',
        'verification/product/index.json': b'{"literal":"index"}\n',
        'verification/product/proof.json': b'{"literal":"proof"}\n'}
    expected = [{'path': name, 'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
        for name, value in sorted(data.items())]
    runtime = [[name, hashlib.sha256(value).hexdigest()] for name, value in sorted(data.items())
        if not name.startswith('verification/product/')]
    seed = literal_seed()
    seed['files'] = [row for row in seed['files'] if row['path'].startswith('.git/') or row['path'] == records.INSTALLER_RELATIVE]
    seed['files'] += [{**row, 'mode': 0o444} for row in expected]
    seed['files'].sort(key=lambda row: row['path'])
    source = {'sha256': 'b' * 64, 'files': runtime}
    return data, expected, seed, source


def accepts(seed, source, public):
    try: records.check_seed_source(seed, source, public_files=public)
    except ValueError: return False
    return True


class CompletePublicSeedControls(unittest.TestCase):
    def test_valid_complete_seed_retains_public_evidence_beyond_execution_identity(self):
        _, expected, seed, source = fixture()
        self.assertEqual(len(source['files']), 5)
        self.assertEqual(len(expected), 7)
        self.assertTrue(accepts(seed, source, expected))

    def test_missing_added_changed_or_wrong_size_public_evidence_is_rejected(self):
        _, expected, seed, source = fixture()
        for change in ('missing', 'added', 'changed', 'size'):
            with self.subTest(change=change):
                candidate = copy.deepcopy(seed)
                if change == 'missing':
                    candidate['files'] = [row for row in candidate['files'] if row['path'] != 'verification/product/proof.json']
                elif change == 'added':
                    candidate['files'].append({'path': 'verification/product/unlisted.json', 'bytes': 1, 'mode': 0o444, 'sha256': 'd' * 64})
                    candidate['files'].sort(key=lambda row: row['path'])
                else:
                    row = next(row for row in candidate['files'] if row['path'] == 'verification/product/proof.json')
                    row['sha256' if change == 'changed' else 'bytes'] = 'd' * 64 if change == 'changed' else row['bytes'] + 1
                self.assertFalse(accepts(candidate, source, expected))

    def test_complete_snapshot_cannot_replace_or_omit_execution_source(self):
        _, expected, seed, source = fixture()
        changed_seed, changed_public = copy.deepcopy(seed), copy.deepcopy(expected)
        next(row for row in changed_seed['files'] if row['path'] == 'Cargo.toml')['sha256'] = 'd' * 64
        next(row for row in changed_public if row['path'] == 'Cargo.toml')['sha256'] = 'd' * 64
        self.assertFalse(accepts(changed_seed, source, changed_public))
        self.assertFalse(accepts(seed, source, [row for row in expected if row['path'] != 'Cargo.toml']))
        changed_seed = copy.deepcopy(seed); changed_seed['source_sha256'] = 'd' * 64
        self.assertFalse(accepts(changed_seed, source, expected))

    def test_public_snapshot_must_be_closed_unique_sorted_and_bounded(self):
        _, expected, seed, source = fixture()
        for public in [expected + [copy.deepcopy(expected[-1])], list(reversed(expected)),
                [{**row, 'extra': True} for row in expected],
                [{**row, 'bytes': True} for row in expected],
                [{**row, 'path': '../outside'} for row in expected]]:
            with self.subTest(public=public): self.assertFalse(accepts(seed, source, public))

    def test_legacy_minimal_scope_remains_exact_and_cannot_ignore_extra_public_files(self):
        _, _, seed, source = fixture()
        minimal = copy.deepcopy(seed)
        minimal['files'] = [row for row in minimal['files'] if not row['path'].startswith('verification/product/')]
        records.check_seed_source(minimal, source)
        with self.assertRaises(ValueError): records.check_seed_source(seed, source)

    def test_actual_bounded_inventory_includes_verification_and_excludes_generated_work(self):
        data, expected, _, _ = fixture()
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='seed-public-inventory-', dir=local) as directory:
            root = Path(directory)
            for name, value in {**data, '.git/config': b'ignored Git metadata',
                    '.local-runs/old/raw': b'ignored generated work', 'target/old': b'ignored old build',
                    '__pycache__/old.pyc': b'ignored cache'}.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(value)
            self.assertEqual(records.public_source_inventory(root), expected)

    def test_actual_inventory_enforces_file_count_and_byte_bounds(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='seed-public-bounds-', dir=local) as directory:
            root = Path(directory); (root / 'one').write_bytes(b'1234')
            with patch.object(records, 'SEED_MAX_FILE', 3), self.assertRaises(ValueError): records.public_source_inventory(root)
            (root / 'two').write_bytes(b'12')
            with patch.object(records, 'SEED_MAX_FILES', 1), self.assertRaises(ValueError): records.public_source_inventory(root)
            with patch.object(records, 'SEED_MAX_TOTAL', 5), self.assertRaises(ValueError): records.public_source_inventory(root)


if __name__ == '__main__': unittest.main()
