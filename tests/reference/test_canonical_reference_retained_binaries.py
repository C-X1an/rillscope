"""Literal byte-custody fixtures; stored ELF-shaped bytes are never executable."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
from canonical_reference_retained_binaries import validate_binaries
from evidence import source_identity
from tests.reference import test_canonical_reference_binaries as custody

elf = custody.elf


def sha(raw): return hashlib.sha256(raw).hexdigest()
def write(path, row): path.write_text(json.dumps(row, indent=2) + '\n', encoding='utf-8')
def load(path): return json.loads(path.read_bytes())


class RetainedNativeRecords(unittest.TestCase):
    def workspace(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='nv-', dir=local)

    def fixture(self, root):
        original = custody.NativeBinaryCustody(); clone, identity = original.fixture(root)
        receipts = [clone / '.local-runs/build/dev-123/build.json',
            clone / '.local-runs/benchmark-123/build/build.json', clone / '.local-runs/bench/s-123/build/build.json']
        for path in receipts:
            row = load(path); row['rustc_executable_sha256'] = 'f' * 64; row['problems'] = []
            row['command'] = ['cargo', 'build', '--bins', '--locked', '--message-format=json-render-diagnostics', '--verbose']
            if row['profile'] == 'release': row['command'].append('--release')
            else:
                raw = elf(b'functional-unused-measurement-bin')
                extra = clone / row['target_directory'] / 'rillscope-measure'; extra.write_bytes(raw)
                row['bins']['rillscope-measure'] = {'path': extra.relative_to(clone).as_posix(), 'sha256': sha(raw),
                    'actual_profile': {'opt_level': '0', 'debug_assertions': True, 'test': False}}
                row['target_directory'] = 'target'
            write(path, row)
        for receipt, stage in [(receipts[1], 'grid'), (receipts[1], 'cancel'), (receipts[2], 'grid')]:
            path = receipt.parent.parent / stage / 'manifest.json'; row = load(path); build = load(receipt)
            row.update(build=build, build_receipt_sha256=sha(receipt.read_bytes())); write(path, row)
        result_path = clone.parent / 'results.json'; result = load(result_path); result['status'] = 'PASS'; write(result_path, result)
        out, result = original.retain(root, identity)
        self.assertEqual(result['status'], 'RETAINED ORIGINAL BYTES', result['errors'])
        source = source_identity(root)
        fresh = {'status': 'CHECKED RECORDED FRESH', 'commit': 'a' * 40, 'source_sha256': identity,
            'fresh_checkout': clone.relative_to(root).as_posix(), 'fresh_result_sha256': sha(result_path.read_bytes())}
        return out, source, fresh

    def check(self, root, out, source, fresh):
        return validate_binaries(out, commit='a' * 40, source=source, fresh=fresh, validator_root=root)

    def metadata_change(self, out, source_suffix, operation):
        record = load(out / 'binaries-result.json')
        row = next(row for row in record['metadata'] if row['source'].endswith(source_suffix))
        path = out / row['file']; raw = operation(path.read_bytes()); path.write_bytes(raw)
        row.update(bytes=len(raw), sha256=sha(raw))
        record['bytes'] = sum(item['bytes'] for key in ('metadata', 'objects') for item in record[key])
        write(out / 'binaries-result.json', record)

    def test_all_four_original_roles_and_shared_bytes_are_checked_without_execution(self):
        with self.workspace() as name:
            root = Path(name); out, source, fresh = self.fixture(root)
            checked = self.check(root, out, source, fresh)
            self.assertEqual([row['role'] for row in checked['associations']], ['functional', 'full-grid', 'full-cancel', 'sort-null'])
            self.assertEqual(checked['objects_checked'], 3)
            self.assertEqual(checked['executables_run'], 0)
            self.assertIs(checked['reference_qualified'], False)
            self.assertEqual(checked['associations'][1]['sha256'], sha(elf(b'measure')))

    def test_changed_retained_elf_fails_its_recorded_digest(self):
        with self.workspace() as name:
            root = Path(name); out, source, fresh = self.fixture(root)
            record = load(out / 'binaries-result.json'); path = out / record['objects'][0]['file']; path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'digest differs'): self.check(root, out, source, fresh)

    def test_reindexed_raw_build_output_still_fails_original_build_binding(self):
        with self.workspace() as name:
            root = Path(name); out, source, fresh = self.fixture(root)
            self.metadata_change(out, 'dev-123/cargo.stdout', lambda raw: b'Changed cargo bytes\n')
            with self.assertRaisesRegex(ValueError, 'raw stream differs'): self.check(root, out, source, fresh)

    def test_wrong_compiler_pin_is_rejected_even_with_updated_metadata_index(self):
        with self.workspace() as name:
            root = Path(name); out, source, fresh = self.fixture(root)
            def change(raw):
                row = json.loads(raw); row['compiler'] = row['compiler'].replace('1.99.0', '1.98.0')
                return json.dumps(row).encode()
            self.metadata_change(out, 'dev-123/build.json', change)
            with self.assertRaisesRegex(ValueError, 'pinned native compiler'): self.check(root, out, source, fresh)

    def test_missing_role_or_boolean_exit_or_renewed_retention_clock_cannot_pass(self):
        for mutation in ['missing-role', 'boolean-exit', 'late-clock']:
            with self.subTest(mutation=mutation), self.workspace() as name:
                root = Path(name); out, source, fresh = self.fixture(root)
                if mutation == 'boolean-exit':
                    def change(raw):
                        row = json.loads(raw); row['exit_code'] = False; return json.dumps(row).encode()
                    self.metadata_change(out, 'dev-123/build.json', change)
                else:
                    path = out / 'binaries-result.json'; row = load(path)
                    if mutation == 'missing-role': row['associations'].pop()
                    else: row['finished_monotonic_ns'] = row['cutoff_monotonic_ns']
                    write(path, row)
                with self.assertRaises(ValueError): self.check(root, out, source, fresh)

    def test_fresh_and_retained_native_records_must_use_same_original_result(self):
        with self.workspace() as name:
            root = Path(name); out, source, fresh = self.fixture(root); fresh['fresh_result_sha256'] = 'e' * 64
            with self.assertRaisesRegex(ValueError, 'different original result'): self.check(root, out, source, fresh)

    def test_manifest_cannot_point_at_a_different_original_build(self):
        with self.workspace() as name:
            root = Path(name); out, source, fresh = self.fixture(root)
            def change(raw):
                row = json.loads(raw); row['build_receipt_sha256'] = 'd' * 64; return json.dumps(row).encode()
            self.metadata_change(out, 'benchmark-123/grid/manifest.json', change)
            with self.assertRaisesRegex(ValueError, 'measured manifest'): self.check(root, out, source, fresh)


if __name__ == '__main__': unittest.main()
