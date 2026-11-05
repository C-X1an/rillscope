"""Literal retained-record fixtures; no native commands or fresh run executed."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
from canonical_reference_retained_fresh import RetainedMetadata, validate_fresh

GATES = ['contracts', 'build', 'fmt', 'lint', 'check', 'test', 'verify-reference',
    'integration', 'acceptance', 'security', 'security-online', 'property', 'fuzz',
    'mutation', 'benchmark', 'benchmark-sort-null', 'publication-check', 'demo']
SOURCE = {'sha256': 'a' * 64, 'files': [['fixture.rs', 'b' * 64]]}
COMMIT = 'c' * 40
ATTEMPT = '.local-runs/clean-literal'
CLONE = ATTEMPT + '/c'
SEED = '/work/c'


def encoded(value): return (json.dumps(value, indent=2) + '\n').encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def timestamp(minute): return '2026-10-25T00:' + str(minute).zfill(2) + ':00+00:00'


def fixture():
    files = {}
    def command(directory, argv, cwd, start, end):
        stdout = b'Literal nonexecution fixture output\n'; stderr = b''
        row = {'schema_version': 1, 'command': argv, 'cwd': cwd,
            'source_before': copy.deepcopy(SOURCE), 'source_after_sha256': SOURCE['sha256'],
            'verification_status': 'PASS', 'execution_outcome': 'EXECUTED', 'exit_code': 0,
            'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0},
            'environment': {'system': 'Linux'}, 'git': {'commit': COMMIT, 'dirty': False},
            'started_utc': timestamp(start), 'finished_utc': timestamp(end), 'elapsed_seconds': 60 * (end - start),
            'stdout': {'file': 'stdout.txt', 'sha256': sha(stdout)},
            'stderr': {'file': 'stderr.txt', 'sha256': sha(stderr)}, 'inputs_before': [], 'inputs_after': [], 'stdin': None,
            'fixture': 'SYNTHETIC RECORD; no command was executed'}
        for name, raw in [('receipt.json', encoded(row)), ('stdout.txt', stdout), ('stderr.txt', stderr)]:
            files[directory + '/' + name] = raw
        return row
    command(ATTEMPT + '/preparation/clone', ['git', 'clone', '--no-local', '--config',
        'core.autocrlf=false', SEED, SEED + '/' + CLONE], SEED, 0, 1)
    commands = []
    for target, start, end in [('bootstrap', 1, 2), ('verify', 2, 40), ('demo', 40, 41)]:
        directory = ATTEMPT + '/commands/' + target
        command(directory, ['make', target], SEED + '/' + CLONE, start, end)
        commands.append({'target': target, 'role': 'canonical', 'state': 'COMPLETED',
            'status': 'PASS', 'exit_code': 0, 'receipt': directory,
            'source_before': SOURCE['sha256'], 'source_after': SOURCE['sha256']})
    steps = []
    for index, target in enumerate(GATES):
        directory = '.local-runs/verify-ledger/commands/' + target
        command(CLONE + '/' + directory, ['make', target], SEED + '/' + CLONE, 3 + index, 4 + index)
        steps.append({'target': target, 'state': 'COMPLETED', 'status': 'PASS', 'exit_code': 0,
            'receipt': directory, 'receipt_sha256': sha(files[CLONE + '/' + directory + '/receipt.json'])})
    files[CLONE + '/.local-runs/verify-ledger/ledger.json'] = encoded({'schema_version': 1,
        'source_sha256': SOURCE['sha256'], 'plan': list(GATES), 'commands': steps, 'status': 'PASS'})
    files[ATTEMPT + '/results.json'] = encoded({'mode': 'fresh-committed-Rust-checkout', 'status': 'PASS',
        'commit': COMMIT, 'source_sha256': SOURCE['sha256'], 'source_stable': True,
        'target_directory_was_fresh': True, 'cargo_target_dir_enforced_inside_fresh_clone': True,
        'same_os_and_toolchain_installation': True, 'checkout': CLONE, 'commands': commands,
        'preparation': [{'operation': 'clone', 'state': 'COMPLETED', 'status': 'PASS', 'exit_code': 0,
            'receipt': ATTEMPT + '/preparation/clone'}], 'diagnostic_commands': [], 'not_run': [],
        'fixture': 'No fresh run executed; literal expected complete shape only'})
    return files


def change(files, path, operation):
    row = json.loads(files[path]); operation(row); files[path] = encoded(row)


def retain(root, files):
    rows = []
    for index, (source, raw) in enumerate(sorted(files.items())):
        file = 'metadata/m' + str(index) + '/' + Path(source).name
        path = root / file; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        rows.append({'source': source, 'file': file, 'bytes': len(raw), 'sha256': sha(raw)})
    (root / 'retention.json').write_bytes(encoded({'status': 'RETAINED', 'metadata': rows,
        'metadata_bytes': sum(row['bytes'] for row in rows), 'captures': [], 'fixture': True}))


class RetainedFreshRecords(unittest.TestCase):
    def workspace(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='rf-', dir=local)

    def inspect(self, root, files):
        retain(root, files)
        return validate_fresh(RetainedMetadata(root), commit=COMMIT, source=SOURCE, validator_root=ROOT)

    def test_every_original_receipt_and_all_eighteen_gates(self):
        with self.workspace() as name:
            result = self.inspect(Path(name), fixture())
            self.assertEqual(result['gates'], 18)
            self.assertEqual(result['command_receipts_checked'], 22)
            self.assertEqual(result['fresh_checkout'], CLONE)
            self.assertIs(result['reference_qualified'], False)

    def test_failed_prefix_or_diagnostic_success_cannot_repair_canonical(self):
        for operation in [lambda row: row.update(status='FAIL'),
            lambda row: row['commands'].pop(),
            lambda row: row.update(diagnostic_commands=[{'target': 'demo', 'status': 'PASS'}])]:
            with self.subTest(operation=operation), self.workspace() as name:
                files = fixture(); change(files, ATTEMPT + '/results.json', operation)
                with self.assertRaises(ValueError): self.inspect(Path(name), files)

    def test_complete_manifest_does_not_repair_bad_raw_stream(self):
        with self.workspace() as name:
            files = fixture(); files[ATTEMPT + '/commands/verify/stdout.txt'] = b'Changed after receipt\n'
            with self.assertRaisesRegex(ValueError, 'raw output digest'): self.inspect(Path(name), files)

    def test_source_inventory_must_match_even_when_summary_hash_matches(self):
        with self.workspace() as name:
            files = fixture()
            change(files, ATTEMPT + '/commands/bootstrap/receipt.json',
                lambda row: row['source_before'].update(files=[]))
            with self.assertRaisesRegex(ValueError, 'source/status'): self.inspect(Path(name), files)

    def test_original_linux_clean_status_and_integer_exit_are_required(self):
        mutations = [lambda row: row.update(exit_code=False),
            lambda row: row['environment'].update(system='Windows'),
            lambda row: row['git'].update(dirty=True),
            lambda row: row['process_cleanup'].update(remaining_active_processes=False)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.workspace() as name:
                files = fixture(); change(files, ATTEMPT + '/commands/bootstrap/receipt.json', mutation)
                with self.assertRaises(ValueError): self.inspect(Path(name), files)

    def test_gate_receipt_hash_and_order_must_be_original(self):
        for operation in [lambda row: row['commands'][5].update(receipt_sha256='d' * 64),
            lambda row: row['commands'].reverse(), lambda row: row['commands'].pop()]:
            with self.subTest(operation=operation), self.workspace() as name:
                files = fixture(); change(files, CLONE + '/.local-runs/verify-ledger/ledger.json', operation)
                with self.assertRaises(ValueError): self.inspect(Path(name), files)

    def test_reordered_enclosing_or_outside_gate_intervals_fail(self):
        for path in [ATTEMPT + '/commands/demo/receipt.json',
            CLONE + '/.local-runs/verify-ledger/commands/contracts/receipt.json']:
            with self.subTest(path=path), self.workspace() as name:
                files = fixture(); change(files, path, lambda row: row.update(started_utc=timestamp(0)))
                # Keep the ledger hash coherent: the interval itself must fail.
                if '/verify-ledger/' in path:
                    change(files, CLONE + '/.local-runs/verify-ledger/ledger.json',
                        lambda row: row['commands'][0].update(receipt_sha256=sha(files[path])))
                with self.assertRaisesRegex(ValueError, 'interval'): self.inspect(Path(name), files)

    def test_ambiguous_fresh_attempt_is_never_selected_by_timestamp(self):
        with self.workspace() as name:
            files = fixture(); files['.local-runs/clean-second/results.json'] = files[ATTEMPT + '/results.json']
            with self.assertRaisesRegex(ValueError, 'exactly one'): self.inspect(Path(name), files)

    def test_duplicate_and_traversing_manifest_paths_rejected(self):
        for operation in [lambda row: row['metadata'].append(copy.deepcopy(row['metadata'][0])),
            lambda row: row['metadata'][0].update(file='metadata/../escape')]:
            with self.subTest(operation=operation), self.workspace() as name:
                root = Path(name); retain(root, fixture()); path = root / 'retention.json'
                row = json.loads(path.read_bytes()); operation(row); path.write_bytes(encoded(row))
                with self.assertRaises(ValueError): RetainedMetadata(root)

    def test_final_manifest_and_byte_stability_are_rechecked(self):
        with self.workspace() as name:
            root = Path(name); retain(root, fixture()); view = RetainedMetadata(root)
            (root / 'retention.json').write_bytes(b'{"status":"RETAINED"}\n')
            with self.assertRaisesRegex(ValueError, 'manifest changed'): view.unchanged()

    def test_absent_malformed_duplicate_or_boolean_input_provenance_is_rejected(self):
        entry = {'path': '/work/c/input.json', 'sha256': 'd' * 64, 'bytes': 0}
        mutations = [lambda row: (row.pop('inputs_before'), row.pop('inputs_after')),
            lambda row: row.update(inputs_before={}, inputs_after={}),
            lambda row: row.update(inputs_before=[entry, entry], inputs_after=[entry, entry]),
            lambda row: row.update(inputs_before=[entry], inputs_after=[{**entry, 'bytes': False}]),
            lambda row: row.update(inputs_before=[{**entry, 'sha256': 'unknown'}],
                inputs_after=[{**entry, 'sha256': 'unknown'}]),
            lambda row: row.pop('stdin')]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.workspace() as name:
                files = fixture(); change(files, ATTEMPT + '/commands/bootstrap/receipt.json', mutation)
                with self.assertRaises(ValueError): self.inspect(Path(name), files)

    def test_post_index_growth_is_rejected_before_unbounded_read(self):
        with self.workspace() as name:
            root = Path(name); retain(root, fixture()); metadata = RetainedMetadata(root)
            source = ATTEMPT + '/commands/bootstrap/stdout.txt'; path = root / metadata.rows[source]['file']
            path.write_bytes(b'G' * (1024**2)); observed = []; original = Path.read_bytes
            def read(current):
                if current == path: observed.append(current.stat().st_size)
                return original(current)
            with patch.object(Path, 'read_bytes', read):
                with self.assertRaises(ValueError): metadata.raw(source)
            self.assertEqual(observed, [])

    def test_manifest_and_retained_metadata_use_only_bounded_descriptor_reads(self):
        with self.workspace() as name:
            root = Path(name); retain(root, fixture())
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('unbounded metadata read')):
                checked = validate_fresh(RetainedMetadata(root), commit=COMMIT, source=SOURCE, validator_root=ROOT)
            self.assertEqual(checked['command_receipts_checked'], 22)


if __name__ == '__main__': unittest.main()
