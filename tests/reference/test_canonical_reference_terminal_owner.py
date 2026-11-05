"""Synthetic original-owner records; no process, VM or canonical run executed."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
from canonical_reference_terminal_owner import validate_terminal_owner

SOURCE = {'sha256': 'b' * 64, 'files': [['fixture.rs', 'c' * 64]]}
COMMIT = 'a' * 40
NATIVE = '/home/runner/work/rillscope/rillscope'


def raw(value): return (json.dumps(value, indent=2) + '\n').encode()
def sha(value): return hashlib.sha256(value).hexdigest()
def write(path, value): path.write_bytes(raw(value))


def fixture(root):
    artifact, owner = root / 'attempt', root / 'enclosing'
    artifact.mkdir(); owner.mkdir()
    plan = {'schema_version': 1, 'method': 'rillscope-controller-owned-canonical-reference-v1', 'mode': 'canonical',
        'commit': COMMIT, 'source_sha256': SOURCE['sha256'], 'provision_seconds': 120,
        'prepare_seconds': 180, 'vm_seconds': 20040, 'guest_setup_seconds': 900,
        'guest_tail_seconds': 60, 'guest_retention_seconds': 180, 'recovery_seconds': 300,
        'cleanup_reserve_seconds': 120, 'whole_seconds': 20880}
    plan_raw = raw(plan); (artifact / 'declared-plan.json').write_bytes(plan_raw)
    result = {'schema_version': 1, 'method': plan['method'], 'mode': 'canonical',
        'status': 'COLLECTED CANONICAL ATTEMPT', 'commit': COMMIT, 'source_sha256': SOURCE['sha256'],
        'plan_sha256': sha(plan_raw), 'reference_qualified': False, 'all_record_validation': 'NOT RUN',
        'provider_fit': 'NOT ESTABLISHED', 'started_monotonic_ns': 100 * 10**9,
        'deadline_monotonic_ns': 20980 * 10**9, 'result_persistence_completed_monotonic_ns': 19010500 * 10**6,
        'finished_monotonic_ns': 19011 * 10**9, 'elapsed_seconds': 18911.0,
        'cleanup': {'status': 'PASS', 'remaining_active_processes': 0},
        'recovery_budget': {'status': 'DECLARED BUDGET AVAILABLE', 'declared_seconds': 300,
            'available_preservation_seconds': 300.0, 'started_monotonic_ns': 19000 * 10**9,
            'completed_monotonic_ns': 19010 * 10**9, 'actual_deadline_monotonic_ns': 19300 * 10**9,
            'declared_deadline_monotonic_ns': 19300 * 10**9}, 'fixture': 'No collector executed'}
    write(artifact / 'driver-result.json', result)
    stdout, stderr = b'SYNTHETIC ORIGINAL OWNER OUTPUT; no execution\n', b''
    (owner / 'stdout.txt').write_bytes(stdout); (owner / 'stderr.txt').write_bytes(stderr)
    entry = {'path': NATIVE + '/.local-runs/plan.json', 'sha256': sha(plan_raw), 'bytes': len(plan_raw)}
    proof = {'schema_version': 1, 'command': ['/usr/bin/python3', NATIVE + '/scripts/run_canonical_reference.py',
        '--config', '.local-runs/plan.json', '--out', '.local-runs/canonical', '--run-as', 'runner'],
        'cwd': NATIVE, 'source_before': copy.deepcopy(SOURCE), 'source_after_sha256': SOURCE['sha256'],
        'verification_status': 'PASS', 'exit_code': 0, 'execution_outcome': 'EXECUTED',
        'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0},
        'environment': {'system': 'Linux'}, 'git': {'commit': COMMIT, 'dirty': False},
        'started_utc': '2026-10-25T00:00:00+00:00', 'finished_utc': '2026-10-25T05:15:12+00:00',
        'elapsed_seconds': 18912.0, 'inputs_before': [entry], 'inputs_after': [entry.copy()], 'stdin': None,
        'stdout': {'file': 'stdout.txt', 'sha256': sha(stdout)}, 'stderr': {'file': 'stderr.txt', 'sha256': sha(stderr)},
        'fixture': 'Literal receipt, not an executed owner'}
    write(owner / 'receipt.json', proof)
    return artifact, owner / 'receipt.json'


class OriginalTerminalOwner(unittest.TestCase):
    def workspace(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='to-', dir=local)

    def check(self, artifact, proof): return validate_terminal_owner(artifact, proof, source=SOURCE)

    def test_original_terminal_receipt_plan_and_post_persistence_clocks(self):
        with self.workspace() as name:
            artifact, proof = fixture(Path(name)); checked = self.check(artifact, proof)
            self.assertEqual(checked['status'], 'CHECKED ORIGINAL TERMINAL OWNER')
            self.assertEqual(checked['actual_enclosing_seconds'], 18912.0)
            self.assertEqual(checked['original_output'], NATIVE + '/.local-runs/canonical')
            self.assertIs(checked['reference_qualified'], False)

    def test_no_terminal_owner_receipt_cannot_be_replaced_by_collector_status(self):
        with self.workspace() as name:
            artifact, proof = fixture(Path(name)); proof.unlink()
            with self.assertRaises(OSError): self.check(artifact, proof)

    def test_actual_outer_overrun_or_boolean_exit_never_passes(self):
        for mutation in [lambda row: row.update(elapsed_seconds=20881.0), lambda row: row.update(exit_code=False),
            lambda row: row.update(verification_status='FAIL')]:
            with self.subTest(mutation=mutation), self.workspace() as name:
                artifact, proof = fixture(Path(name)); row = json.loads(proof.read_bytes()); mutation(row); write(proof, row)
                with self.assertRaises(ValueError): self.check(artifact, proof)

    def test_original_plan_requires_exact_fingerprinted_input_bytes(self):
        with self.workspace() as name:
            artifact, proof = fixture(Path(name)); row = json.loads(proof.read_bytes())
            row['inputs_before'][0]['sha256'] = row['inputs_after'][0]['sha256'] = 'd' * 64; write(proof, row)
            with self.assertRaisesRegex(ValueError, 'fingerprint'): self.check(artifact, proof)

    def test_whole_clock_cannot_be_renewed_or_missing_terminal_observation(self):
        for mutation in [lambda row: row.update(deadline_monotonic_ns=20981 * 10**9),
            lambda row: row.pop('result_persistence_completed_monotonic_ns'),
            lambda row: row.update(finished_monotonic_ns=20980 * 10**9)]:
            with self.subTest(mutation=mutation), self.workspace() as name:
                artifact, proof = fixture(Path(name)); path = artifact / 'driver-result.json'
                row = json.loads(path.read_bytes()); mutation(row); write(path, row)
                with self.assertRaisesRegex(ValueError, 'clocks/persistence'): self.check(artifact, proof)

    def test_shortened_or_late_recovery_is_failure_even_before_whole_deadline(self):
        for mutation in [lambda row: row.update(status='FAIL'),
            lambda row: row.update(available_preservation_seconds=200.0),
            lambda row: row.pop('completed_monotonic_ns'),
            lambda row: row.update(completed_monotonic_ns=19301 * 10**9)]:
            with self.subTest(mutation=mutation), self.workspace() as name:
                artifact, proof = fixture(Path(name)); path = artifact / 'driver-result.json'
                row = json.loads(path.read_bytes()); mutation(row['recovery_budget']); write(path, row)
                with self.assertRaises(ValueError): self.check(artifact, proof)

    def test_changed_original_output_stream_is_detected(self):
        with self.workspace() as name:
            artifact, proof = fixture(Path(name)); (proof.parent / 'stdout.txt').write_bytes(b'changed\n')
            with self.assertRaisesRegex(ValueError, 'raw output digest'): self.check(artifact, proof)

    def test_other_command_or_unowned_native_configuration_is_rejected(self):
        for mutation in [lambda row: row['command'].__setitem__(1, NATIVE + '/scripts/canonical_reference_diagnostic.py'),
            lambda row: row['command'].__setitem__(3, '/tmp/other-plan.json')]:
            with self.subTest(mutation=mutation), self.workspace() as name:
                artifact, proof = fixture(Path(name)); row = json.loads(proof.read_bytes()); mutation(row); write(proof, row)
                with self.assertRaises(ValueError): self.check(artifact, proof)

    def test_reported_elapsed_cannot_shrink_or_inflate_recorded_monotonic_span(self):
        for reported, outer in [(0.1, 1.0), (18912.0, 18913.0)]:
            with self.subTest(reported=reported, outer=outer), self.workspace() as name:
                artifact, proof = fixture(Path(name)); path = artifact / 'driver-result.json'
                result = json.loads(path.read_bytes()); result['elapsed_seconds'] = reported; write(path, result)
                receipt = json.loads(proof.read_bytes()); receipt['elapsed_seconds'] = outer; write(proof, receipt)
                with self.assertRaisesRegex(ValueError, 'monotonic span'): self.check(artifact, proof)


if __name__ == '__main__': unittest.main()
