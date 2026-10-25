"""Literal output/time association tests; no native command or full capture."""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import verify_canonical_reference as verifier
from . import test_canonical_reference_retained_fresh as fixtures


def raw(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def sha(value): return hashlib.sha256(value).hexdigest()
EPOCH = dt.datetime(2026, 10, 25, tzinfo=dt.timezone.utc)
def timestamp(seconds): return (EPOCH + dt.timedelta(seconds=seconds)).isoformat()


class Originals:
    def __init__(self):
        self.members = {'owner': {'measurement-config.json': 'config', 'export-config.json': 'export'},
            'allocation': {'reference-host-receipt.json': 'allocation'}}
        self.rows = {'config': b'{}', 'export': b'{}', 'allocation': b'{}'}
    def raw(self, name, limit=16 * 1024**2):
        value = self.rows[name]
        if len(value) > limit: raise ValueError('fixture byte bound exceeded')
        return value


def command_fixture():
    original = Originals(); second = 10**9; source, commit = fixtures.SOURCE, fixtures.COMMIT
    parent = {'canonical_budget_seconds': 60, 'canonical_started_monotonic_ns': 100 * second,
        'canonical_finished_monotonic_ns': 160 * second,
        'native_retention': {'started_monotonic_ns': 161 * second, 'finished_monotonic_ns': 164 * second, 'cutoff_monotonic_ns': 341 * second}}
    inputs = [{'path': '/work/c/.local-runs/' + folder + name, 'bytes': 2, 'sha256': sha(b'{}')}
        for folder, name in [('canonical-allocation/', 'reference-host-receipt.json'),
            ('canonical-attempt/', 'measurement-config.json'), ('canonical-attempt/', 'export-config.json')]]
    prefix = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--', '/usr/bin/env']
    commands = [('canonical', prefix + ['/usr/bin/python3', '/work/c/scripts/clean_verify.py', '--budget-seconds', '60'], 0, 60),
        ('retain-native-binaries', ['/usr/bin/python3', '/work/c/scripts/canonical_reference_binaries.py', '--out',
            '/work/c/.local-runs/canonical-attempt/native-binaries', '--commit', commit, '--source-sha256', source['sha256'],
            '--cutoff-monotonic-ns', str(341 * second)], 61, 62),
        ('retain-canonical', ['/usr/bin/python3', '/work/c/scripts/retain_release.py', '--out', '/work/c/.local-runs/canonical-attempt/retained'], 63, 64)]
    template = json.loads(fixtures.fixture()[fixtures.ATTEMPT + '/commands/bootstrap/receipt.json'])
    for index, (name, command, start, end) in enumerate(commands):
        proof = copy.deepcopy(template)
        proof.update(command=command, cwd='/work/c', started_utc=timestamp(start), finished_utc=timestamp(end), elapsed_seconds=1.0,
            inputs_before=sorted(inputs, key=lambda row: row['path']) if index == 0 else inputs[:1],
            inputs_after=sorted(inputs, key=lambda row: row['path']) if index == 0 else inputs[:1],
            stdout={'file': 'stdout.txt', 'sha256': sha(b'{}')}, stderr={'file': 'stderr.txt', 'sha256': sha(b'')})
        for leaf, value in [('receipt.json', raw(proof)), ('stdout.txt', b'{}'), ('stderr.txt', b'')]:
            path = 'commands/' + name + '/' + leaf; original.members['owner'][path] = path; original.rows[path] = value
    prerequisites = {'owner': parent, 'seed': {'commit': commit}, 'recovered': original,
        'version_proofs': [{'command': prefix + ['rustup', '--version'], 'started_utc': timestamp(-40), 'finished_utc': timestamp(-39)}],
        'setup': {'started_monotonic_ns': 50 * second, 'finished_monotonic_ns': 99 * second}}
    controls = {'config_sha256': sha(b'{}'), 'export_sha256': sha(b'{}'),
        'events': [{'phase': 'prefix-start', 'monotonic_ns': 100 * second, 'utc_ns': verifier.utc_ns(timestamp(0))}]}
    return prerequisites, {'receipt_sha256': sha(b'{}')}, controls


def change_receipt(original, name, operation):
    path = 'commands/' + name + '/receipt.json'; proof = json.loads(original.rows[path]); operation(proof); original.rows[path] = raw(proof)


class CanonicalCommandBindings(unittest.TestCase):
    def check(self, prerequisites, allocation, controls):
        return verifier.check_canonical_commands(prerequisites, allocation, controls, source=fixtures.SOURCE)

    def test_realistic_bounded_command_receipt_envelopes_and_correlated_guest_clocks(self):
        prerequisites, allocation, controls = command_fixture(); proofs = self.check(prerequisites, allocation, controls)
        self.assertEqual(len(proofs), 3); verifier.check_recorded_utc_intervals(prerequisites, controls, proofs)

    def test_hour_long_canonical_or_day_separated_retention_do_not_fit_original_intervals(self):
        for target, mutate in [('canonical', lambda proof: proof.update(finished_utc=timestamp(3600))),
            ('retain-canonical', lambda proof: proof.update(started_utc=timestamp(86463), finished_utc=timestamp(86464)))]:
            prerequisites, allocation, controls = command_fixture(); change_receipt(prerequisites['recovered'], target, mutate)
            with self.subTest(target=target), self.assertRaises(ValueError): self.check(prerequisites, allocation, controls)

    def test_hash_correct_non_json_stdout_is_rejected_at_command_stage(self):
        prerequisites, allocation, controls = command_fixture(); original = prerequisites['recovered']; value = b'not JSON\n'
        original.rows['commands/canonical/stdout.txt'] = value
        change_receipt(original, 'canonical', lambda proof: proof['stdout'].update(sha256=sha(value)))
        with self.assertRaises(ValueError): self.check(prerequisites, allocation, controls)

    def test_day_shifted_commands_cannot_borrow_an_unrelated_guest_clock_epoch(self):
        prerequisites, allocation, controls = command_fixture(); proofs = self.check(prerequisites, allocation, controls)
        for proof in proofs:
            proof['started_utc'] = (verifier.instant(proof['started_utc']) + dt.timedelta(days=1)).isoformat()
            proof['finished_utc'] = (verifier.instant(proof['finished_utc']) + dt.timedelta(days=1)).isoformat()
        with self.assertRaisesRegex(ValueError, 'correlated guest'): verifier.check_recorded_utc_intervals(prerequisites, controls, proofs)

    def bind(self, transform=None, bounds=None, stdout=None, progress=b''):
        files = fixtures.fixture(); result = json.loads(files[fixtures.ATTEMPT + '/results.json'])
        if transform: transform(result)
        value = progress + json.dumps(result, indent=3).encode() + b'\n' if stdout is None else stdout
        original = Originals(); original.members['owner']['commands/canonical/stdout.txt'] = 'stdout'; original.rows['stdout'] = value
        proofs = [{'started_utc': timestamp(-1), 'finished_utc': timestamp(2520)}]
        if bounds: bounds(proofs[0])
        with tempfile.TemporaryDirectory(prefix='rill-clean-binding-unit-') as name:
            root = Path(name).resolve(); retained = root / '.local-runs/retained'; retained.mkdir(parents=True); fixtures.retain(retained, files)
            with patch.object(archive_capture, 'ROOT', root):
                metadata = verifier.RetainedMetadata(retained)
                fresh = verifier.validate_fresh(metadata, commit=fixtures.COMMIT, source=fixtures.SOURCE, validator_root=ROOT)
                return verifier.bind_clean_output({'recovered': original}, proofs, metadata, fresh, source=fixtures.SOURCE)

    def test_original_parsed_clean_output_binds_all22_intervals_despite_whitespace(self):
        row = self.bind(); self.assertEqual(row['status'], 'CHECKED ORIGINAL CLEAN STDOUT AND22 INTERVALS')
        self.assertIs(row['reference_qualified'], False)

    def test_unchanged_nested_make_evidence_progress_precedes_the_final_clean_report(self):
        progress = b'make: Entering original clone\n{"receipt":"nested","exit_code":0}\ncompiler progress\n'
        row = self.bind(progress=progress)
        self.assertEqual(row['status'], 'CHECKED ORIGINAL CLEAN STDOUT AND22 INTERVALS')

    def test_another_valid_clean_result_cannot_replace_the_selected_original_result(self):
        with self.assertRaisesRegex(ValueError, 'differs from selected retained'):
            self.bind(transform=lambda row: row.update(elapsed_seconds=1234.5))

    def test_success_shape_cannot_hide_fresh_intervals_outside_direct_canonical_command(self):
        for bounds in [lambda row: row.update(started_utc=timestamp(1)), lambda row: row.update(finished_utc=timestamp(2400))]:
            with self.subTest(bounds=bounds), self.assertRaisesRegex(ValueError, 'outside original canonical direct'):
                self.bind(bounds=bounds)

    def test_non_object_duplicate_keys_and_nonfinite_stdout_are_never_original_results(self):
        for value in [b'[]', b'{"status":"PASS","status":"FAIL"}', b'{"elapsed_seconds":NaN}']:
            with self.subTest(value=value), self.assertRaises(ValueError): self.bind(stdout=value)


if __name__ == '__main__': unittest.main()
