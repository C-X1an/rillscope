"""Validator unit fixtures are synthetic; none are claimed as performance observations."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
sys.path.insert(0, str(ROOT / 'scripts'))
from envelopes import terminal
from process_metrics import measured_child
from reference_gate import host_reasons
from workloads import descriptors, make_catalog, realized_shape
from build import verify_build, sha
from evidence import source_identity
import run
import release_audit


class BenchmarkContracts(unittest.TestCase):
    def test_failure_cannot_publish_rows_and_exit_mapping_is_exact(self):
        value = {'version': 1, 'implementation': 'rust-benchmark', 'status': 'error',
                 'error': {'code': 'E_BUDGET', 'stage': 'execute', 'message': 'synthetic unit error'}}
        self.assertEqual(terminal(json.dumps(value).encode(), b'', 3, 'rust-on')['status'], 'error')
        with self.assertRaises(ValueError): terminal(json.dumps(value).encode(), b'', 5, 'rust-on')
        value['rows'] = [[1]]
        with self.assertRaises(ValueError): terminal(json.dumps(value).encode(), b'', 3, 'rust-on')
        with self.assertRaises(ValueError): terminal(b'[]', b'', 3, 'rust-on')

    def test_real_missing_executable_attempt_has_retained_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); prefix = root / 'probe'
            usage, stdout, stderr = measured_child([str(root / 'missing-executable')], cwd=root, prefix=prefix)
            self.assertNotEqual(usage['exit_code'], 0)
            self.assertEqual(prefix.with_suffix('.stdout').read_bytes(), stdout)
            self.assertEqual(prefix.with_suffix('.stderr').read_bytes(), stderr)
            self.assertGreater(usage['wall_ns'], 0)

    def test_completed_attempt_is_journaled_before_next_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            samples, pairs = io.StringIO(), io.StringIO()
            count = 0
            def fixture(mode, binary, case, description, spec, output, phase, repetition, order, hashes):
                nonlocal count
                count += 1
                if count == 2: raise RuntimeError('deliberate unit interruption, no process launched')
                return {'mode': mode, 'phase': phase, 'repetition': repetition, 'status': 'UNIT FIXTURE', 'problems': ['no runtime observation']}, None
            description = {'id': 'unit-journal', 'family': 'filter', 'rows': 10, 'selectivity': 1, 'null_percent': 0, 'batch_rows': 128}
            with patch.object(run, 'sample', side_effect=fixture):
                with self.assertRaises(RuntimeError): run.execute_case(Path('unused'), description, 20261014, Path(folder), samples, pairs)
            self.assertEqual(len(samples.getvalue().splitlines()), 1)
            self.assertEqual(json.loads(samples.getvalue())['status'], 'UNIT FIXTURE')

    def test_authorized_group_counts_are_realized_for_all_five_seeds(self):
        for identifier in ('B03-g1000', 'B03-g100000'):
            description = next(row for row in descriptors() if row['id'] == identifier)
            for seed in range(20261014, 20261019):
                shape = realized_shape(make_catalog(description, seed))
                self.assertEqual(shape['authorized_distinct_group_values_including_null'], description['groups'])

    def test_equal_complete_sort_keys_and_distinguishing_composites(self):
        for identifier in ('B04-n10000-equal', 'B04-n100000-equal', 'B02-k1000-uniform-composite1', 'B02-k10000-heavy-composite1'):
            description = next(row for row in descriptors() if row['id'] == identifier)
            shape = realized_shape(make_catalog(description, 20261014))
            if description['family'] == 'sort': self.assertEqual(shape['authorized_distinct_complete_sort_keys'], 1)
            else:
                self.assertEqual(shape['authorized_distinct_nonnull_keys'], description['keys'])
                self.assertTrue(shape['first_key_collisions_with_distinct_second_keys'])

    def test_arm_cannot_qualify_as_x86_reference_host(self):
        actual = {'system': 'Linux', 'machine': 'aarch64', 'logical_processors': 4,
                  'physical_memory_bytes': 8 * 1024**3, 'cpu_model': 'synthetic fixture'}
        receipt = {'source': 'actual host allocation and inspection', 'dedicated': True,
                   'machine': 'aarch64', 'logical_processors': 4, 'cpu_model': 'synthetic fixture'}
        self.assertIn('actual reference architecture is not x86_64', host_reasons(actual, receipt))

    def test_debug_artifact_cannot_be_attributed_to_release(self):
        # Synthetic metadata/bytes exercise the validator; no compiler or binary is executed.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / 'Cargo.lock').write_text('synthetic fixture')
            out = root / '.local-runs/build'; out.mkdir(parents=True)
            executable = out / 'synthetic-artifact'; executable.write_bytes(b'not an executable')
            (out / 'cargo.stdout').write_bytes(b'synthetic unit log'); (out / 'cargo.stderr').write_bytes(b'')
            identity = source_identity(root)
            receipt = {'schema_version': 1, 'fresh_target_directory': True, 'target_directory': out.relative_to(root).as_posix(), 'status': 'PASS', 'exit_code': 0, 'profile': 'release', 'source': identity,
                       'source_after_sha256': identity['sha256'], 'cargo_lock_sha256': sha(root / 'Cargo.lock'),
                       'bins': {'rillscope-measure': {'path': executable.relative_to(root).as_posix(), 'sha256': sha(executable),
                                'actual_profile': {'opt_level': '0', 'debug_assertions': True, 'test': False}}},
                       'raw_stdout_sha256': sha(out / 'cargo.stdout'), 'raw_stderr_sha256': sha(out / 'cargo.stderr')}
            path = out / 'build.json'; path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, 'wrong actual build profile'):
                verify_build(path, executable, name='rillscope-measure', root=root)

    def test_unrelated_passing_artifact_cannot_qualify_performance_claim(self):
        index = json.loads((ROOT / 'verification/product/index.json').read_bytes())
        index['criteria']['AC-021'] = {'status': 'PASS', 'runs': ['rust-core-and-contracts'], 'scope': 'deliberate unit corruption'}
        result = release_audit.audit(index)
        self.assertIn('criterion-specific executed observation missing: AC-021', result['errors'])


if __name__ == '__main__': unittest.main()
