"""Validator unit fixtures are synthetic; none are claimed as performance observations."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
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
import build
from verify import sample_problems
import release_audit


class BenchmarkContracts(unittest.TestCase):
    def test_full_grid_budget_control_and_successful_baseline_are_required(self):
        description = next(row for row in descriptors() if row['id'] == 'B06-tiny-work')
        self.assertEqual(description['expected_product_status'], 'E_BUDGET')
        self.assertEqual(description['expected_oracle_status'], 'OK')
        failed = {'status':'error', 'error':{'code':'E_BUDGET'}}
        oracle = {'status':'error', 'error':{'code':'E_OUTPUT_LIMIT'}}
        triplet = [({'mode': mode, 'phase':'measured', 'repetition':0}, oracle if mode == 'sqlite' else failed) for mode in run.MODES]
        verdict = run.pair_verdict(triplet, {'description':description, 'ordered':False})
        self.assertIn('predetermined independent baseline outcome mismatch', verdict['modes']['sqlite']['problems'])

    def test_terminal_digest_metrics_schema_and_parameters_are_rechecked(self):
        # Explicit unit bytes/metadata; no executable or timing observation is generated.
        value = {'status':'ok', 'schema':[{'name':'x','type':'i64','nullable':False}], 'rows':[[7]]}
        stdout = json.dumps(value).encode()
        hashes = {name + '.json':'a' * 64 for name in ('catalog','context','query','case')}
        measurement = {'implementation':'rust-benchmark', 'synthetic_only':True, 'optimize':True, 'batch_rows':128,
                       'execution_only_ns':10, 'error':None, 'result_sha256':__import__('hashlib').sha256(stdout).hexdigest(),
                       **{name:1 for name in ('load_ns','compile_ns','execution_call_wall_ns','consumed_work','visible_work','peak_reserved_bytes')},
                       **{name + '_sha256':'a' * 64 for name in ('catalog','context','query')}}
        row = {'mode':'rust-on', 'inputs':hashes, 'status':'OK', 'result_digest':run.semantic_digest(value, False), 'execution_only_ns':10}
        row.update({key:value for key,value in measurement.items() if key in run.METRICS})
        description, spec = {'batch_rows':128}, {'ordered':False, 'schema':value['schema']}
        self.assertEqual(sample_problems(row, value, measurement, description, spec, hashes, stdout), [])
        for key, altered, expected in [('result_digest','0' * 64,'semantic digest differs from terminal result'),
                                       ('execution_only_ns',999,'flattened metric differs: execution_only_ns')]:
            broken = dict(row, **{key:altered})
            self.assertIn(expected, sample_problems(broken, value, measurement, description, spec, hashes, stdout))
        for key, altered, expected in [('optimize',False,'measured optimization/batch parameters differ'),
                                       ('batch_rows',1024,'measured optimization/batch parameters differ'),
                                       ('query_sha256','b' * 64,'measurement input hash mismatch: query'),
                                       ('result_sha256','b' * 64,'measurement result hash mismatch')]:
            broken = dict(measurement, **{key:altered})
            self.assertIn(expected, sample_problems(row, value, broken, description, spec, hashes, stdout))

    def test_failed_build_attempt_records_compiler_discovery_and_cargo_failure(self):
        # Mocked launch failures test receipt retention only; no compiler is executed.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); (root / 'Cargo.lock').write_text('unit fixture')
            compiler = root / 'unit-toolchain/bin' / ('rustc.exe' if os.name == 'nt' else 'rustc')
            compiler.parent.mkdir(parents=True); compiler.write_bytes(b'unit fixture, not an executable')
            paths = [root / '.local-runs/probe', root / '.local-runs/cargo']
            with patch.object(build, 'ROOT', root), patch.object(build.subprocess, 'run', side_effect=OSError('unit discovery failure')):
                with self.assertRaises(ValueError): build.build_release(paths[0])
            receipt = json.loads((paths[0] / 'build.json').read_bytes())
            self.assertEqual((receipt['status'], receipt['stage'], receipt['command']), ('FAIL','compiler discovery',['rustc','--print','sysroot']))
            responses = [subprocess.CompletedProcess([],0,str(compiler.parent.parent).encode() + b'\n',b''),
                         subprocess.CompletedProcess([],0,b'rustc 1.99.0 (unit fixture)\n',b''), OSError('unit Cargo launch failure')]
            with patch.object(build, 'ROOT', root), patch.dict(os.environ, {'RUSTC':'unrelated-compiler', 'CARGO_BUILD_RUSTFLAGS':'unit-invalid-flags'}), patch.object(build.subprocess, 'run', side_effect=responses) as launched:
                with self.assertRaises(ValueError): build.build_release(paths[1])
                env = launched.call_args.kwargs['env']
                self.assertEqual(env['RUSTC'], str(compiler))
                self.assertEqual(env['CARGO_ENCODED_RUSTFLAGS'], '')
                self.assertNotIn('CARGO_BUILD_RUSTFLAGS', env)
            receipt = json.loads((paths[1] / 'build.json').read_bytes())
            self.assertEqual((receipt['status'], receipt['stage']), ('FAIL','cargo build'))
            self.assertEqual(receipt['compiler_selection'], 'explicit pinned sysroot executable passed as RUSTC')

    def test_failure_cannot_publish_rows_and_exit_mapping_is_exact(self):
        value = {'version': 1, 'implementation': 'rust-benchmark', 'status': 'error',
                 'error': {'code': 'E_BUDGET', 'stage': 'execute', 'message': 'synthetic unit error'}}
        self.assertEqual(terminal(json.dumps(value).encode(), b'', 3, 'rust-on')['status'], 'error')
        with self.assertRaises(ValueError): terminal(json.dumps(value).encode(), b'', 5, 'rust-on')
        value['rows'] = [[1]]
        with self.assertRaises(ValueError): terminal(json.dumps(value).encode(), b'', 3, 'rust-on')
        with self.assertRaises(ValueError): terminal(b'[]', b'', 3, 'rust-on')

    def test_terminal_schema_retains_bool_integer_and_null_types(self):
        fixture = {'version':1,'implementation':'rust-benchmark','status':'ok',
                   'schema':[{'name':'x','type':'i64','nullable':False}],'rows':[[7]]}
        self.assertEqual(terminal(json.dumps(fixture).encode(), b'', 0, 'rust-on')['rows'], [[7]])
        for rows in ([[True]], [[None]], [[2**63]], [[]]):
            with self.assertRaises(ValueError): terminal(json.dumps(dict(fixture, rows=rows)).encode(), b'', 0, 'rust-on')

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

    def test_cgroup_limits_cannot_masquerade_as_reference_capacity(self):
        actual = {'system':'Linux','machine':'x86_64','logical_processors':4,
                  'physical_memory_bytes':8 * 1024**3,'cpu_model':'unit fixture',
                  'resource_inspection_status':'MEASURED','process_affinity_cpu_count':4,
                  'effective_cpu_capacity':2,'cgroup_memory_limit_bytes':2 * 1024**3}
        receipt = {'source':'actual host allocation and inspection','dedicated':True,
                   'machine':'x86_64','logical_processors':4,'cpu_model':'unit fixture'}
        reasons = host_reasons(actual, receipt)
        self.assertIn('effective Linux CPU capacity/affinity is not four', reasons)
        self.assertIn('effective cgroup memory is below the reference configuration', reasons)

    def test_actual_cgroup_parser_includes_ancestors_and_handles_root_interfaces(self):
        # Filesystem fixture, not an actual Linux host/allocation claim.
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve(); child = base / 'worker'; child.mkdir()
            (base / 'cgroup.controllers').write_text('cpu memory')
            membership = base / 'membership'; membership.write_text('0::/worker\n')
            for name, value in [('cpu.max','200000 100000'),('memory.max',str(2 * 1024**3)),('memory.high','max')]:
                (child / name).write_text(value)
            with patch.object(os, 'sched_getaffinity', return_value={0,1,2,3}, create=True):
                observed = run.effective_linux_resources(base, membership)
            self.assertEqual(observed['resource_inspection_status'], 'MEASURED')
            self.assertEqual(observed['cgroup_v2_ancestor_levels'], 2)
            self.assertEqual(observed['effective_cpu_capacity'], 2)
            self.assertEqual(observed['cgroup_memory_limit_bytes'], 2 * 1024**3)

    def test_stale_functional_executable_source_binding_is_rejected(self):
        # Source/binary bytes are validator unit fixtures, never compiled/executed product evidence.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); (root / 'Cargo.lock').write_text('unit lock')
            source = root / 'lib.rs'; source.write_text('unit source before')
            out = root / '.local-runs/build'; out.mkdir(parents=True)
            executable = root / 'target/debug/unit-artifact'; executable.parent.mkdir(parents=True)
            executable.write_bytes(b'unit binary, not an executable')
            for stream in ('stdout','stderr'): (out / ('cargo.' + stream)).write_bytes(b'unit log')
            (out / 'compiler.stdout').write_bytes(b'rustc 1.99.0 (unit fixture)')
            (out / 'compiler.stderr').write_bytes(b'')
            identity = source_identity(root)
            receipt = {'schema_version':2,'fresh_target_directory':False,'target_directory':'target',
                       'status':'PASS','exit_code':0,'profile':'dev','source':identity,'source_after_sha256':identity['sha256'],
                       'cargo_lock_sha256':sha(root / 'Cargo.lock'),'compiler':'rustc 1.99.0 (unit fixture)',
                       'compiler_selection':'explicit pinned sysroot executable passed as RUSTC',
                       'compiler_configuration':{'RUSTUP_TOOLCHAIN':'1.99.0','RUSTC_WRAPPER':'','RUSTC_WORKSPACE_WRAPPER':'','CARGO_ENCODED_RUSTFLAGS':''},
                       'bins':{'rillscope':{'path':executable.relative_to(root).as_posix(),'sha256':sha(executable),
                                           'actual_profile':{'opt_level':'0','debug_assertions':True,'test':False}}},
                       **{'raw_' + stream + '_sha256':sha(out / ('cargo.' + stream)) for stream in ('stdout','stderr')}}
            receipt.update({'raw_compiler_' + stream + '_sha256':sha(out / ('compiler.' + stream)) for stream in ('stdout','stderr')})
            path = out / 'build.json'; path.write_text(json.dumps(receipt))
            verify_build(path, executable, name='rillscope', profile='dev', root=root)
            source.write_text('unit source with a deliberate regression')
            with self.assertRaisesRegex(ValueError, 'source differs'):
                verify_build(path, executable, name='rillscope', profile='dev', root=root)
            source.write_text('unit source before')
            verify_build(path, executable, name='rillscope', profile='dev', root=root)

    def test_debug_artifact_cannot_be_attributed_to_release(self):
        # Synthetic metadata/bytes exercise the validator; no compiler or binary is executed.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / 'Cargo.lock').write_text('synthetic fixture')
            out = root / '.local-runs/build'; out.mkdir(parents=True)
            executable = out / 'synthetic-artifact'; executable.write_bytes(b'not an executable')
            (out / 'cargo.stdout').write_bytes(b'synthetic unit log'); (out / 'cargo.stderr').write_bytes(b'')
            identity = source_identity(root)
            receipt = {'schema_version': 2, 'fresh_target_directory': True, 'target_directory': out.relative_to(root).as_posix(), 'status': 'PASS', 'exit_code': 0, 'profile': 'release', 'source': identity,
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
