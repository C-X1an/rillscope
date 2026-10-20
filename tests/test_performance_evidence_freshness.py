"""Synthetic audit-metadata controls; no benchmark or engine run is represented."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import evidence_coverage
import release_audit

PERFORMANCE = ('AC-021', 'AC-022', 'AC-023')
LIFETIME = 'scripts/kvm_reference_lifetime.py'
COLLECTION = 'scripts/reference_collection.py'


def digest(data): return hashlib.sha256(data).hexdigest()


class PerformanceFreshness(unittest.TestCase):
    def setUp(self):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='pf-', dir=ROOT / '.local-runs')
        self.root = Path(self.temporary.name)
        names = {'src/lib.rs', 'src/bin/rillscope-measure.rs', 'Cargo.toml', 'Cargo.lock',
            'rust-toolchain.toml', 'Makefile', 'deny.toml', 'ACCEPTANCE_SPEC.md',
            'spec/acceptance.json', 'verification/spec-lock.json'}
        for folder, suffixes in [('scripts', {'.py'}), ('benchmarks', {'.py'}),
                                 ('tools', {'.py'}), ('.github', {'.yml', '.yaml'})]:
            names.update(path.relative_to(ROOT).as_posix() for path in (ROOT / folder).rglob('*')
                if path.is_file() and path.suffix in suffixes and '__pycache__' not in path.parts)
        self.names = sorted(names)
        for name in self.names:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'SYNTHETIC AUDIT METADATA FIXTURE; NEVER EXECUTED\n')
        (self.root / 'spec').mkdir(exist_ok=True)
        (self.root / 'spec/acceptance.json').write_bytes((ROOT / 'spec/acceptance.json').read_bytes())
        self.index = {'criteria': {row['id']: {'status': 'NOT RUN', 'runs': [],
            'scope': 'synthetic metadata unit only'} for row in json.loads(
                (ROOT / 'spec/acceptance.json').read_bytes())['criteria']}, 'artifacts': {}}
        self.sources = self.snapshot()

    def tearDown(self): self.temporary.cleanup()

    def snapshot(self):
        return [[name, digest((self.root / name).read_bytes())]
                for name in self.names if (self.root / name).is_file()]

    def artifact(self, name, kind, sources=None):
        # These literal objects exercise provenance bookkeeping only. No real
        # process receipt, timing, user, host allocation or capture is claimed.
        observations = {
            'capture': {'profile': 'full', 'instrumentation_status': 'PASS', 'complete_grid': True,
                'completed_cases': 410, 'invalid_observations': 0, 'independent_semantic_comparisons': 1},
            'full': {'profile': 'full', 'status': 'PASS', 'observations_checked': 43050,
                'cases_checked': 410, 'current_product_source_matches_capture': True,
                'evidence_schema_version': 3, 'build_provenance_status': 'RECORDED',
                'current_release_evidence_qualified': True, 'required_success_cases_checked': 290,
                'independent_semantic_comparisons': 1},
            'null': {'profile': 'sort-null-supplement', 'status': 'PASS', 'observations_checked': 4200,
                'cases_checked': 40, 'current_release_evidence_qualified': True,
                'required_success_cases_checked': 40, 'independent_semantic_comparisons': 2400},
            'reference': {'status': 'PASS', 'reference_host_preflight': {'status': 'READY'},
                'allocation_receipt_stable': True, 'experiment_environment_errors': [],
                'experiment_environments': {key: {} for key in
                    ['grid-start', 'grid-end', 'cancellation-start', 'cancellation-end', 'wrapper-end']},
                'filter_project_target_by_seed': [{'target_status': 'MISSED', 'execution_ns': {'n': 30},
                    'end_to_end_ns': {'n': 30}, 'independent_semantic_comparisons': 60} for _ in range(5)],
                'cancellation_reference_target': {'status': 'MISSED'}}}
        value = {'purpose': 'SYNTHETIC METADATA UNIT; NO RUNTIME QUALIFICATION',
            'status': 'PASS', 'exit_code': 0, 'source_before_sha256': 'a' * 64,
            'source_after_sha256': 'a' * 64, 'raw_stdout_sha256': 'b' * 64,
            'raw_stderr_sha256': 'c' * 64, 'source_files': copy.deepcopy(sources or self.sources),
            'observations': [observations[kind]]}
        name = 'synthetic-' + name
        relative = 'verification/product/runs/' + name + '.json'
        path = self.root / relative; path.parent.mkdir(parents=True, exist_ok=True)
        self.assertFalse(path.exists(), 'preserve every synthetic input version')
        path.write_text(json.dumps(value), encoding='utf-8')
        self.index['artifacts'][name] = {'path': relative, 'sha256': digest(path.read_bytes())}
        return name

    def select(self, identifier, names):
        self.index['criteria'][identifier].update(status='PASS', runs=names)

    def audit(self):
        lines = []
        for identifier, row in self.index['criteria'].items():
            links = ', '.join('[' + name + '](' + self.index['artifacts'][name]['path'] + ')'
                              for name in row['runs']) or row['scope']
            lines.append('| C-' + identifier[3:] + ': fixture | fixture | fixture | '
                         + links + ' | ' + row['status'] + ' |')
        (self.root / 'CLAIMS_EVIDENCE.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        with patch.object(release_audit, 'ROOT', self.root): return release_audit.audit(self.index)

    def full_proofs(self):
        names = [self.artifact('capture', 'capture'), self.artifact('full', 'full'), self.artifact('null', 'null')]
        self.select('AC-021', names)
        return names

    def require_helpers_for_association(self, identifier, root):
        # Force the known dependencies into this unit independently of closure
        # discovery, so an old union defect cannot hide behind a missing path.
        result = evidence_coverage.required_sources(identifier, root)
        return result | {LIFETIME, COLLECTION} if identifier in PERFORMANCE else result

    def stale(self, report, identifier):
        return [item for item in report['stale_required_sources'] if item.startswith(identifier + ':')]

    def test_actual_performance_closure_covers_runtime_lifetime_validation_and_recipes(self):
        expected = {LIFETIME, COLLECTION, 'scripts/kvm_reference_budget.py',
            'scripts/kvm_reference_host.py', 'scripts/kvm_reference_guest.py',
            'scripts/kvm_reference_receiver.py', 'scripts/verify_kvm_reference.py',
            'scripts/reference_capture_export.py', 'scripts/reference_guest_owner.py',
            'scripts/reference_guest_observer.py', 'scripts/reference_measurement_barrier.py',
            'scripts/kvm_benchmark_pilot.py', 'scripts/kvm_pilot_guest.py',
            'scripts/inspect_reference_guest.py', 'scripts/kvm_boot_recovery.py',
            'scripts/guest_resource_probe.py', 'scripts/owned_process.py', 'scripts/evidence.py',
            'scripts/evidence_coverage.py', 'scripts/release_audit.py', 'scripts/product_build.py',
            '.github/workflows/kvm-full-capture.yml', 'Makefile', 'rust-toolchain.toml'}
        for identifier in PERFORMANCE:
            with self.subTest(identifier=identifier):
                self.assertTrue(expected <= evidence_coverage.required_sources(identifier, ROOT))

    def test_changed_lifetime_helper_stales_each_performance_criterion(self):
        self.full_proofs(); reference = self.artifact('reference', 'reference')
        for identifier in ['AC-022', 'AC-023']: self.select(identifier, [reference])
        before = self.audit(); self.assertEqual(before['errors'], [])
        self.assertEqual(before['stale_required_sources'], [])
        self.assertFalse(before['all_declared_criteria_have_current_passing_evidence_links'])
        (self.root / LIFETIME).write_bytes(b'changed lifetime behavior\n')
        after = self.audit()
        for identifier in PERFORMANCE:
            with self.subTest(identifier=identifier): self.assertTrue(self.stale(after, identifier))

    def test_new_null_only_proof_cannot_refresh_old_full_capture_or_validation(self):
        names = self.full_proofs()
        with patch.object(release_audit, 'required_sources', side_effect=self.require_helpers_for_association):
            self.assertEqual(self.audit()['stale_required_sources'], [])
            (self.root / LIFETIME).write_bytes(b'changed lifetime behavior\n')
            self.assertTrue(self.stale(self.audit(), 'AC-021'))
            current_null = self.artifact('current-null', 'null', self.snapshot())
            self.select('AC-021', names[:2] + [current_null])
            after = self.audit()
            self.assertTrue(self.stale(after, 'AC-021'), 'a supplement cannot refresh an older full experiment')

    def test_new_full_proofs_cannot_refresh_old_null_validation(self):
        names = self.full_proofs()
        with patch.object(release_audit, 'required_sources', side_effect=self.require_helpers_for_association):
            (self.root / LIFETIME).write_bytes(b'changed lifetime behavior\n')
            current = self.snapshot()
            capture = self.artifact('current-capture', 'capture', current)
            full = self.artifact('current-full', 'full', current)
            self.select('AC-021', [capture, full, names[-1]])
            self.assertTrue(self.stale(self.audit(), 'AC-021'))

    def test_two_incomplete_full_proofs_cannot_mosaic_a_complete_current_one(self):
        self.full_proofs()
        old = dict(self.sources)
        with patch.object(release_audit, 'required_sources', side_effect=self.require_helpers_for_association):
            for name in [LIFETIME, COLLECTION]: (self.root / name).write_bytes(b'changed behavior\n')
            current = dict(self.snapshot())
            left = dict(current); left[LIFETIME] = old[LIFETIME]
            right = dict(current); right[COLLECTION] = old[COLLECTION]
            capture = self.artifact('current-capture', 'capture', sorted(current.items()))
            null = self.artifact('current-null', 'null', sorted(current.items()))
            full_left = self.artifact('full-left', 'full', sorted(left.items()))
            full_right = self.artifact('full-right', 'full', sorted(right.items()))
            self.select('AC-021', [capture, full_left, full_right, null])
            self.assertTrue(self.stale(self.audit(), 'AC-021'))

    def test_deleted_lifetime_helper_does_not_make_its_dependency_disappear(self):
        self.full_proofs()
        (self.root / LIFETIME).unlink()
        report = self.audit()
        self.assertTrue(self.stale(report, 'AC-021') or any('AC-021' in item for item in report['errors']))

    def test_deleted_recorded_tool_cannot_shrink_an_old_proofs_dependency_set(self):
        self.full_proofs()
        (self.root / 'tools/fixed_scope.py').unlink()
        self.assertTrue(self.stale(self.audit(), 'AC-021'))

    def test_reference_criteria_cannot_mosaic_incomplete_current_runs(self):
        old = dict(self.sources)
        with patch.object(release_audit, 'required_sources', side_effect=self.require_helpers_for_association):
            for name in [LIFETIME, COLLECTION]: (self.root / name).write_bytes(b'changed behavior\n')
            current = dict(self.snapshot())
            left = dict(current); left[LIFETIME] = old[LIFETIME]
            right = dict(current); right[COLLECTION] = old[COLLECTION]
            a = self.artifact('reference-left', 'reference', sorted(left.items()))
            b = self.artifact('reference-right', 'reference', sorted(right.items()))
            for identifier in ['AC-022', 'AC-023']: self.select(identifier, [a, b])
            after = self.audit()
            for identifier in ['AC-022', 'AC-023']:
                with self.subTest(identifier=identifier): self.assertTrue(self.stale(after, identifier))

    def test_current_complete_subjects_remain_current_after_an_unrelated_prose_edit(self):
        self.full_proofs()
        (self.root / 'README.md').write_text('Changed illustrative prose only.\n', encoding='utf-8')
        report = self.audit()
        self.assertEqual(report['errors'], []); self.assertEqual(report['stale_required_sources'], [])
        self.assertFalse(report['all_declared_criteria_have_current_passing_evidence_links'])


if __name__ == '__main__': unittest.main()
