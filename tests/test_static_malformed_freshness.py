"""Synthetic provenance units only; no compilation or malformed-input campaign."""
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
from evidence import source_identity
import release_audit

def digest(data): return hashlib.sha256(data).hexdigest()

class StaticMalformedFreshness(unittest.TestCase):
    def setUp(self):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / '.local-runs')
        self.root = Path(self.temporary.name).resolve()
        # Mirror filenames with inert literal fixture bytes, independently of
        # required_sources. Nothing in this temporary tree is ever executed.
        self.names = {name for name, _ in source_identity(ROOT)['files'] if
            (name.startswith(('src/', 'scripts/', 'benchmarks/', 'tools/', 'tests/', '.github/'))
             and Path(name).suffix in {'.rs', '.py', '.yml', '.yaml'})
            or name in {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'Makefile',
                'deny.toml', 'ACCEPTANCE_SPEC.md', 'spec/acceptance.json', 'verification/spec-lock.json'}}
        for name in self.names:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'SYNTHETIC METADATA FILE; NEVER EXECUTED\n')
        (self.root / 'spec/acceptance.json').write_bytes((ROOT / 'spec/acceptance.json').read_bytes())
        self.index = {'criteria': {row['id']: {'status': 'NOT RUN', 'runs': [],
            'scope': 'synthetic bookkeeping fixture only'} for row in json.loads(
                (ROOT / 'spec/acceptance.json').read_bytes())['criteria']}, 'artifacts': {}}
        self.sources = self.snapshot()

    def tearDown(self): self.temporary.cleanup()

    def snapshot(self):
        return [[name, digest((self.root / name).read_bytes())] for name in sorted(self.names)
                if (self.root / name).is_file()]

    def artifact(self, name, kind, sources=None):
        observation = {'status': 'PASS', 'failures': 0, 'cases': 2000,
            'cases_by_format': {'json': 1000, 'sql': 1000}, 'binary_sha256': 'd' * 64}
        value = {'purpose': 'SYNTHETIC METADATA UNIT; NO RUNTIME QUALIFICATION',
            'status': 'PASS', 'exit_code': 0, 'source_before_sha256': 'a' * 64,
            'source_after_sha256': 'a' * 64, 'raw_stdout_sha256': 'b' * 64,
            'raw_stderr_sha256': 'c' * 64, 'source_files': copy.deepcopy(sources or self.sources),
            'executed_targets': ['fmt', 'lint', 'check', 'test'] if kind == 'static' else [],
            'observations': [] if kind == 'static' else [observation]}
        name = 'synthetic-' + name
        relative = 'verification/product/runs/' + name + '.json'
        path = self.root / relative; path.parent.mkdir(parents=True, exist_ok=True)
        self.assertFalse(path.exists(), 'preserve each synthetic input version')
        path.write_text(json.dumps(value), encoding='utf-8')
        self.index['artifacts'][name] = {'path': relative, 'sha256': digest(path.read_bytes())}
        return name

    def select(self, names): self.index['criteria']['AC-025'].update(status='PASS', runs=names)

    def audit(self):
        lines = []
        for identifier, row in self.index['criteria'].items():
            links = ', '.join('[' + name + '](' + self.index['artifacts'][name]['path'] + ')'
                for name in row['runs']) or row['scope']
            lines.append('| C-' + identifier[3:] + ': fixture | fixture | fixture | '
                         + links + ' | ' + row['status'] + ' |')
        (self.root / 'CLAIMS_EVIDENCE.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        with patch.object(release_audit, 'ROOT', self.root): return release_audit.audit(self.index)

    def stale(self, report):
        return [item for item in report['stale_required_sources'] if item.startswith('AC-025:')]

    def proofs(self):
        names = [self.artifact('static', 'static'), self.artifact('malformed', 'malformed')]
        self.select(names)
        self.assertEqual(self.audit()['errors'], [])
        self.assertEqual(self.stale(self.audit()), [])
        return names

    def test_actual_closure_includes_build_static_and_malformed_execution_inputs(self):
        expected = {'Makefile', 'rust-toolchain.toml', 'src/bin/rillscope-measure.rs', 'src/seed.rs',
            'scripts/lint_reference.py', 'scripts/required_gate.py', 'scripts/product_build.py',
            'benchmarks/build.py', 'scripts/evidence.py', 'scripts/owned_process.py',
            'scripts/release_audit.py', 'scripts/evidence_coverage.py',
            'tests/security/malformed.py', 'tests/acceptance_locked/product_helpers.py'}
        self.assertTrue(expected <= evidence_coverage.required_sources('AC-025', ROOT))

    def test_complete_current_subjects_remain_current_after_unrelated_prose(self):
        self.proofs(); (self.root / 'README.md').write_text('Unrelated illustrative prose.\n', encoding='utf-8')
        result = self.audit(); self.assertEqual(result['errors'], []); self.assertEqual(self.stale(result), [])
        self.assertFalse(result['all_declared_criteria_have_current_passing_evidence_links'])

    def test_both_old_subjects_reject_after_rust_change(self):
        self.proofs(); (self.root / 'src/lib.rs').write_bytes(b'changed Rust fixture\n')
        self.assertTrue(self.stale(self.audit()))

    def test_current_static_cannot_refresh_old_malformed_campaign(self):
        names = self.proofs(); (self.root / 'src/lib.rs').write_bytes(b'changed Rust fixture\n')
        self.select([self.artifact('current-static', 'static', self.snapshot()), names[1]])
        self.assertTrue(self.stale(self.audit()))

    def test_current_malformed_cannot_refresh_old_static_checks(self):
        names = self.proofs(); (self.root / 'src/lib.rs').write_bytes(b'changed Rust fixture\n')
        self.select([names[0], self.artifact('current-malformed', 'malformed', self.snapshot())])
        self.assertTrue(self.stale(self.audit()))

    def fragmented_subject(self, kind):
        self.proofs(); old = dict(self.sources)
        for name in ['src/lib.rs', 'src/main.rs']: (self.root / name).write_bytes(b'changed Rust fixture\n')
        current = dict(self.snapshot()); left = dict(current); right = dict(current)
        left['src/lib.rs'] = old['src/lib.rs']; right['src/main.rs'] = old['src/main.rs']
        other = 'malformed' if kind == 'static' else 'static'
        self.select([self.artifact('current-' + other, other, sorted(current.items())),
            self.artifact(kind + '-left', kind, sorted(left.items())),
            self.artifact(kind + '-right', kind, sorted(right.items()))])
        self.assertTrue(self.stale(self.audit()))

    def test_two_incomplete_static_maps_cannot_mosaic_a_current_subject(self): self.fragmented_subject('static')

    def test_two_incomplete_malformed_maps_cannot_mosaic_a_current_subject(self): self.fragmented_subject('malformed')

    def test_changed_malformed_campaign_helper_stales_the_criterion(self):
        self.proofs(); (self.root / 'tests/security/malformed.py').write_bytes(b'changed campaign fixture\n')
        self.assertTrue(self.stale(self.audit()))

    def test_changed_build_recipe_stales_the_criterion(self):
        self.proofs(); (self.root / 'Makefile').write_bytes(b'changed static recipe fixture\n')
        self.assertTrue(self.stale(self.audit()))

    def test_deleted_recorded_test_helper_cannot_shrink_the_dependency_set(self):
        self.proofs(); (self.root / 'tests/acceptance_locked/product_helpers.py').unlink()
        self.assertTrue(self.stale(self.audit()))

    def test_deleted_recorded_non_entrypoint_test_remains_a_dependency(self):
        self.proofs(); (self.root / 'tests/test_archive_capture.py').unlink()
        self.assertTrue(self.stale(self.audit()))

if __name__ == '__main__': unittest.main()
