"""Execute workflow declarations and shell boundaries without starting a VM."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
from evidence import source_identity
from run_canonical_reference import validate_plan
from canonical_reference_bundle import CanonicalBundle, MAX_ARCHIVE

WORKFLOW = ROOT / '.github/workflows/kvm-full-capture.yml'
CANONICAL = 'canonical-native'


def selected(expression, mode):
    """Closed evaluator for the small routing expressions used by this workflow."""
    expression = expression.removeprefix('${{').removesuffix('}}').strip()
    tree = ast.parse(expression.replace('&&', ' and ').replace('||', ' or '), mode='eval')
    def value(node):
        if isinstance(node, ast.Expression): return value(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is str: return node.value
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == 'inputs' and node.attr == 'capture_mode': return mode
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == 'always' and not node.args and not node.keywords: return True
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            values = [value(child) for child in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
            left, right = value(node.left), value(node.comparators[0])
            if isinstance(node.ops[0], ast.Eq): return left == right
            if isinstance(node.ops[0], ast.NotEq): return left != right
        raise AssertionError('unsupported workflow routing expression')
    return value(tree)


def inline_python(step):
    command = shlex.split(step['run'])
    if len(command) != 3 or command[:2] != ['python3', '-c']:
        raise AssertionError('closed inline Python command required')
    return command[2]


class CanonicalWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = json.loads(WORKFLOW.read_bytes())
        self.jobs = self.workflow['jobs']
        self.collect = self.jobs['collect-canonical']
        self.validate = self.jobs['validate-canonical']

    def step(self, job, name):
        return next(row for row in job['steps'] if row.get('id') == name)

    def test_legacy_commands_steps_and_budgets_remain_byte_equivalent(self):
        expected = {'collect': '33f6d7d179befac4325a30342d9733c923ba8737c3abd95f261556f4221fa6d9',
                    'validate-all-records': '8d0a8717f97805c97e92040e0cb13215e75f7a59f44cbc5c8246092865131955'}
        for name, digest in expected.items():
            job = copy.deepcopy(self.jobs[name])
            if name == 'collect': del job['if']
            else: job['if'] = '${{ always() }}'
            encoded = json.dumps(job, sort_keys=True, separators=(',', ':')).encode()
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), digest)

    def test_modes_select_one_collection_and_fail_closed_for_unknown_inputs(self):
        input_row = self.workflow['on']['workflow_dispatch']['inputs']['capture_mode']
        self.assertEqual(input_row['options'], ['legacy-full', CANONICAL])
        self.assertEqual(input_row['default'], 'legacy-full')
        self.assertIs(input_row['required'], True)
        expected = {
            '': {'collect', 'validate-all-records'},
            'legacy-full': {'collect', 'validate-all-records'},
            CANONICAL: {'collect-canonical', 'validate-canonical'},
            'unexpected': {'reject-unknown-capture-mode'},
        }
        for mode, wanted in expected.items():
            self.assertEqual({name for name, row in self.jobs.items() if selected(row['if'], mode)}, wanted)
        self.assertRegex(self.jobs['reject-unknown-capture-mode']['steps'][-1]['run'], r'exit 2$')

    def test_actual_inline_source_guards_reject_wrong_empty_and_shell_like_commits(self):
        commit = 'a' * 40
        for job in (self.collect, self.validate):
            step = self.step(job, 'source_guard')
            self.assertIs(job['steps'][0], step)
            self.assertEqual(step['env'], {'EXPECTED_COMMIT': '${{ inputs.expected_commit }}'})
            for given, code in [(commit, 0), ('b' * 40, 1), ('', 1), ("$(echo bad);'x", 1)]:
                result = subprocess.run([sys.executable, '-c', inline_python(step)], capture_output=True,
                    env={**os.environ, 'EXPECTED_COMMIT': given, 'GITHUB_SHA': commit}, timeout=10)
                self.assertEqual(result.returncode, code)

    def plan(self):
        run = self.step(self.collect, 'plan')['run']
        self.assertTrue(run.startswith("mkdir -p .local-runs\npython3 - <<'PY'\n"))
        body, tail = run.split("python3 - <<'PY'\n", 1)[1].split('\nPY', 1)
        self.assertTrue(tail.startswith('\nsudo -n env '))
        self.assertIn('tests/system/canonical_handoff_permissions.py', tail)
        program = body
        with tempfile.TemporaryDirectory(prefix='rill-workflow-plan-unit-') as directory:
            root = Path(directory); (root / '.local-runs').mkdir()
            result = subprocess.run([sys.executable, '-c', program], cwd=root, capture_output=True, timeout=20,
                env={**os.environ, 'GITHUB_SHA': 'a' * 40, 'PYTHONDONTWRITEBYTECODE': '1',
                     'PYTHONPATH': os.pathsep.join([str(ROOT / 'scripts'), str(ROOT / 'benchmarks')])})
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            raw = (root / '.local-runs/canonical-plan.json').read_bytes()
            self.assertTrue(raw.endswith(b'\n'))
            plan = validate_plan(json.loads(raw))
            status = json.loads(result.stdout)
            self.assertEqual(status['status'], 'DECLARED; NOT EXECUTED')
            self.assertIs(status['reference_qualified'], False)
            self.assertEqual(status['provider_fit'], 'NOT ESTABLISHED')
            self.assertEqual(plan['commit'], 'a' * 40)
            self.assertEqual(plan['source_sha256'], source_identity(ROOT)['sha256'])
            return plan

    def test_actual_plan_program_writes_strict_source_bound_json_without_execution(self):
        self.plan()

    def test_declared_sequential_and_wrapper_deadlines_fit_without_claiming_provider_fit(self):
        plan = self.plan()
        for job in (self.collect, self.validate):
            self.assertLessEqual(sum(step['timeout-minutes'] for step in job['steps']), job['timeout-minutes'])
        owner = self.step(self.collect, 'collection')
        outer = int(re.search(r'--timeout (\d+)', owner['run'])[1])
        self.assertLess(plan['whole_seconds'], outer)
        self.assertLess(outer, 60 * owner['timeout-minutes'])
        reserve = sum(plan[key] for key in ('provision_seconds', 'prepare_seconds', 'vm_seconds',
                                           'recovery_seconds', 'cleanup_reserve_seconds'))
        self.assertLessEqual(reserve + 60, plan['whole_seconds'])
        self.assertGreaterEqual(plan['vm_seconds'], 18000)
        retention = self.step(self.collect, 'retention')
        self.assertIn('--budget-seconds 90', retention['run'])
        self.assertIn('--timeout 110', retention['run'])
        self.assertLess(110, 60 * retention['timeout-minutes'])
        validation = next(row for row in self.validate['steps'] if '--budget-seconds' in row.get('run', ''))
        self.assertIn('--budget-seconds 3300', validation['run'])
        self.assertIn('--timeout 3420', validation['run'])
        self.assertLess(3420, 60 * validation['timeout-minutes'])

    def test_retention_shell_preserves_failure_and_publishes_actual_multiline_paths(self):
        run = self.step(self.collect, 'retention')['run']
        lines = run.splitlines()
        self.assertTrue(lines[0].startswith('if sudo -n env ') and lines[0].endswith('; then'))
        self.assertIn('scripts/retain_canonical_reference.py', lines[0])
        # Substitute only the external retention command; execute the unchanged
        # real shell control flow, output framing, path selection and exit.
        lines[0] = 'if sh -c "exit $RILLSCOPE_TEST_RETENTION_STATUS"; then'
        shell = shutil.which('sh')
        self.assertIsNotNone(shell, 'the project requires sh for make/workflow controls')
        for code in (0, 17):
            with tempfile.TemporaryDirectory(prefix='rill-workflow-paths-unit-') as directory:
                output = Path(directory) / 'output'
                result = subprocess.run([shell, '-c', '\n'.join(lines)], capture_output=True, timeout=10,
                    env={**os.environ, 'GITHUB_OUTPUT': output.as_posix(),
                         'RILLSCOPE_TEST_RETENTION_STATUS': str(code)})
                self.assertEqual(result.returncode, code, result.stderr.decode(errors='replace'))
                rows = output.read_text().splitlines()
                self.assertEqual(rows[0], 'upload_paths<<RILLSCOPE_ORIGINAL_PATHS_EOF')
                self.assertEqual(rows[-1], 'RILLSCOPE_ORIGINAL_PATHS_EOF')
                paths = rows[1:-1]
                self.assertIn('.local-runs/canonical-retained.zip', paths)
                if code == 0:
                    self.assertIn('.local-runs/canonical-owner/', paths)
                    self.assertIn('.local-runs/canonical-retention-command/', paths)
                else:
                    self.assertIn('.local-runs/canonical-failure.zip', paths)
                    self.assertIn('.local-runs/canonical-failure.zip.pending', paths)
                self.assertNotIn('.local-runs/canonical-attempt/vm/artifact/', paths)
                self.assertNotIn('.local-runs/canonical-reservations/', paths)
                self.assertFalse(any('/target' in path or '/system' in path or 'qcow2' in path for path in paths))
        upload = self.collect['steps'][-1]
        self.assertEqual(upload['with']['path'], '${{ steps.retention.outputs.upload_paths }}')
        self.assertIn('always()', upload['if'])

    def test_separate_validator_cannot_repair_upstream_failure_or_duplicate_raw_capture(self):
        self.assertEqual(self.validate['needs'], 'collect-canonical')
        guard = next(row for row in self.validate['steps'] if 'ORIGINAL_COLLECTION_RESULT' in row.get('env', {}))
        self.assertIn('always()', guard['if'])
        self.assertEqual(guard['env']['ORIGINAL_COLLECTION_RESULT'], '${{ needs.collect-canonical.result }}')
        for status in ('success', 'failure', 'cancelled', 'skipped'):
            result = subprocess.run([sys.executable, '-c', inline_python(guard)], capture_output=True, timeout=10,
                env={**os.environ, 'ORIGINAL_COLLECTION_RESULT': status})
            self.assertEqual(result.returncode, 0 if status == 'success' else 1)
        paths = self.validate['steps'][-1]['with']['path'].splitlines()
        self.assertIn('.local-runs/canonical-validation/record-inspection.json', paths)
        self.assertFalse(any('expanded' in path or 'canonical-downloaded' in path or 'canonical-retained.zip' in path for path in paths))

    def test_actions_are_pinned_and_credentials_and_runtime_environment_are_scoped(self):
        self.assertEqual(self.workflow['permissions'], {'contents': 'read'})
        for job in (self.collect, self.validate):
            checkout = self.step(job, 'checkout')
            self.assertIs(checkout['with']['persist-credentials'], False)
            for step in job['steps']:
                if 'uses' in step: self.assertRegex(step['uses'], r'^actions/[\w-]+@[0-9a-f]{40}$')
                self.assertNotIn('continue-on-error', step)
        owner = self.step(self.collect, 'collection')['run']
        for name in ('GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
            self.assertIn(name + '="$' + name + '"', owner)
        self.assertIn('GIT_CONFIG_KEY_0=safe.directory', owner)
        self.assertIn('GIT_CONFIG_VALUE_0="$PWD"', owner)
        self.assertIn('PYTHONDONTWRITEBYTECODE=1', owner)
        self.assertNotIn('cargo build', owner)
        self.assertIn('digest-mismatch', self.validate['steps'][2]['with'])
        self.assertEqual(self.validate['steps'][2]['with']['digest-mismatch'], 'error')

    def test_archive_custody_uses_its_512mib_reader_without_the_recorders_256mib_input_cap(self):
        row = next(step for step in self.validate['steps'] if '--archive' in step.get('run', ''))
        args = shlex.split(row['run']); split = args.index('--'); outer, child = args[:split], args[split + 1:]
        self.assertEqual([outer[index + 1] for index, value in enumerate(outer) if value == '--input'],
                         ['.local-runs/canonical-downloaded/canonical-plan.json'])
        self.assertEqual(child[child.index('--archive') + 1], '.local-runs/canonical-downloaded/canonical-retained.zip')
        # Exercise the actual held-reader digest at the full interface bound
        # with one reused1MiB block; this is not a ZIP or a valid capture.
        self.assertEqual(MAX_ARCHIVE, 512 * 1024**2)
        class ReusedStream:
            def seek(self, offset): self.offset = offset
            def read(self, count):
                size = min(count, MAX_ARCHIVE - self.offset)
                self.offset += size
                return block[:size]
        block = b'x' * 1024**2
        reader = CanonicalBundle.__new__(CanonicalBundle)
        reader.stream = ReusedStream(); reader.before = SimpleNamespace(st_size=MAX_ARCHIVE)
        reader.deadline = time.monotonic() + 20
        expected = hashlib.sha256()
        for _ in range(512): expected.update(block)
        self.assertEqual(reader.digest(), expected.hexdigest())

    def test_failed_retention_has_a_separate_bounded_privileged_readable_export(self):
        self.assertIn('failure_handoff', {row.get('id') for row in self.collect['steps']})
        retention = self.step(self.collect, 'retention'); handoff = self.step(self.collect, 'failure_handoff')
        self.assertLess(self.collect['steps'].index(retention), self.collect['steps'].index(handoff))
        self.assertIn("steps.retention.outcome == 'failure'", handoff['if'])
        self.assertIn('always()', handoff['if'])
        self.assertTrue(handoff['run'].startswith('sudo -n env '))
        for value in ('scripts/export_canonical_failure.py', '--owner-receipt .local-runs/canonical-owner/receipt.json',
                      '--budget-seconds 45', '--timeout 55'): self.assertIn(value, handoff['run'])
        self.assertLess(55, 60 * handoff['timeout-minutes'])
        self.assertNotIn('chmod', handoff['run'])


if __name__ == '__main__': unittest.main()
