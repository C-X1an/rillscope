"""Literal Git trust/stream controls; no privileged command is executed here."""
import ast
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_guest_owner as owner


def actual_nonroot_fixture_prefix(root, home, command):
    """Relocate only ROOT/HOME in the actual pure prefix function."""
    program = ast.parse((ROOT / 'scripts/canonical_reference_guest_owner.py').read_text(encoding='utf-8'))
    functions = [node for node in program.body if isinstance(node, ast.FunctionDef) and node.name == 'nonroot']
    if len(functions) != 1: raise AssertionError('one actual nonroot function required')
    program = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
    scope = {'ROOT': root, 'HOME': home}
    exec(compile(program, '<actual nonroot prefix with fixture constants>', 'exec'), scope)
    return scope['nonroot'](command)


class ExactGitTrust(unittest.TestCase):
    def test_exact_source_and_git_directory_are_the_only_two_child_trust_entries(self):
        root, home = PurePosixPath('/synthetic/source'), PurePosixPath('/synthetic/home')
        command = actual_nonroot_fixture_prefix(root, home, ['/usr/bin/git', 'clone', '--no-local'])
        self.assertEqual(command[:6], ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--', '/usr/bin/env'])
        entries = [value for value in command[6:] if value.startswith('GIT_CONFIG_')]
        self.assertEqual(entries, ['GIT_CONFIG_COUNT=2', 'GIT_CONFIG_KEY_0=safe.directory',
            'GIT_CONFIG_VALUE_0=/synthetic/source', 'GIT_CONFIG_KEY_1=safe.directory',
            'GIT_CONFIG_VALUE_1=/synthetic/source/.git'])
        self.assertNotIn('*', '\n'.join(command))
        self.assertFalse(any('safe.directory' in value and value.startswith('--') for value in command))
        self.assertEqual(command[-3:], ['/usr/bin/git', 'clone', '--no-local'])

    def test_fixture_executes_the_exact_existing_function_with_only_constants_relocated(self):
        command = ['/usr/bin/git', 'status', '--porcelain']
        self.assertEqual(actual_nonroot_fixture_prefix(owner.ROOT, owner.HOME, command), owner.nonroot(command))


class GitFailureStreams(unittest.TestCase):
    def observe(self, execute):
        source = ast.parse((ROOT / 'tests/system/canonical_handoff_permissions.py').read_text(encoding='utf-8'))
        selected = [node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == 'run_git_control']
        self.assertEqual(len(selected), 1)
        scope = {'base64': base64, 'hashlib': hashlib, 'json': json, 'ROOT': ROOT,
            'subprocess': SimpleNamespace(run=execute, TimeoutExpired=subprocess.TimeoutExpired)}
        exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
            '<actual Git-control observation function>', 'exec'), scope)
        captured = io.StringIO(); result = error = None; command = ['/usr/bin/git', 'SYNTHETIC; NEVER EXECUTED']
        with contextlib.redirect_stdout(captured):
            try: result = scope['run_git_control']('literal-case', command)
            except subprocess.TimeoutExpired as value: error = value
        rows = [json.loads(line)['canonical_git_child_observation'] for line in captured.getvalue().splitlines()]
        self.assertEqual(len(rows), 1)
        row = rows[0]; self.assertEqual(row['command'], command); self.assertEqual(row['case'], 'literal-case')
        self.assertEqual(row['timeout_seconds'], 10)
        self.assertEqual(row['prefix_source_sha256'],
            hashlib.sha256((ROOT / 'scripts/canonical_reference_guest_owner.py').read_bytes()).hexdigest())
        return result, error, row

    def stream(self, row, name, expected):
        self.assertEqual(base64.b64decode(row[name]['base64'], validate=True), expected)
        self.assertEqual(row[name]['sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(row[name]['bytes'], len(expected))

    def test_nonzero_git_and_invalid_utf8_streams_are_retained_without_repairing_exit(self):
        stdout, stderr = b'GIT OUT\n\xff', b'GIT ERR\n\xfe'
        def execute(command, **options):
            self.assertEqual(options, {'cwd': '/', 'capture_output': True, 'timeout': 10, 'check': False})
            return subprocess.CompletedProcess(command, 128, stdout, stderr)
        result, error, row = self.observe(execute)
        self.assertIsNone(error); self.assertEqual(result.returncode, 128)
        self.assertEqual(row['returncode'], 128); self.assertEqual(row['outcome'], 'EXECUTED')
        self.stream(row, 'stdout', stdout); self.stream(row, 'stderr', stderr)

    def test_git_timeout_retains_partial_bytes_and_reraises_the_same_exception(self):
        stdout, stderr = b'PARTIAL OUT\n', b'PARTIAL ERR\n\xff'
        failure = subprocess.TimeoutExpired(['synthetic-only'], 10, output=stdout, stderr=stderr)
        def execute(*args, **kwargs): raise failure
        result, error, row = self.observe(execute)
        self.assertIsNone(result); self.assertIs(error, failure)
        self.assertIsNone(row['returncode']); self.assertEqual(row['outcome'], 'TIMEOUT')
        self.stream(row, 'stdout', stdout); self.stream(row, 'stderr', stderr)

    def test_git_timeout_without_output_truthfully_retains_empty_bytes(self):
        failure = subprocess.TimeoutExpired(['synthetic-only'], 10)
        def execute(*args, **kwargs): raise failure
        result, error, row = self.observe(execute)
        self.assertIsNone(result); self.assertIs(error, failure); self.assertEqual(row['outcome'], 'TIMEOUT')
        self.stream(row, 'stdout', b''); self.stream(row, 'stderr', b'')


if __name__ == '__main__': unittest.main()
