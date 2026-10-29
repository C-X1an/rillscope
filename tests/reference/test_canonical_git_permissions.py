"""Literal Git trust/stream controls; no privileged command is executed here."""
import ast
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
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
        self.assertEqual(entries, ['GIT_CONFIG_GLOBAL=/synthetic/canonical-git-trust/config',
            'GIT_CONFIG_COUNT=2', 'GIT_CONFIG_KEY_0=safe.directory',
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


class FixtureGitConfiguration(unittest.TestCase):
    """Real configuration-only Git checks use the current user, without setpriv."""
    def function(self, name, extra=None):
        source = ast.parse((ROOT / 'tests/system/canonical_handoff_permissions.py').read_text(encoding='utf-8'))
        nodes = [node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == name]
        self.assertEqual(len(nodes), 1, 'one actual fixture function required: ' + name)
        scope = dict(extra or {})
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
            '<actual fixture Git configuration function>', 'exec'), scope)
        return scope[name]

    def test_child_command_starts_with_a_closed_restrictive_environment(self):
        command = ['/usr/bin/git', 'config', '--get-all', 'safe.directory']
        self.assertEqual(self.function('fixture_git_command')(command), ['/usr/bin/env', '-i',
            'PATH=/usr/bin:/bin', 'LC_ALL=C', 'GIT_CONFIG_NOSYSTEM=1',
            'GIT_CONFIG_SYSTEM=/dev/null', 'GIT_CONFIG_GLOBAL=/dev/null', *command])
        self.assertEqual(command, ['/usr/bin/git', 'config', '--get-all', 'safe.directory'])

    @contextlib.contextmanager
    def ambient_configuration(self):
        git = shutil.which('git'); self.assertIsNotNone(git, 'real Git is required for configuration controls')
        env = Path(git).parents[1] / 'usr/bin/env.exe' if os.name == 'nt' else Path('/usr/bin/env')
        self.assertTrue(env.is_file(), 'real environment launcher is required')
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='g22-', dir=local) as directory:
            path = Path(directory); home = path / 'h'; home.mkdir(); xdg = path / 'x'; xdg.mkdir()
            system, global_config = path / 's', path / 'g'
            (path / 'empty-child-global').write_bytes(b'')
            for file in (system, global_config): file.write_text('[safe]\n\tdirectory = *\n', encoding='utf-8')
            ambient = {**os.environ, 'GIT_CONFIG_SYSTEM': str(system), 'GIT_CONFIG_GLOBAL': str(global_config),
                'GIT_CONFIG_PARAMETERS': "'safe.directory'='*'", 'GIT_CONFIG_COUNT': '1',
                'GIT_CONFIG_KEY_0': 'safe.directory', 'GIT_CONFIG_VALUE_0': '*',
                'HOME': str(home), 'XDG_CONFIG_HOME': str(xdg)}
            yield git, str(env), ambient, path

    def real_git(self, command, env, ambient, directory):
        # Windows adapts executable spelling and prevents MSYS from rewriting literal POSIX config values.
        # The production Linux command and every expected byte remain unchanged. No UID operation runs.
        adapted = [env if value == '/usr/bin/env' else value for value in command]
        # The pure literal prefix uses a synthetic absolute path. Configuration-only
        # execution binds that one selector to this test's own empty file.
        adapted = ['GIT_CONFIG_GLOBAL=' + str(directory / 'empty-child-global')
            if value == 'GIT_CONFIG_GLOBAL=/synthetic/canonical-git-trust/config' else value for value in adapted]
        if os.name == 'nt' and adapted[:2] == [env, '-i']:
            adapted[2:2] = ['MSYS2_ARG_CONV_EXCL=*', 'MSYS2_ENV_CONV_EXCL=*']
        return subprocess.run(adapted, cwd=directory, env=ambient, capture_output=True, timeout=10, check=False)

    def test_real_git_ignores_ambient_system_global_parameters_and_count(self):
        with self.ambient_configuration() as (git, env, ambient, directory):
            query = [git, 'config', '--get-all', 'safe.directory']
            baseline = self.real_git(query, env, ambient, directory)
            self.assertEqual(baseline.returncode, 0, baseline.stderr)
            self.assertEqual(baseline.stdout.splitlines(), [b'*'] * 4)
            original = {key: ambient[key] for key in ('GIT_CONFIG_SYSTEM', 'GIT_CONFIG_GLOBAL')}
            files = {key: Path(value).read_bytes() for key, value in original.items()}
            result = self.real_git(self.function('fixture_git_command')(query), env, ambient, directory)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b''))
            self.assertEqual({key: Path(value).read_bytes() for key, value in original.items()}, files)

    def test_real_git_effective_trust_has_only_the_two_actual_prefix_entries(self):
        with self.ambient_configuration() as (git, env, ambient, directory):
            root, home = PurePosixPath('/synthetic/source'), PurePosixPath('/synthetic/home')
            # This checks configuration composition only. The Linux gate separately tests UID/ownership.
            command = actual_nonroot_fixture_prefix(root, home,
                [git, 'config', '--null', '--show-origin', '--show-scope', '--get-all', 'safe.directory'])[5:]
            result = self.real_git(self.function('fixture_git_command')(command), env, ambient, directory)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            self.assertEqual(result.stdout, b'command\0command line:\0/synthetic/source\0'
                b'command\0command line:\0/synthetic/source/.git\0')

    def test_all_tiny_git_calls_delegate_to_the_restrictive_fixture_runner(self):
        calls = []
        runner = self.function('run_fixture_git_control', {
            'fixture_git_command': self.function('fixture_git_command'),
            'run_git_control': lambda name, command: calls.append((name, command)) or 'unchanged-result'})
        self.assertEqual(runner('literal-case', ['/usr/bin/git', '--version']), 'unchanged-result')
        self.assertEqual(calls, [('literal-case', ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin',
            'LC_ALL=C', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_SYSTEM=/dev/null',
            'GIT_CONFIG_GLOBAL=/dev/null', '/usr/bin/git', '--version'])])
        source = ast.parse((ROOT / 'tests/system/canonical_handoff_permissions.py').read_text(encoding='utf-8'))
        control = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == 'git_clone_control')
        direct = [node for node in ast.walk(control) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == 'run_git_control']
        self.assertEqual(direct, [], 'fixture calls must not inherit the ambient Git configuration')


if __name__ == '__main__': unittest.main()
