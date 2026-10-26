"""Guest transport placement and strict synthetic original-proof controls.

Literal records never claim that a Linux command, guest, or product ran.
"""
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]


class GuestControlPlacement(unittest.TestCase):
    def test_host_negative_uses_ownership_checked_discovery(self):
        node = self.function('tests/system/canonical_handoff_permissions.py', 'host_git_directory_command')
        scope = {}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), '<actual pure host command>', 'exec'), scope)
        prefix = ['SYNTHETIC exact one-entry prefix; never executed']
        self.assertEqual(scope['host_git_directory_command'](prefix, PurePosixPath('/synthetic/source')),
            prefix + ['/usr/bin/git', '-C', '/synthetic/source/.git', 'for-each-ref'])
        self.assertEqual(prefix, ['SYNTHETIC exact one-entry prefix; never executed'])

    def function(self, path, name):
        tree = ast.parse((ROOT / path).read_text(encoding='utf-8'))
        found = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
        self.assertEqual(len(found), 1, name + ' must be a mandatory entry point')
        return found[0]

    def test_host_requires_separate_direct_repository_control(self):
        main = self.function('tests/system/canonical_handoff_permissions.py', 'main')
        calls = [n for n in ast.walk(main) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == 'git_clone_control']
        self.assertEqual(len(calls), 1)
        self.assertEqual([(k.arg, ast.literal_eval(k.value)) for k in calls[0].keywords],
            [('transport_regression', False)])
        control = self.function('tests/system/canonical_handoff_permissions.py', 'git_clone_control')
        self.assertIn('host-one-entry-git-directory', [n.value for n in ast.walk(control) if isinstance(n, ast.Constant)])

    def test_guest_requires_owned_runtime_and_original_transport_regression(self):
        guest = self.function('tests/system/canonical_handoff_permissions.py', 'guest_git_main')
        calls = [n for n in ast.walk(guest) if isinstance(n, ast.Call)]
        guard = next((n for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr == 'guard'), None)
        self.assertIsNotNone(guard)
        self.assertEqual(ast.unparse(guard), 'device.guard(0)')
        control = [n for n in calls if isinstance(n.func, ast.Name) and n.func.id == 'git_clone_control']
        self.assertEqual(len(control), 1)
        self.assertEqual(control[0].args + control[0].keywords, [])
        self.assertIn('canonical_guest_git_control', [n.value for n in ast.walk(guest) if isinstance(n, ast.Constant)])

    def test_guest_control_uses_original_setup_deadline_before_native_tools(self):
        setup = self.function('scripts/canonical_reference_guest_setup.py', 'setup')
        calls = [n for n in ast.walk(setup) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'checked']
        named = {n.args[0].value: n for n in calls if n.args and isinstance(n.args[0], ast.Constant)}
        self.assertIn('guest-git-ownership', named)
        self.assertLess(named['apt-install'].lineno, named['guest-git-ownership'].lineno)
        self.assertLess(named['guest-git-ownership'].lineno, named['rustup-init'].lineno)
        self.assertEqual(ast.literal_eval(named['guest-git-ownership'].args[2]), 30)
        self.assertIn('--guest-git-only', ast.unparse(named['guest-git-ownership']))
        checked = next(n for n in ast.walk(setup) if isinstance(n, ast.FunctionDef) and n.name == 'checked')
        self.assertIn('min(timeout, remaining)', ast.unparse(checked))

    def test_both_consumers_require_guest_original_proof(self):
        for path, name in [('scripts/canonical_reference_recovered_records.py', 'validate_prerequisites'),
            ('scripts/canonical_reference_diagnostic.py', 'check_setup_metadata')]:
            with self.subTest(path=path):
                function = self.function(path, name)
                calls = [n.func.id for n in ast.walk(function) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
                self.assertIn('validate_guest_git_proof', calls)


def literal_guest_events():
    """Independent tiny expected transcript; every event is synthetic test data."""
    root = '/tmp/rill-git-permission-SYNTHETIC'; source = root + '/source'; home = root + '/consumer/home'
    capsule = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C',
        'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_SYSTEM=/dev/null', 'GIT_CONFIG_GLOBAL=/dev/null']
    prefix = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--', '/usr/bin/env',
        'HOME=' + home, 'CARGO_HOME=' + home + '/.cargo', 'RUSTUP_HOME=' + home + '/.rustup',
        'CARGO_INCREMENTAL=0', 'PATH=' + home + '/.cargo/bin:/usr/bin:/bin', 'GIT_OPTIONAL_LOCKS=0',
        'GIT_CONFIG_COUNT=2', 'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=' + source,
        'GIT_CONFIG_KEY_1=safe.directory', 'GIT_CONFIG_VALUE_1=' + source + '/.git', 'PYTHONDONTWRITEBYTECODE=1']
    head = b'1234567890abcdef1234567890abcdef12345678\n'
    commands = [('fixture-git-version', ['/usr/bin/git', '--version'], 0, b'git version 2.43.0\n', b'')]
    for name in ('source', 'unrelated'):
        path = root + '/' + name
        commands.extend([
            (name + '-init', ['/usr/bin/git', 'init', '--quiet', '--initial-branch=fixture', '--object-format=sha1',
                '--template=' + root + '/empty-template', path], 0, b'', b''),
            (name + '-add', ['/usr/bin/git', '-C', path, 'add', '--', 'literal.txt'], 0, b'', b''),
            (name + '-commit', ['/usr/bin/env', 'GIT_AUTHOR_DATE=2000-01-01T00:00:00Z', 'GIT_COMMITTER_DATE=2000-01-01T00:00:00Z',
                '/usr/bin/git', '-C', path, '-c', 'user.name=RillScope synthetic fixture', '-c',
                'user.email=fixture@rillscope.invalid', '-c', 'commit.gpgsign=false', '-c',
                'core.hooksPath=' + root + '/empty-template', 'commit', '--quiet', '-m', 'Synthetic permission fixture'], 0, b'', b''),
            (name + '-head', ['/usr/bin/git', '-C', path, 'rev-parse', 'HEAD'], 0, head, b'')])
    trust = b'command\0command line:\0' + source.encode() + b'\0command\0command line:\0' + source.encode() + b'/.git\0'
    old = [v.replace('GIT_CONFIG_COUNT=2', 'GIT_CONFIG_COUNT=1') for v in prefix
        if v not in ('GIT_CONFIG_KEY_1=safe.directory', 'GIT_CONFIG_VALUE_1=' + source + '/.git')]
    commands.extend([
        ('effective-two-entry-trust', prefix + ['/usr/bin/git', 'config', '--null', '--show-origin', '--show-scope', '--get-all', 'safe.directory'], 0, trust, b''),
        ('original-one-entry-clone', old + ['/usr/bin/git', 'clone', '--no-local', '--config', 'core.autocrlf=false', source, root + '/consumer/old-clone'],
            128, b'', b'fatal: detected dubious ownership in repository at ' + source.encode() + b'/.git\n'),
        ('two-entry-fresh-clone', prefix + ['/usr/bin/git', 'clone', '--no-local', '--config', 'core.autocrlf=false', source, root + '/consumer/fresh'], 0, b'', b'Cloning synthetic fixture\n'),
        ('fresh-head', prefix + ['/usr/bin/git', '-C', root + '/consumer/fresh', 'rev-parse', 'HEAD'], 0, head, b''),
        ('unrelated-root-owned-repository', prefix + ['/usr/bin/git', '-C', root + '/unrelated', 'rev-parse', 'HEAD'],
            128, b'', b'fatal: detected dubious ownership in repository at ' + root.encode() + b'/unrelated\n')])
    def raw_stream(value):
        return {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest(), 'base64': base64.b64encode(value).decode()}
    rows = [{'canonical_git_child_observation': {'case': case, 'command': capsule + command, 'outcome': 'EXECUTED',
        'returncode': code, 'timeout_seconds': 10, 'stdout': raw_stream(stdout), 'stderr': raw_stream(stderr),
        'prefix_source_sha256': 'c' * 64, 'scope': 'SYNTHETIC literal; no command executed'}}
        for case, command, code, stdout, stderr in commands]
    literal = b'SYNTHETIC GIT OWNERSHIP CONTROL ONLY\n'
    entries = [{'path': name, 'uid': 0, 'gid': 0, 'mode': 0o755 if kind == 'directory' else 0o644,
        'kind': kind, **raw_stream(value)} for name, kind, value in
        [('.', 'directory', b''), ('.git', 'directory', b''), ('literal.txt', 'file', literal)]]
    fixtures = {'source': copy.deepcopy(entries), 'unrelated': copy.deepcopy(entries)}
    result = {'status': 'PASS', 'consumer_uid': 65534, 'consumer_gid': 65534, 'original_one_entry_exit': 128,
        'two_entry_clone_exit': 0, 'unrelated_repository_exit': 128, 'git_version': 'git version 2.43.0',
        'effective_trust': trust.decode().split('\0')[:-1], 'configuration_scope': 'SYNTHETIC',
        'source_and_unrelated_ownership_modes_bytes_unchanged': True, 'fresh_commit': head.decode().strip(),
        'literal_sha256': hashlib.sha256(literal).hexdigest(), 'original_fixtures': fixtures, 'scope': 'SYNTHETIC'}
    rows.insert(9, {'canonical_git_original_fixtures': fixtures})
    rows.append({'canonical_guest_git_control': {'identity': {'uid': 0, 'gid': 0, 'groups': [0]}, 'control': result}})
    return rows, result


def literal_guest_proof(directory, seed, seed_raw, source, setup):
    """Write only labelled parser fixtures, never an execution receipt claim."""
    rows, result = literal_guest_events()
    directory.mkdir(parents=True)
    stdout = b''.join(json.dumps(row).encode() + b'\n' for row in rows)
    inputs = [{'path': '/work/c/.local-runs/canonical-seed/seed.json', 'bytes': len(seed_raw), 'sha256': hashlib.sha256(seed_raw).hexdigest()}]
    proof = {'schema_version': 1, 'command': ['/usr/bin/python3', '/work/c/tests/system/canonical_handoff_permissions.py', '--guest-git-only'],
        'cwd': '/work/c', 'source_before': source, 'source_after_sha256': source['sha256'], 'git': {'commit': seed['commit'], 'dirty': False},
        'verification_status': 'PASS', 'execution_outcome': 'EXECUTED', 'exit_code': 0,
        'environment': {'system': 'Linux'}, 'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0},
        'started_utc': '2026-10-24T23:59:59+00:00', 'finished_utc': '2026-10-25T00:00:00+00:00', 'elapsed_seconds': 1,
        'inputs_before': inputs, 'inputs_after': inputs, 'stdin': None, 'fixture': 'SYNTHETIC parser data; no command executed',
        'stdout': {'file': 'stdout.txt', 'sha256': hashlib.sha256(stdout).hexdigest()},
        'stderr': {'file': 'stderr.txt', 'sha256': hashlib.sha256(b'').hexdigest()}}
    (directory / 'stdout.txt').write_bytes(stdout); (directory / 'stderr.txt').write_bytes(b'')
    (directory / 'receipt.json').write_text(json.dumps(proof), encoding='utf-8')
    setup['git_ownership_control'] = result
    return proof


class GuestOriginalProofControls(unittest.TestCase):
    def check(self, change=None):
        from canonical_reference_git_control import guest_output
        rows, expected = literal_guest_events()
        if change: change(rows)
        raw = b''.join(json.dumps(row).encode() + b'\n' for row in rows)
        return guest_output(raw, prefix_sha256='c' * 64), expected

    def test_complete_literal_original_transport_record_is_accepted(self):
        actual, expected = self.check()
        self.assertEqual(actual, expected)

    def test_old_clone_success_or_missing_old_denial_never_passes(self):
        for index, key, value in [(11, 'returncode', 0), (11, 'outcome', 'TIMEOUT'),
            (11, 'case', 'host-one-entry-git-directory')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(lambda rows: rows[index]['canonical_git_child_observation'].__setitem__(key, value))

    def test_positive_clone_foreign_denial_and_source_identity_are_required(self):
        for index, key, value in [(12, 'returncode', 128), (14, 'returncode', 0),
            (11, 'prefix_source_sha256', 'd' * 64)]:
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.check(lambda rows: rows[index]['canonical_git_child_observation'].__setitem__(key, value))

    def test_ambient_wildcard_extra_trust_and_wrong_uid_are_rejected(self):
        for original, replacement in [('GIT_CONFIG_COUNT=2', 'GIT_CONFIG_COUNT=3'),
            ('GIT_CONFIG_VALUE_1=/tmp/rill-git-permission-SYNTHETIC/source/.git', 'GIT_CONFIG_VALUE_1=*'),
            ('--reuid=65534', '--reuid=0'), ('--clear-groups', '--keep-groups')]:
            def change(rows):
                command = rows[10]['canonical_git_child_observation']['command']
                command[command.index(original)] = replacement
            with self.subTest(original=original), self.assertRaises(ValueError): self.check(change)

    def test_stream_digest_bytes_and_denial_content_are_checked(self):
        for key, value in [('sha256', '0' * 64), ('bytes', 0), ('base64', '!!')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(lambda rows: rows[11]['canonical_git_child_observation']['stderr'].__setitem__(key, value))

    def test_root_fixtures_must_remain_root_owned_read_only_and_complete(self):
        for key, value in [('uid', 65534), ('mode', 0o777), ('path', '../outside')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(lambda rows: rows[9]['canonical_git_original_fixtures']['source'][0].__setitem__(key, value))

    def test_omitted_reordered_and_duplicate_events_are_rejected(self):
        for change in [lambda rows: rows.pop(11), lambda rows: rows.insert(11, copy.deepcopy(rows[11])),
            lambda rows: rows.reverse()]:
            with self.subTest(change=change), self.assertRaises(ValueError): self.check(change)

    def test_guest_identity_and_final_immutability_are_required(self):
        for change in [lambda rows: rows[-1]['canonical_guest_git_control']['identity'].__setitem__('uid', 65534),
            lambda rows: rows[-1]['canonical_guest_git_control']['control'].__setitem__('source_and_unrelated_ownership_modes_bytes_unchanged', False)]:
            with self.subTest(change=change), self.assertRaises(ValueError): self.check(change)


class GuestIntervalControls(unittest.TestCase):
    def test_all_six_intervals_reject_stale_overlap_invalid_duration_or_exhausted_budget(self):
        from canonical_reference_git_control import setup_intervals
        original = [{'started_utc': '2026-10-25T00:00:0' + str(i) + '+00:00',
            'finished_utc': '2026-10-25T00:00:0' + str(i + 1) + '+00:00', 'elapsed_seconds': 1} for i in range(6)]
        setup_intervals(copy.deepcopy(original), 6)
        for kind in ('stale', 'overlap', 'nan', 'boolean', 'missing', 'extra', 'budget'):
            values = copy.deepcopy(original)
            if kind == 'stale':
                values[0].update(started_utc='2000-01-01T00:00:00+00:00', finished_utc='2000-01-01T00:00:01+00:00')
            if kind == 'overlap':
                values[3].update(started_utc='2026-10-25T00:00:02+00:00', finished_utc='2026-10-25T00:00:03+00:00')
            if kind == 'nan': values[0]['elapsed_seconds'] = float('nan')
            if kind == 'boolean': values[0]['elapsed_seconds'] = True
            if kind == 'missing': values.pop()
            if kind == 'extra': values.append(copy.deepcopy(values[-1]))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                setup_intervals(values, 5.9 if kind == 'budget' else 6)


if __name__ == '__main__': unittest.main()
