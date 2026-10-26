"""Exact child-only trust binding; synthetic records are never execution proof."""
import base64
import hashlib
import importlib
import json
from pathlib import Path, PurePosixPath
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
from .test_canonical_git_permissions import actual_nonroot_fixture_prefix
from . import test_canonical_git_permissions as configuration_fixtures


def literal_trust_observation(root='/work/c'):
    raw = ('[safe]\n\tdirectory = ' + root + '\n\tdirectory = ' + root + '/.git\n').encode()
    return {'schema_version': 1, 'source': root,
        'path': str(PurePosixPath(root).parent / 'canonical-git-trust/config'),
        'uid': 0, 'gid': 0, 'mode': 0o444, 'directory_uid': 0, 'directory_gid': 0, 'directory_mode': 0o555,
        'mount_uid': 0, 'mount_gid': 0, 'mount_mode': 0o755, 'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(), 'base64': base64.b64encode(raw).decode()}


def literal_setup_trust(directory, setup):
    """Labelled parser fixture only; no file ownership or execution is asserted."""
    row = literal_trust_observation()
    (directory / 'git-trust-observation.json').write_text(json.dumps(row), encoding='utf-8')
    (directory / 'git-trust-config.raw').write_bytes(base64.b64decode(row['base64']))
    setup['git_trust_before'] = dict(row); setup['git_trust_after'] = dict(row)
    return {key: row[key] for key in ('path', 'bytes', 'sha256')}


class ChildGitTrustControls(unittest.TestCase):
    def test_real_configuration_reads_only_the_two_values_from_the_selected_file(self):
        helper = configuration_fixtures.FixtureGitConfiguration()
        with helper.ambient_configuration() as (git, env, ambient, directory):
            path = directory / 'query-only.cfg'; raw = self.module().config_bytes('/work/c'); path.write_bytes(raw)
            command = helper.function('fixture_git_command')(['/usr/bin/env', 'GIT_CONFIG_GLOBAL=' + path.as_posix(),
                git, 'config', '--null', '--show-origin', '--show-scope', '--get-all', 'safe.directory'])
            result = helper.real_git(command, env, ambient, directory)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            expected = b''.join(b'global\0file:' + path.as_posix().encode() + b'\0' + value + b'\0'
                for value in (b'/work/c', b'/work/c/.git'))
            self.assertEqual(result.stdout, expected)
            self.assertEqual(path.read_bytes(), raw)

    def module(self):
        self.assertTrue((ROOT / 'scripts/canonical_reference_git_trust.py').is_file(),
            'source-bound protected child trust implementation required')
        return importlib.import_module('canonical_reference_git_trust')

    def test_config_has_only_two_exact_source_directories_and_lives_outside_source(self):
        trust = self.module(); root = PurePosixPath('/work/c')
        self.assertEqual(trust.trust_path(root), PurePosixPath('/work/canonical-git-trust/config'))
        self.assertEqual(trust.config_bytes(root), b'[safe]\n\tdirectory = /work/c\n\tdirectory = /work/c/.git\n')
        for invalid in ('/unrelated', '/work/c/../other', '/work/c space', '/tmp/rill-git-permission-x/source/.git'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError): trust.config_bytes(invalid)

    def test_only_closed_root_owned_read_only_role_and_original_bytes_are_accepted(self):
        trust = self.module(); original = literal_trust_observation()
        self.assertEqual(trust.validate_observation(original, PurePosixPath('/work/c')), original)
        for key, value in [('uid', 65534), ('gid', 65534), ('mode', 0o644), ('directory_mode', 0o755),
            ('mount_uid', 65534), ('mount_mode', 0o777), ('bytes', True), ('schema_version', True),
            ('sha256', '0' * 64), ('path', '/work/c/.git/config'), ('base64', '!!'), ('unexpected', 1)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                trust.validate_observation({**original, key: value}, PurePosixPath('/work/c'))

    def test_actual_prefix_selects_exact_child_file_and_keeps_both_client_entries(self):
        command = actual_nonroot_fixture_prefix(PurePosixPath('/work/c'),
            PurePosixPath('/work/c/.local-runs/canonical-home'), ['/usr/bin/git', 'clone', '--no-local'])
        entries = [value for value in command if value.startswith('GIT_CONFIG_')]
        self.assertEqual(entries, ['GIT_CONFIG_GLOBAL=/work/canonical-git-trust/config', 'GIT_CONFIG_COUNT=2',
            'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=/work/c',
            'GIT_CONFIG_KEY_1=safe.directory', 'GIT_CONFIG_VALUE_1=/work/c/.git'])

    def test_unowned_runtime_cannot_create_or_replace_a_trust_file(self):
        trust = self.module()
        with patch.object(trust.device, 'guard', side_effect=ValueError('owned guest required')), \
            patch.object(trust.os, 'mkdir') as mkdir, patch.object(trust.os, 'open') as open_file:
            with self.assertRaises(ValueError): trust.install(PurePosixPath('/work/c'))
            mkdir.assert_not_called(); open_file.assert_not_called()


if __name__ == '__main__': unittest.main()
