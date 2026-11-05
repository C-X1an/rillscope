"""Literal portable acquisition controls; no APT, Linux role or network run."""
import base64
import copy
import hashlib
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import canonical_reference_native_apt as apt

SOURCE = b'''Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: noble noble-updates
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Check-Valid-Until: yes

Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: noble-security
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Check-Valid-Until: yes
'''
PUBLIC_KEY_FIXTURE = b'EXPLICITLY SYNTHETIC PUBLIC KEY BYTES; NEVER USED BY APT'
DIR = '/work/c/.local-runs/canonical-native-apt'
KEY = '/usr/share/keyrings/ubuntu-archive-keyring.gpg'
PACKAGES = ('build-essential', 'ca-certificates', 'curl', 'pkg-config', 'libssl-dev',
    'git', 'make', 'gdb', 'strace', 'time', 'util-linux')


def fixture():
    parents = ['/', '/usr', '/usr/share', '/usr/share/keyrings', '/work', '/work/c', '/work/c/.local-runs', DIR]
    nodes = {name: {'path': name, 'device': 37, 'inode': index + 11, 'uid': 0, 'gid': 0,
        'mode': 0o555 if name == DIR else 0o755, 'kind': 'directory'} for index, name in enumerate(parents)}
    for index, name in enumerate([DIR + '/native.sources', DIR + '/empty-sources.d', KEY]):
        nodes[name] = {'path': name, 'device': 37, 'inode': index + 101, 'uid': 0, 'gid': 0,
            'mode': 0o444 if name.endswith('.sources') else 0o555 if name.endswith('.d') else 0o644,
            'kind': 'directory' if name.endswith('.d') else 'file'}
    policy = {'schema_version': 1, 'method': 'rillscope-native-apt-acquisition-v1', 'root': '/work/c',
        'source_bytes': len(SOURCE), 'source_sha256': hashlib.sha256(SOURCE).hexdigest(),
        'source_base64': base64.b64encode(SOURCE).decode(), 'keyring_bytes': len(PUBLIC_KEY_FIXTURE),
        'keyring_sha256': hashlib.sha256(PUBLIC_KEY_FIXTURE).hexdigest(),
        'nodes': [copy.deepcopy(nodes[name]) for name in [DIR, DIR + '/native.sources', DIR + '/empty-sources.d', KEY]],
        'ancestors': [copy.deepcopy(nodes[name]) for name in parents], 'reference_qualified': False}
    return policy, nodes


class NativeAptAcquisition(unittest.TestCase):
    def test_closed_sources_keep_archive_security_main_architecture_and_original_key(self):
        self.assertEqual(apt.SOURCES, SOURCE)
        self.assertEqual(apt.PACKAGES, PACKAGES)
        self.assertEqual(apt.validate(fixture()[0]), fixture()[0])

    def test_both_commands_apply_same_closed_inputs_and_authentication(self):
        prefix = ['/usr/bin/apt-get', '-o', 'Dir::Etc::sourcelist=' + DIR + '/native.sources',
            '-o', 'Dir::Etc::sourceparts=' + DIR + '/empty-sources.d', '-o', 'Acquire::Languages=none',
            '-o', 'Acquire::AllowInsecureRepositories=false', '-o', 'Acquire::AllowWeakRepositories=false',
            '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false', '-o', 'Acquire::Check-Valid-Until=true',
            '-o', 'APT::Get::AllowUnauthenticated=false']
        self.assertEqual(apt.commands('/work/c', PACKAGES), (prefix + ['--error-on=any', 'update'],
            prefix + ['install', '--yes', '--no-install-recommends', *PACKAGES]))

    def test_missing_added_reordered_or_substituted_packages_are_rejected(self):
        for changed in [PACKAGES[:-1], PACKAGES + ('other',), tuple(reversed(PACKAGES)), list(PACKAGES)]:
            with self.subTest(changed=changed), self.assertRaises(ValueError): apt.commands('/work/c', changed)

    def test_noncanonical_roots_are_rejected_before_command_construction(self):
        for root in ['relative', '//work/c', '/work/./c', '/work//c', '/work/c/..', '/work/c\nextra',
                'C:/work/c', '/work\\c', '/' + 'x' * 513]:
            with self.subTest(root=root), self.assertRaises(ValueError): apt.commands(root, PACKAGES)

    def test_coherent_extra_component_or_changed_signature_policy_is_rejected(self):
        for before, after in [(b'Components: main', b'Components: main universe'),
                (b'noble-security', b'noble-backports'), (b'Check-Valid-Until: yes', b'Check-Valid-Until: no'),
                (b'ubuntu-archive-keyring.gpg', b'other-keyring.gpg')]:
            policy, _ = fixture(); raw = SOURCE.replace(before, after)
            policy.update(source_bytes=len(raw), source_sha256=hashlib.sha256(raw).hexdigest(), source_base64=base64.b64encode(raw).decode())
            with self.subTest(after=after), self.assertRaises(ValueError): apt.validate(policy)

    def test_missing_or_unreadable_writable_or_foreign_nodes_are_rejected(self):
        for index, key, value in [(0, 'mode', 0o777), (1, 'uid', 65534), (1, 'mode', 0o666),
                (2, 'kind', 'file'), (3, 'mode', 0o600), (3, 'path', '/other/key')]:
            policy, _ = fixture(); policy['nodes'][index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(ValueError): apt.validate(policy)
        policy, _ = fixture(); policy['nodes'].pop()
        with self.assertRaises(ValueError): apt.validate(policy)

    def test_boolean_identity_unknown_fields_and_missing_ancestry_are_rejected(self):
        for edit in [lambda p: p['nodes'][0].update(uid=False), lambda p: p.update(extra=True),
                lambda p: p['ancestors'].pop(), lambda p: p['ancestors'][0].update(mode=0o777),
                lambda p: p.update(schema_version=True)]:
            policy, _ = fixture(); edit(policy)
            with self.subTest(edit=edit), self.assertRaises(ValueError): apt.validate(policy)

    def observe_fixture(self, mutate=None):
        policy, nodes = fixture()
        class VirtualPath(PurePosixPath):
            def iterdir(self): return iter(())
        def read(path, limit):
            raw = SOURCE if str(path).endswith('.sources') else PUBLIC_KEY_FIXTURE
            if str(path) == KEY and mutate: mutate(nodes)
            return raw
        with patch.object(apt, 'Path', VirtualPath), patch.object(apt, 'node', side_effect=lambda p: copy.deepcopy(nodes[str(p)])), \
                patch.object(apt, 'read', side_effect=read):
            return apt.observe(policy)

    def test_original_literal_nodes_and_bytes_survive_both_observation_boundaries(self):
        self.assertEqual(self.observe_fixture()['nodes'], fixture()[0]['nodes'])

    def test_two_completed_ordered_commands_have_unchanged_before_and_after_roles(self):
        policy, _ = fixture(); observation = {'nodes': policy['nodes'], 'ancestors': policy['ancestors']}
        record = {'policy': policy, 'checks': [{'stage': name, 'before': copy.deepcopy(observation),
            'after': copy.deepcopy(observation)} for name in ('apt-update', 'apt-install')]}
        self.assertEqual(apt.validate_acquisition(record), policy)
        for edit in [lambda r: r['checks'].pop(), lambda r: r['checks'].reverse(),
                lambda r: r['checks'][1]['after']['nodes'][1].update(mode=0o666),
                lambda r: r['checks'][0].update(after={'nodes': policy['nodes']}),
                lambda r: r['checks'][1].update(stage='unchecked')]:
            changed = copy.deepcopy(record); edit(changed)
            with self.subTest(edit=edit), self.assertRaises(ValueError): apt.validate_acquisition(changed)

    def test_same_byte_leaf_replacement_after_last_read_is_rejected(self):
        for edit in [lambda n: n[DIR + '/native.sources'].update(mode=0o666),
                lambda n: n[KEY].update(inode=9999), lambda n: n[DIR].update(uid=65534)]:
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.observe_fixture(edit)

    def test_descriptor_read_ignores_atime_but_rejects_changed_content_metadata(self):
        fields = dict(st_dev=37, st_ino=44, st_mode=stat_mode(), st_uid=0, st_gid=0, st_nlink=1,
            st_size=4, st_mtime_ns=77, st_ctime_ns=88, st_atime_ns=1)
        for changed, valid in [({'st_atime_ns': 2}, True), ({'st_mtime_ns': 78}, False), ({'st_ino': 45}, False)]:
            with patch.object(apt.os, 'O_NOFOLLOW', 0, create=True), patch.object(apt.os, 'O_CLOEXEC', 0, create=True), \
                    patch.object(apt.os, 'open', return_value=731), patch.object(apt.os, 'close') as close, \
                    patch.object(apt.os, 'read', side_effect=[b'data', b'']), \
                    patch.object(apt.os, 'fstat', side_effect=[SimpleNamespace(**fields), SimpleNamespace(**{**fields, **changed})]):
                if valid: self.assertEqual(apt.read(PurePosixPath('/literal'), 8192), b'data')
                else:
                    with self.assertRaises(ValueError): apt.read(PurePosixPath('/literal'), 8192)
                close.assert_called_once_with(731)

    def test_foreign_platform_cannot_create_any_native_policy(self):
        with patch.object(apt.platform, 'system', return_value='Windows'), patch.object(apt.os, 'open') as opened:
            with self.assertRaises(ValueError): apt.publish('/work/c')
            opened.assert_not_called()


def stat_mode():
    import stat
    return stat.S_IFREG | 0o444


if __name__ == '__main__': unittest.main()
