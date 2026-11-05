"""Independent literal permission/provenance records; these are not POSIX runs."""
import copy
import io
from pathlib import Path, PurePosixPath
import stat
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_config_handoff as handoff


def access_fixture(configurations):
    """Explicit synthetic root/nonroot record for offline rejection controls."""
    def directory(path, mode, inode):
        return {'path': str(path), 'device': 1, 'inode': inode, 'uid': 0, 'gid': 0, 'mode': mode, 'kind': 'directory'}
    ancestors = [directory(handoff.PRIVATE, 0o700, 1), directory(handoff.DIRECTORY, 0o555, 2)]
    ancestors.extend(directory(path, 0o1777 if index == 0 else 0o755, index + 3)
        for index, path in enumerate(handoff.DIRECTORY.parents))
    files, probes = [], []
    for index, name in enumerate(handoff.NAMES):
        private = {'path': str(handoff.PRIVATE / name), 'device': 1, 'inode': index + 100,
            'uid': 0, 'gid': 0, 'mode': 0o444, 'kind': 'file'}
        public = {**private, 'path': str(handoff.DIRECTORY / name)}
        raw = configurations[name]
        files.append({'name': name, 'private': private, 'published': public, 'bytes': len(raw), 'sha256': handoff.digest(raw)})
        probes.append({'name': name, 'path': public['path'], 'bytes': len(raw), 'sha256': handoff.digest(raw),
            'node': copy.deepcopy(public), 'write_denied': True, 'parent_create_denied': True})
    return {'status': 'CHECKED ACTUAL NONROOT CONFIG ACCESS', 'publication': {
        'schema_version': 1, 'method': handoff.METHOD, 'private_root': str(handoff.PRIVATE),
        'directory': str(handoff.DIRECTORY), 'files': files, 'ancestors': ancestors},
        'probe': {'schema_version': 1, 'method': handoff.METHOD, 'uids': [65534]*3, 'gids': [65534]*3,
            'groups': [], 'private_root': str(handoff.PRIVATE), 'private_read_denied': True,
            'files': probes, 'reference_qualified': False},
        'leaf_nodes_before': [copy.deepcopy(row[key]) for row in files for key in ('private', 'published')],
        'leaf_nodes_after': [copy.deepcopy(row[key]) for row in files for key in ('private', 'published')],
        'ancestors_after': copy.deepcopy(ancestors), 'reference_qualified': False}


class ConfigurationHandoffRecords(unittest.TestCase):
    def setUp(self):
        self.raw = {'measurement-config.json': b'{"measurement":"original"}\n',
            'export-config.json': b'{"export":"different-original"}\n'}
        self.record = access_fixture(self.raw)

    def test_two_original_read_only_inodes_and_complete_nonroot_denials_are_required(self):
        rows = handoff.validate_record(self.record, self.raw)
        self.assertEqual([row['name'] for row in rows], ['measurement-config.json', 'export-config.json'])
        self.assertEqual(self.record['publication']['ancestors'][0]['mode'], 0o700)
        self.assertFalse(self.record['reference_qualified'])

    def test_missing_either_probe_or_its_read_write_directory_denial_is_rejected(self):
        for index in range(2):
            for key, value in [('write_denied', False), ('parent_create_denied', False), ('bytes', True),
                    ('sha256', '0'*64), ('path', '/wrong/config')]:
                row = copy.deepcopy(self.record); row['probe']['files'][index][key] = value
                with self.subTest(index=index, key=key), self.assertRaises(ValueError): handoff.validate_record(row, self.raw)
            row = copy.deepcopy(self.record); row['probe']['files'].pop(index)
            with self.assertRaises(ValueError): handoff.validate_record(row, self.raw)

    def test_root_mixed_identity_supplementary_groups_or_private_access_cannot_be_admitted(self):
        for key, value in [('uids', [0]*3), ('uids', [65534, 0, 65534]), ('gids', [0]*3),
                ('groups', [65534]), ('private_read_denied', False), ('reference_qualified', True)]:
            row = copy.deepcopy(self.record); row['probe'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): handoff.validate_record(row, self.raw)

    def test_no_config_fix_can_open_private_evidence_or_change_protected_ancestors(self):
        for index, key, value in [(0, 'mode', 0o755), (1, 'mode', 0o755), (2, 'mode', 0o777),
                (3, 'uid', 65534), (3, 'mode', 0o700), (1, 'inode', True)]:
            row = copy.deepcopy(self.record); row['publication']['ancestors'][index][key] = value
            row['ancestors_after'] = copy.deepcopy(row['publication']['ancestors'])
            with self.subTest(index=index, key=key), self.assertRaises(ValueError): handoff.validate_record(row, self.raw)
        row = copy.deepcopy(self.record); row['ancestors_after'][1]['inode'] += 1
        with self.assertRaises(ValueError): handoff.validate_record(row, self.raw)
        row = copy.deepcopy(self.record); row['ancestors_after'][1]['uid'] = False
        with self.assertRaises(ValueError): handoff.validate_record(row, self.raw)

    def test_either_config_substitution_writable_node_or_separate_inode_fails_closed(self):
        for index in range(2):
            for key, value in [('mode', 0o644), ('uid', 65534), ('kind', 'directory'), ('inode', 999), ('device', True)]:
                row = copy.deepcopy(self.record); row['publication']['files'][index]['published'][key] = value
                row['probe']['files'][index]['node'] = copy.deepcopy(row['publication']['files'][index]['published'])
                with self.subTest(index=index, key=key), self.assertRaises(ValueError): handoff.validate_record(row, self.raw)
            name = handoff.NAMES[index]; altered = {**self.raw, name: self.raw[name] + b' '}
            with self.assertRaises(ValueError): handoff.validate_record(self.record, altered)
            row = copy.deepcopy(self.record); row['probe']['files'][index]['node']['uid'] = False
            with self.assertRaises(ValueError): handoff.validate_record(row, self.raw)

    def test_paths_schema_extra_claims_and_non_integer_values_are_closed(self):
        for target, key, value in [('publication', 'directory', '/work/c/.local-runs/canonical-attempt'),
                ('publication', 'schema_version', True), ('probe', 'schema_version', True),
                ('publication', 'extra', 'unobserved'), ('probe', 'extra', 'unobserved')]:
            row = copy.deepcopy(self.record); row[target][key] = value
            with self.subTest(target=target, key=key), self.assertRaises(ValueError): handoff.validate_record(row, self.raw)

    def test_probe_command_binds_both_exact_published_paths_and_original_digests(self):
        from pathlib import PurePosixPath
        command = handoff.command(self.record['publication']['files'], root=PurePosixPath('/work/c'))
        self.assertEqual(command, ['/usr/bin/python3', '-I', '/work/c/scripts/canonical_reference_config_handoff.py',
            'probe', '--private-root', '/work/c/.local-runs/canonical-attempt',
            '--measurement', '/work/c/.local-runs/canonical-config/measurement-config.json',
            '--measurement-sha256', handoff.digest(self.raw['measurement-config.json']),
            '--export', '/work/c/.local-runs/canonical-config/export-config.json',
            '--export-sha256', handoff.digest(self.raw['export-config.json'])])

    def test_missing_real_linux_root_stops_before_directory_or_file_changes(self):
        with patch.object(handoff.platform, 'system', return_value='Windows'), patch.object(handoff, 'durable_mkdir') as create:
            with self.assertRaisesRegex(ValueError, 'actual existing Linux root'):
                handoff.install(Path('/synthetic/private'), {})
            create.assert_not_called()


def invoke(change=None, after_read=None):
    """Literal virtual nodes; actual production finish/read, no POSIX experiment."""
    raw = {'measurement-config.json': b'{"measurement":"literal"}\n', 'export-config.json': b'{"export":"literal"}\n'}
    record = access_fixture(raw)
    nodes = {row['path']: copy.deepcopy(row) for row in record['publication']['ancestors']}
    contents = {}
    for item in record['publication']['files']:
        for key in ('private', 'published'):
            nodes[item[key]['path']] = copy.deepcopy(item[key]); contents[item[key]['path']] = raw[item['name']]
    if change:
        key, value = change
        for kind in ('private', 'published'): nodes[record['publication']['files'][0][kind]['path']][key] = value

    class VirtualPath(PurePosixPath):
        def lstat(self):
            row = nodes[str(self)]
            return types.SimpleNamespace(st_dev=row['device'], st_ino=row['inode'], st_uid=row['uid'], st_gid=row['gid'],
                st_mode=(stat.S_IFDIR if row['kind']=='directory' else stat.S_IFREG) | row['mode'],
                st_size=len(contents.get(str(self), b'')))
        def stat(self, **_kwargs): return self.lstat()
        def is_junction(self): return False
        def open(self, mode='r', **_kwargs):
            if mode != 'rb': raise AssertionError('Only byte reads are authorized by this virtual fixture')
            return io.BytesIO(contents[str(self)])

    production_read = handoff.read
    def read_then_change(path):
        value = production_read(path)
        if str(path) == record['publication']['files'][-1]['published']['path']:
            key, changed = after_read
            for kind in ('private', 'published'): nodes[record['publication']['files'][-1][kind]['path']][key] = changed
        return value
    with patch.object(handoff, 'Path', VirtualPath):
        if after_read is None:
            result = handoff.finish(copy.deepcopy(record['publication']), copy.deepcopy(record['probe']))
        else:
            with patch.object(handoff, 'read', side_effect=read_then_change):
                result = handoff.finish(copy.deepcopy(record['publication']), copy.deepcopy(record['probe']))
    return result, record


class FinalConfigurationLeafIdentity(unittest.TestCase):
    # These four independent reproducer method bodies are unchanged from review40.
    def test_unchanged_original_leaf_snapshots_are_accepted(self):
        result,original=invoke();self.assertEqual(result,original)
    def test_same_byte_mode_change_after_probe_is_rejected(self):
        with self.assertRaises(ValueError):invoke(('mode',0o666))
    def test_same_byte_inode_replacement_after_probe_is_rejected(self):
        with self.assertRaises(ValueError):invoke(('inode',999))
    def test_same_byte_leaf_owner_change_after_probe_is_rejected(self):
        with self.assertRaises(ValueError):invoke(('uid',65534))
    def test_leaf_change_after_completed_read_is_rejected(self):
        with self.assertRaises(ValueError): invoke(after_read=('mode', 0o666))


if __name__ == '__main__': unittest.main()
