"""Narrow root-owned configuration handoff, with an actual nonroot access probe.

Private owner evidence remains0700. Only two bounded0444 configuration leaves
are linked into a new0555 directory; no parent, source or evidence is opened up.
The permission observation is supporting evidence, never reference authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import secrets
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
from canonical_reference_allocation import METHOD, require
from canonical_reference_reservation import durable_mkdir, fsync_directory
from kvm_reference_common import strict_json
from feasibility_profile import exact

DIRECTORY = PurePosixPath('/work/c/.local-runs/canonical-config')
PRIVATE = PurePosixPath('/work/c/.local-runs/canonical-attempt')
NAMES = ('measurement-config.json', 'export-config.json')
LIMIT = 8192


def digest(raw): return hashlib.sha256(raw).hexdigest()


def node(path):
    require(path.is_absolute() and len(path.parts) <= 32, 'bounded absolute configuration path required')
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and not (hasattr(path, 'is_junction') and path.is_junction()),
        'configuration handoff cannot traverse links')
    return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
        'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
        'kind': 'directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'other'}


def read(path):
    before = node(path)
    require(before['kind'] == 'file' and path.stat().st_size <= LIMIT, 'bounded regular configuration required')
    with path.open('rb') as stream: raw = stream.read(LIMIT + 1)
    require(0 < len(raw) <= LIMIT and node(path) == before, 'configuration changed while reading')
    return raw


def snapshot(private, directory):
    paths = [private, directory, *directory.parents]
    return [node(path) for path in paths]


def protected(rows, private, directory):
    wanted = [str(private), str(directory), *(str(path) for path in directory.parents)]
    require(type(rows) is list and len(rows) == len(wanted) <= 34,
        'complete bounded configuration ancestor observations required')
    for index, (row, path) in enumerate(zip(rows, wanted)):
        require(type(row) is dict and set(row) == {'path', 'device', 'inode', 'uid', 'gid', 'mode', 'kind'}
            and row['path'] == path and row['kind'] == 'directory'
            and all(type(row[key]) is int and row[key] >= 0 for key in ('device', 'inode', 'uid', 'gid', 'mode'))
            and row['uid'] == row['gid'] == 0, 'root-owned original configuration ancestors required')
        mode = row['mode']
        if index == 0: require(mode == 0o700, 'private owner evidence must remain0700')
        elif index == 1: require(mode == 0o555, 'published configuration directory must remain0555')
        else:
            require(mode & 0o005 == 0o005 and (not mode & 0o022 or mode == 0o1777),
                'configuration ancestor must be traversable and root-protected or root-sticky')


def install(private, configurations, *, directory=None):
    require(platform.system() == 'Linux' and hasattr(os, 'geteuid') and os.geteuid() == 0,
        'actual existing Linux root required for configuration publication')
    directory = Path(DIRECTORY) if directory is None else directory
    require(set(configurations) == set(NAMES) and private.is_absolute() and directory.is_absolute()
        and private.parent == directory.parent and private != directory,
        'two closed configuration leaves in separate sibling directories required')
    # Check all ancestors before any creation; never follow an untrusted link.
    for path in (private, *private.parents):
        observed = node(path)
        require(observed['kind'] == 'directory' and observed['uid'] == observed['gid'] == 0,
            'root-owned original configuration parent required')
        mode = observed['mode']
        require(mode == 0o700 if path == private else
            mode & 0o005 == 0o005 and (not mode & 0o022 or mode == 0o1777),
            'configuration ancestors must already protect traversal before publication')
    require(node(private)['mode'] == 0o700 and not directory.exists(),
        'new public config handoff and unchanged private0700 owner required')
    durable_mkdir(directory, mode=0o700)
    files = []
    for name in NAMES:
        raw = (json.dumps(configurations[name], sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
        require(0 < len(raw) <= LIMIT, 'configuration exceeds explicit bound')
        original, published = private / name, directory / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(original, flags, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            require(stream.write(raw) == len(raw), 'configuration write incomplete')
            stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(), 0o444)
            os.fsync(stream.fileno())
        os.link(original, published, follow_symlinks=False)
        before, public = node(original), node(published)
        require(before['kind'] == public['kind'] == 'file' and before['uid'] == before['gid'] == 0
            and public['uid'] == public['gid'] == 0 and before['mode'] == public['mode'] == 0o444
            and (before['device'], before['inode']) == (public['device'], public['inode'])
            and read(original) == read(published) == raw, 'exact immutable original and published configuration required')
        files.append({'name': name, 'private': before, 'published': public, 'bytes': len(raw), 'sha256': digest(raw)})
    os.chmod(directory, 0o555); fsync_directory(directory); fsync_directory(private); fsync_directory(directory.parent)
    ancestors = snapshot(private, directory); protected(ancestors, private, directory)
    return {'schema_version': 1, 'method': METHOD, 'private_root': str(private),
        'directory': str(directory), 'files': files, 'ancestors': ancestors}


def command(files, private=PRIVATE, *, root=ROOT):
    require([row['name'] for row in files] == list(NAMES), 'two original configuration identities required')
    return ['/usr/bin/python3', '-I', str(root / 'scripts/canonical_reference_config_handoff.py'), 'probe',
        '--private-root', str(private), '--measurement', files[0]['published']['path'],
        '--measurement-sha256', files[0]['sha256'], '--export', files[1]['published']['path'],
        '--export-sha256', files[1]['sha256']]


def denied_open(path, flags):
    try: descriptor = os.open(path, flags | os.O_NOFOLLOW)
    except PermissionError: return True
    else: os.close(descriptor); return False


def probe(private, paths, digests):
    require(platform.system() == 'Linux' and os.getresuid() == os.getresgid() == (65534, 65534, 65534)
        and os.getgroups() == [], 'actual UID/GID65534 with cleared supplementary groups required')
    rows = []
    for name, path, wanted in zip(NAMES, paths, digests):
        require(path.name == name and len(wanted) == 64, 'closed configuration probe inputs required')
        raw = read(path); info = node(path)
        require(digest(raw) == wanted, 'actual nonroot read does not match original configuration')
        leaf = path.parent / ('.permission-probe-' + secrets.token_hex(8))
        try:
            fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except PermissionError: create_denied = True
        else:
            os.close(fd); leaf.unlink(); create_denied = False
        rows.append({'name': name, 'path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
            'node': info, 'write_denied': denied_open(path, os.O_WRONLY), 'parent_create_denied': create_denied})
    return {'schema_version': 1, 'method': METHOD, 'uids': list(os.getresuid()), 'gids': list(os.getresgid()),
        'groups': os.getgroups(), 'private_root': str(private),
        'private_read_denied': denied_open(private, os.O_RDONLY | os.O_DIRECTORY),
        'files': rows, 'reference_qualified': False}


def validate_record(record, configurations, *, private=PRIVATE, directory=DIRECTORY):
    require(type(record) is dict and set(record) == {'status', 'publication', 'probe', 'leaf_nodes_before',
        'leaf_nodes_after', 'ancestors_after', 'reference_qualified'}
        and record['status'] == 'CHECKED ACTUAL NONROOT CONFIG ACCESS' and record['reference_qualified'] is False,
        'original actual configuration access record required')
    publication, observed = record['publication'], record['probe']
    require(type(publication) is dict and set(publication) == {'schema_version', 'method', 'private_root', 'directory', 'files', 'ancestors'}
        and type(publication['schema_version']) is int and publication['schema_version'] == 1
        and publication['method'] == METHOD and publication['private_root'] == str(private)
        and publication['directory'] == str(directory), 'exact original configuration handoff paths required')
    protected(publication['ancestors'], private, directory)
    require(exact(publication['ancestors'], record['ancestors_after']), 'configuration ancestor identity/modes changed')
    require(type(observed) is dict and set(observed) == {'schema_version', 'method', 'uids', 'gids', 'groups',
        'private_root', 'private_read_denied', 'files', 'reference_qualified'}
        and type(observed['schema_version']) is int and observed['schema_version'] == 1
        and observed['method'] == METHOD and observed['uids'] == observed['gids'] == [65534]*3
        and all(type(value) is int for value in observed['uids'] + observed['gids'])
        and observed['groups'] == [] and observed['private_root'] == str(private)
        and observed['private_read_denied'] is True and observed['reference_qualified'] is False,
        'actual nonroot private-directory denial or complete identity differs')
    files, reads = publication['files'], observed['files']
    require(type(files) is list and type(reads) is list and len(files) == len(reads) == 2
        and set(configurations) == set(NAMES), 'both exact original configuration probes required')
    for name, row, child in zip(NAMES, files, reads):
        raw = configurations[name]
        require(type(raw) is bytes and 0 < len(raw) <= LIMIT
            and type(row) is dict and set(row) == {'name', 'private', 'published', 'bytes', 'sha256'}
            and row['name'] == name and type(row['bytes']) is int and row['bytes'] == len(raw)
            and row['sha256'] == digest(raw), 'original retained configuration byte binding differs')
        for key, path in [('private', private / name), ('published', directory / name)]:
            info = row[key]
            require(type(info) is dict and set(info) == {'path', 'device', 'inode', 'uid', 'gid', 'mode', 'kind'}
                and info['path'] == str(path) and info['kind'] == 'file' and info['mode'] == 0o444
                and info['uid'] == info['gid'] == 0 and all(type(info[key]) is int and info[key] >= 0
                    for key in ('device', 'inode', 'uid', 'gid', 'mode')), 'immutable root-owned original configuration node differs')
        require((row['private']['device'], row['private']['inode']) == (row['published']['device'], row['published']['inode']),
            'published configuration is not the same original inode')
        require(type(child) is dict and set(child) == {'name', 'path', 'bytes', 'sha256', 'node', 'write_denied', 'parent_create_denied'}
            and child['name'] == name and child['path'] == str(directory / name) and exact(child['node'], row['published'])
            and type(child['bytes']) is int and child['bytes'] == len(raw) and child['sha256'] == digest(raw)
            and child['write_denied'] is True and child['parent_create_denied'] is True,
            'actual nonroot read/write/directory denial differs for original configuration')
    expected_leaves = [row[key] for row in files for key in ('private', 'published')]
    require(exact(record['leaf_nodes_before'], expected_leaves) and exact(record['leaf_nodes_after'], expected_leaves),
        'original file nodes must retain exact identity/ownership/mode before and after final reads')
    return files


def observe_original_leaves(publication):
    """Compare actual leaf metadata to the original install/probe identities."""
    observations = []
    for row in publication['files']:
        for key in ('private', 'published'):
            current = node(Path(row[key]['path']))
            require(exact(current, row[key]), 'original configuration file identity/ownership/mode changed after probe')
            observations.append(current)
    return observations


def finish(publication, observed):
    private, directory = Path(publication['private_root']), Path(publication['directory'])
    before = observe_original_leaves(publication)
    originals = {name: read(private / name) for name in NAMES}
    for name in NAMES: require(read(directory / name) == originals[name], 'published configuration changed during probe')
    after = observe_original_leaves(publication)
    result = {'status': 'CHECKED ACTUAL NONROOT CONFIG ACCESS', 'publication': publication, 'probe': observed,
        'leaf_nodes_before': before, 'leaf_nodes_after': after,
        'ancestors_after': snapshot(private, directory), 'reference_qualified': False}
    validate_record(result, originals, private=private, directory=directory)
    return result


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=['probe'])
    parser.add_argument('--private-root', type=Path, required=True)
    parser.add_argument('--measurement', type=Path, required=True); parser.add_argument('--measurement-sha256', required=True)
    parser.add_argument('--export', type=Path, required=True); parser.add_argument('--export-sha256', required=True)
    args = parser.parse_args()
    result = probe(args.private_root, [args.measurement, args.export], [args.measurement_sha256, args.export_sha256])
    print(json.dumps(result, sort_keys=True, separators=(',', ':'))); return 0


if __name__ == '__main__': raise SystemExit(main())
