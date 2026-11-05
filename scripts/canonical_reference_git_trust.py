"""Exact child-selected Git trust in the existing owned guest, never user config."""
import base64
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat

import canonical_reference_device as device
from canonical_reference_allocation import require
from canonical_reference_reservation import fsync_directory


def source_path(root):
    value = str(root)
    require(value == '/work/c' or re.fullmatch(r'/tmp/rill-git-permission-[A-Za-z0-9_-]{1,80}/source', value) is not None,
        'exact owned guest or synthetic fixture source required')
    return PurePosixPath(value)


def trust_path(root):
    return source_path(root).parent / 'canonical-git-trust/config'


def config_bytes(root):
    root = source_path(root)
    return ('[safe]\n\tdirectory = ' + str(root) + '\n\tdirectory = ' + str(root / '.git') + '\n').encode('ascii')


def validate_observation(row, root):
    expected = config_bytes(root)
    fields = {'schema_version', 'source', 'path', 'uid', 'gid', 'mode',
        'directory_uid', 'directory_gid', 'directory_mode', 'mount_uid', 'mount_gid', 'mount_mode',
        'bytes', 'sha256', 'base64'}
    require(type(row) is dict and set(row) == fields and type(row['schema_version']) is int and row['schema_version'] == 1
        and row['source'] == str(source_path(root)) and row['path'] == str(trust_path(root)),
        'closed exact child trust observation required')
    for key in ('uid', 'gid', 'mode', 'directory_uid', 'directory_gid', 'directory_mode', 'mount_uid', 'mount_gid', 'mount_mode', 'bytes'):
        require(type(row[key]) is int, 'integer child trust role fields required')
    require(row['uid'] == row['gid'] == row['directory_uid'] == row['directory_gid'] == row['mount_uid'] == row['mount_gid'] == 0
        and row['mode'] == 0o444 and row['directory_mode'] == 0o555
        and 0 <= row['mount_mode'] <= 0o7777 and not row['mount_mode'] & 0o022 and row['mount_mode'] & 0o005 == 0o005,
        'child trust file and both ancestor roles must be root owned, protected and traversable')
    require(row['bytes'] == len(expected) and row['sha256'] == hashlib.sha256(expected).hexdigest()
        and row['base64'] == base64.b64encode(expected).decode('ascii'), 'exact original two-source trust bytes required')
    return row


def directory(path, *, mode=None):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
        and not stat.S_IMODE(info.st_mode) & 0o022
        and stat.S_IMODE(info.st_mode) & 0o005 == 0o005
        and (mode is None or stat.S_IMODE(info.st_mode) == mode), 'protected root-owned traversable trust ancestor required')
    return info


def observe(root):
    path = Path(trust_path(root)); parent = directory(path.parent, mode=0o555); mount = directory(path.parent.parent)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
        and stat.S_IMODE(before.st_mode) == 0o444 and before.st_size == len(config_bytes(root)),
        'root-owned read-only regular child trust file required')
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_uid, info.st_gid, info.st_mode)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        require(identity(before) == identity(os.fstat(descriptor)), 'child trust descriptor identity changed')
        raw = os.read(descriptor, 4097)
        require(raw == config_bytes(root) and identity(before) == identity(os.fstat(descriptor))
            and identity(before) == identity(path.lstat()), 'child trust bytes or descriptor changed')
    finally: os.close(descriptor)
    row = {'schema_version': 1, 'source': str(source_path(root)), 'path': str(trust_path(root)),
        'uid': before.st_uid, 'gid': before.st_gid, 'mode': stat.S_IMODE(before.st_mode),
        'directory_uid': parent.st_uid, 'directory_gid': parent.st_gid, 'directory_mode': stat.S_IMODE(parent.st_mode),
        'mount_uid': mount.st_uid, 'mount_gid': mount.st_gid, 'mount_mode': stat.S_IMODE(mount.st_mode),
        'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'base64': base64.b64encode(raw).decode('ascii')}
    return validate_observation(row, root)


def install(root, *, fixture=False):
    require(type(fixture) is bool, 'explicit child trust installation context required')
    root = source_path(root)
    if fixture:
        require(str(root).startswith('/tmp/rill-git-permission-') and platform.system() == 'Linux'
            and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'actual root-owned synthetic fixture required')
    else:
        device.guard(0)
        require(root == PurePosixPath('/work/c'), 'actual owned canonical guest trust source required')
    path = Path(trust_path(root)); directory(path.parent.parent)
    require(not path.parent.exists() and not path.parent.is_symlink(), 'new dedicated child trust directory required')
    os.mkdir(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        raw = config_bytes(root); offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:]); require(written > 0, 'child trust write made no progress')
            offset += written
        os.fchmod(descriptor, 0o444); os.fsync(descriptor)
    finally: os.close(descriptor)
    os.chmod(path.parent, 0o555); fsync_directory(path.parent); fsync_directory(path.parent.parent)
    return observe(root)


def input_identity(observation, root=PurePosixPath('/work/c')):
    row = validate_observation(observation, root)
    return {'path': row['path'], 'bytes': row['bytes'], 'sha256': row['sha256']}


def validate_setup(metadata, directory, setup):
    row = metadata.document(str(directory / 'git-trust-observation.json'), 4096)
    validate_observation(row, PurePosixPath('/work/c'))
    raw = metadata.raw(str(directory / 'git-trust-config.raw'), 4096)
    require(row == setup.get('git_trust_before') == setup.get('git_trust_after')
        and raw == config_bytes('/work/c'), 'original setup child trust role or raw bytes differ')
    return input_identity(row)
