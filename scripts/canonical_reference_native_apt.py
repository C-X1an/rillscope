"""Closed authenticated Ubuntu package acquisition before native tool setup.

This changes acquisition metadata only. It does not install host-built tools,
extend a setup clock, alter package requirements or establish reference fit.
"""
import base64
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import stat

METHOD = 'rillscope-native-apt-acquisition-v1'
KEYRING = '/usr/share/keyrings/ubuntu-archive-keyring.gpg'
PACKAGES = ('build-essential', 'ca-certificates', 'curl', 'pkg-config', 'libssl-dev',
    'git', 'make', 'gdb', 'strace', 'time', 'util-linux')
SOURCES = (f'Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\n'
    f'Suites: noble noble-updates\nComponents: main\nArchitectures: amd64\nSigned-By: {KEYRING}\n'
    f'Check-Valid-Until: yes\n\nTypes: deb\nURIs: http://security.ubuntu.com/ubuntu\n'
    f'Suites: noble-security\nComponents: main\nArchitectures: amd64\nSigned-By: {KEYRING}\n'
    'Check-Valid-Until: yes\n').encode('ascii')
NODE_KEYS = {'path', 'device', 'inode', 'uid', 'gid', 'mode', 'kind'}


def require(condition, message):
    if not condition: raise ValueError(message)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def exact(left, right):
    return type(left) is type(right) and (set(left) == set(right)
        and all(exact(left[key], right[key]) for key in left) if type(left) is dict
        else len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
        if type(left) is list else left == right)


def locations(root):
    value = str(root)
    require(0 < len(value) <= 512, 'bounded native APT root length required')
    root = PurePosixPath(value)
    require(root.is_absolute() and not value.startswith('//') and len(root.parts) <= 24 and root.as_posix() == value
        and '..' not in root.parts and all(ord(c) >= 32 for c in str(root))
        and '\\' not in str(root) and ':' not in str(root), 'bounded absolute native APT source root required')
    directory = root / '.local-runs/canonical-native-apt'
    return directory, directory / 'native.sources', directory / 'empty-sources.d'


def arguments(root):
    _, sources, parts = locations(root)
    values = ['Dir::Etc::sourcelist=' + str(sources), 'Dir::Etc::sourceparts=' + str(parts),
        'Acquire::Languages=none', 'Acquire::AllowInsecureRepositories=false',
        'Acquire::AllowWeakRepositories=false', 'Acquire::AllowDowngradeToInsecureRepositories=false',
        'Acquire::Check-Valid-Until=true', 'APT::Get::AllowUnauthenticated=false']
    return [item for value in values for item in ('-o', value)]


def commands(root, packages):
    require(type(packages) is tuple and packages == PACKAGES, 'unchanged eleven native package requirements required')
    prefix = ['/usr/bin/apt-get', *arguments(root)]
    return (prefix + ['--error-on=any', 'update'], prefix + ['install', '--yes', '--no-install-recommends', *packages])


def node(path):
    info = path.lstat()
    require(not path.is_symlink() and not (hasattr(path, 'is_junction') and path.is_junction()), 'native APT paths cannot traverse links')
    kind = 'directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'other'
    return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
        'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'kind': kind}


def chain(paths):
    paths = sorted({parent for path in paths for parent in (path.parent, *path.parents)}, key=str)
    require(len(paths) <= 64, 'native APT ancestor count exceeded')
    rows = [node(path) for path in paths]
    for row in rows:
        require(row['kind'] == 'directory' and row['uid'] == row['gid'] == 0
            and (row['mode'] & 0o022 == 0 or row['mode'] & 0o1000)
            and row['mode'] & 0o005 == 0o005, 'root-owned protected and traversable native APT ancestors required')
    return rows


def read(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, 'bounded regular native APT file required')
        parts = []; count = 0
        while count <= limit:
            part = os.read(descriptor, min(65536, limit + 1 - count))
            if not part: break
            parts.append(part); count += len(part)
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, key) == getattr(after, key) for key in fields)
            and count == before.st_size, 'native APT file changed during bounded read')
        return b''.join(parts)
    finally: os.close(descriptor)


def validate(policy, *, root='/work/c'):
    directory, sources, parts = locations(root)
    require(type(policy) is dict and set(policy) == {'schema_version', 'method', 'root', 'source_bytes',
        'source_sha256', 'source_base64', 'keyring_bytes', 'keyring_sha256', 'nodes', 'ancestors', 'reference_qualified'}
        and type(policy['schema_version']) is int and policy['schema_version'] == 1
        and policy['method'] == METHOD and policy['root'] == str(root) and policy['reference_qualified'] is False,
        'closed native APT acquisition policy required')
    require(type(policy['source_bytes']) is int and policy['source_bytes'] == len(SOURCES)
        and policy['source_sha256'] == digest(SOURCES)
        and policy['source_base64'] == base64.b64encode(SOURCES).decode('ascii')
        and type(policy['keyring_bytes']) is int and 0 < policy['keyring_bytes'] <= 1024**2
        and type(policy['keyring_sha256']) is str and len(policy['keyring_sha256']) == 64
        and all(c in '0123456789abcdef' for c in policy['keyring_sha256']), 'original authenticated source/keyring byte binding differs')
    nodes = policy['nodes']; expected = [(str(directory), 'directory', 0o555),
        (str(sources), 'file', 0o444), (str(parts), 'directory', 0o555), (KEYRING, 'file', None)]
    require(type(nodes) is list and len(nodes) == 4, 'all original native APT nodes required')
    for row, (path, kind, mode) in zip(nodes, expected):
        require(type(row) is dict and set(row) == NODE_KEYS and row['path'] == path and row['kind'] == kind
            and all(type(row[key]) is int and row[key] >= 0 for key in ('device', 'inode', 'uid', 'gid', 'mode'))
            and row['uid'] == row['gid'] == 0 and (row['mode'] == mode if mode is not None
                else row['mode'] in (0o444, 0o644)), 'root-owned immutable/readable native APT node differs')
    ancestors = policy['ancestors']
    expected_parents = sorted({str(parent) for path in (sources, parts, PurePosixPath(KEYRING))
        for parent in (path.parent, *path.parents)})
    require(type(ancestors) is list and len(ancestors) == len(expected_parents) <= 64,
        'complete native APT ancestry required')
    for row, path in zip(ancestors, expected_parents):
        require(type(row) is dict and set(row) == NODE_KEYS and row['path'] == path and row['kind'] == 'directory'
            and all(type(row[key]) is int and row[key] >= 0 for key in ('device', 'inode', 'uid', 'gid', 'mode'))
            and row['uid'] == row['gid'] == 0 and (row['mode'] & 0o022 == 0 or row['mode'] & 0o1000)
            and row['mode'] & 0o005 == 0o005, 'protected native APT ancestor role differs')
    return policy


def observe(policy):
    validate(policy, root=policy['root'])
    directory, sources, parts = (Path(str(path)) for path in locations(policy['root']))
    key = Path(KEYRING); paths = (directory, sources, parts, key)
    before = [node(path) for path in paths]; ancestors = chain((sources, parts, key))
    require(exact(before, policy['nodes']) and exact(ancestors, policy['ancestors']) and not any(parts.iterdir()),
        'native APT node/ancestor identity changed or extra source appeared')
    require(read(sources, 8192) == SOURCES and digest(read(key, 1024**2)) == policy['keyring_sha256'],
        'native APT source/keyring bytes changed')
    after = [node(path) for path in paths]
    require(exact(before, after) and exact(ancestors, chain((sources, parts, key))), 'native APT nodes changed after read')
    return {'nodes': after, 'ancestors': ancestors}


def validate_acquisition(record, *, root='/work/c'):
    require(type(record) is dict and set(record) == {'policy', 'checks'}, 'original native APT acquisition record required')
    policy = validate(record['policy'], root=root)
    checks = record['checks']
    require(type(checks) is list and len(checks) == 2, 'both completed original native APT stages required')
    expected = {'nodes': policy['nodes'], 'ancestors': policy['ancestors']}
    for row, stage in zip(checks, ('apt-update', 'apt-install')):
        require(type(row) is dict and set(row) == {'stage', 'before', 'after'} and row['stage'] == stage
            and exact(row['before'], expected) and exact(row['after'], expected),
            'native APT nodes/ancestors must retain original identity across both acquisition commands')
    return policy


def publish(root):
    require(platform.system() == 'Linux' and hasattr(os, 'geteuid') and os.geteuid() == os.getegid() == 0,
        'actual owned Linux root native setup required')
    require(platform.machine() == 'x86_64', 'native amd64 Ubuntu acquisition required')
    directory, sources, parts = (Path(str(path)) for path in locations(root))
    key = Path(KEYRING); chain((directory, key))
    require(not directory.exists(), 'new exclusive native APT policy directory required')
    key_bytes = read(key, 1024**2)
    directory.mkdir(mode=0o755); parts.mkdir(mode=0o555)
    descriptor = os.open(sources, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444)
    try:
        written = os.write(descriptor, SOURCES); require(written == len(SOURCES), 'complete native APT source write required')
        os.fchmod(descriptor, 0o444); os.fsync(descriptor)
    finally: os.close(descriptor)
    os.chmod(parts, 0o555); os.chmod(directory, 0o555)
    policy = {'schema_version': 1, 'method': METHOD, 'root': str(root), 'source_bytes': len(SOURCES),
        'source_sha256': digest(SOURCES), 'source_base64': base64.b64encode(SOURCES).decode('ascii'),
        'keyring_bytes': len(key_bytes), 'keyring_sha256': digest(key_bytes),
        'nodes': [node(path) for path in (directory, sources, parts, key)],
        'ancestors': chain((sources, parts, key)), 'reference_qualified': False}
    observe(policy)
    for path in (parts, directory, directory.parent):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    return policy
