"""Configure and actually open only the owned guest's named capture device.

The preflight transfers no protocol bytes and grants no host permissions. Its
observations are setup evidence, not allocation or benchmark qualification.
"""
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time

from kvm_pilot_common import require
from kvm_reference_channel import DEVICE, PORT_NAME

ROOT = Path(__file__).resolve().parents[1]
MARKER = Path('/run/rillscope-owned-reference')
UID = GID = 65534
IDENTITY_KEYS = {'alias', 'node', 'port_name', 'major', 'minor', 'filesystem_device',
    'inode', 'rdev', 'uid', 'gid', 'mode'}
REPORT_KEYS = {'status', 'identity_before', 'identity_after', 'uid', 'gid', 'groups',
    'opened_monotonic_ns', 'closed_monotonic_ns', 'bytes_read', 'bytes_written'}


def text(path):
    with path.open('rb') as stream: data = stream.read(257)
    require(0 < len(data) <= 256, 'bounded device/ownership identity required')
    return data.decode('ascii', errors='strict').strip()


def guard(uid):
    require(platform.system() == 'Linux' and ROOT == Path('/work/c')
        and hasattr(os, 'geteuid') and os.getuid() == os.geteuid() == uid
        and os.getgid() == os.getegid() == (0 if uid == 0 else GID),
        'owned Linux full guest and exact device identity required')
    marker = MARKER.lstat()
    require(stat.S_ISREG(marker.st_mode) and marker.st_uid == 0 and marker.st_gid == 0
        and not marker.st_mode & 0o022
        and text(MARKER) == 'owned-ephemeral-full-collection', 'owned full guest marker differs')
    groups = os.getgroups()
    require(len(groups) <= 64 and all(type(group) is int and group >= 0 for group in groups)
        and (uid == 0 or groups == []), 'device probe must have no supplementary groups')
    return {'uid': uid, 'gid': 0 if uid == 0 else GID, 'groups': groups}


def inspect_port():
    alias = Path(DEVICE)
    require(stat.S_ISLNK(alias.lstat().st_mode), 'exact named virtio alias required')
    node = alias.resolve(strict=True)
    require(re.fullmatch(r'/dev/vport[0-9]+p[0-9]+', node.as_posix()) is not None,
        'exact resolved vport character path required')
    info = node.lstat()
    require(stat.S_ISCHR(info.st_mode), 'resolved vport must be a character device')
    base = Path('/sys/class/virtio-ports') / node.name
    require(text(base / 'name') == PORT_NAME, 'sysfs virtio port name differs')
    number = text(base / 'dev')
    require(re.fullmatch('[0-9]+:[0-9]+', number) is not None, 'sysfs device number differs')
    major, minor = map(int, number.split(':'))
    require((major, minor) == (os.major(info.st_rdev), os.minor(info.st_rdev)),
        'sysfs and character device numbers differ')
    return node, {'alias': DEVICE, 'node': node.as_posix(), 'port_name': PORT_NAME,
        'major': major, 'minor': minor, 'filesystem_device': info.st_dev, 'inode': info.st_ino,
        'rdev': info.st_rdev, 'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}


def descriptor_matches(fd, value):
    info = os.fstat(fd)
    require(stat.S_ISCHR(info.st_mode) and (info.st_dev, info.st_ino, info.st_rdev,
        info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == tuple(value[key] for key in
        ['filesystem_device', 'inode', 'rdev', 'uid', 'gid', 'mode']),
        'opened device descriptor differs from the inspected exact port')


def operate(report, *, configure):
    require(type(report) is dict and not report, 'new device access observation required')
    report.update(guard(0 if configure else UID), status='FAIL', bytes_read=0, bytes_written=0)
    node, before = inspect_port(); report['identity_before'] = before
    require(before['uid'] in (0, UID) and before['gid'] in (0, GID), 'unexpected capture device owner')
    if not configure:
        require((before['uid'], before['gid'], before['mode']) == (UID, GID, 0o600),
            'capture device must have the exact private measurement permissions')
    # Opening the already resolved node with NOFOLLOW and comparing its inode
    # avoids applying permissions to a replacement alias or another device.
    fd = os.open(node, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    report['opened_monotonic_ns'] = time.monotonic_ns()
    try:
        descriptor_matches(fd, before)
        if configure:
            os.fchown(fd, UID, GID)
            os.fchmod(fd, 0o600)
        after_node, after = inspect_port(); report['identity_after'] = after
        require(after_node == node and all(after[key] == before[key] for key in
            IDENTITY_KEYS - {'uid', 'gid', 'mode'}), 'named capture device changed during access setup')
        descriptor_matches(fd, after)
        require((after['uid'], after['gid'], after['mode']) == (UID, GID, 0o600),
            'capture device permission grant did not take effect')
    finally:
        os.close(fd)
        report['closed_monotonic_ns'] = time.monotonic_ns()
    report['status'] = 'GRANTED' if configure else 'OPENED'
    return report


def grant(report): return operate(report, configure=True)


def probe(report): return operate(report, configure=False)


def validate_identity(value):
    require(type(value) is dict and set(value) == IDENTITY_KEYS
        and value['alias'] == DEVICE and value['port_name'] == PORT_NAME
        and isinstance(value['node'], str)
        and re.fullmatch(r'/dev/vport[0-9]+p[0-9]+', value['node']) is not None
        and all(type(value[key]) is int and value[key] >= 0 for key in
            IDENTITY_KEYS - {'alias', 'node', 'port_name'})
        and value['inode'] > 0 and value['rdev'] > 0 and value['mode'] <= 0o7777,
        'closed exact device identity required')


def validate_access(grant_report, probe_report):
    for value, status, uid in [(grant_report, 'GRANTED', 0), (probe_report, 'OPENED', UID)]:
        require(type(value) is dict and set(value) == REPORT_KEYS and value['status'] == status
            and type(value['uid']) is int and value['uid'] == uid
            and type(value['gid']) is int and value['gid'] == (0 if uid == 0 else GID)
            and type(value['groups']) is list and len(value['groups']) <= 64
            and all(type(group) is int and group >= 0 for group in value['groups'])
            and (uid == 0 or value['groups'] == [])
            and all(type(value[key]) is int and value[key] == 0 for key in ['bytes_read', 'bytes_written'])
            and all(type(value[key]) is int and value[key] > 0 for key in
                ['opened_monotonic_ns', 'closed_monotonic_ns'])
            and value['opened_monotonic_ns'] <= value['closed_monotonic_ns'],
            'closed device grant and actual nobody open/close observations required')
        validate_identity(value['identity_before']); validate_identity(value['identity_after'])
    before = grant_report['identity_before']; after = grant_report['identity_after']
    require(before['uid'] in (0, UID) and before['gid'] in (0, GID)
        and all(before[key] == after[key] for key in IDENTITY_KEYS - {'uid', 'gid', 'mode'})
        and (after['uid'], after['gid'], after['mode']) == (UID, GID, 0o600)
        and probe_report['identity_before'] == probe_report['identity_after'] == after
        and grant_report['closed_monotonic_ns'] <= probe_report['opened_monotonic_ns'],
        'device grant and actual nobody descriptor identity/mode/order differ')


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    require(argv == ['probe'], 'only the fixed unprivileged device probe is supported')
    report = {}
    try: probe(report)
    except Exception as error:
        report.update(status='FAIL', error=type(error).__name__ + ': ' + str(error)[:1024])
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] != 'OPENED')


if __name__ == '__main__': raise SystemExit(main())
