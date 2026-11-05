"""Actual capture-device access for the distinct canonical guest marker.

The original full-method guard and device helper stay unchanged. These calls
reuse its exact character-device inspection and descriptor/receipt checks with
the new guest's real identity. No bytes are transmitted and no host permission
or allocation is granted by the probe.
"""
import json
import os
from pathlib import Path
import platform
import stat
import sys
import time

from canonical_reference_guest_allocation import MARKER, MARKER_VALUE
from canonical_reference_allocation import require
from reference_allocation import read_bounded
from kvm_reference_device import (UID, GID, IDENTITY_KEYS, inspect_port,
    descriptor_matches, validate_access)

ROOT = Path(__file__).resolve().parents[1]


def check_marker(info, raw):
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
        and not info.st_mode & 0o022 and raw == MARKER_VALUE,
        'actual root-owned canonical guest marker differs')


def guard(uid):
    require(type(uid) is int and uid in (0, UID) and platform.system() == 'Linux'
        and ROOT == Path('/work/c') and hasattr(os, 'geteuid')
        and os.getuid() == os.geteuid() == uid
        and os.getgid() == os.getegid() == (0 if uid == 0 else GID),
        'actual canonical Linux guest and exact existing device identity required')
    check_marker(MARKER.lstat(), read_bounded(MARKER, 128))
    groups = os.getgroups()
    require(len(groups) <= 64 and all(type(group) is int and group >= 0 for group in groups)
        and (uid == 0 or groups == []), 'canonical device probe must clear supplementary groups')
    return {'uid': uid, 'gid': 0 if uid == 0 else GID, 'groups': groups}


def operate(report, *, configure):
    require(type(report) is dict and not report and type(configure) is bool,
        'new canonical device access observation and explicit operation required')
    report.update(guard(0 if configure else UID), status='FAIL', bytes_read=0, bytes_written=0)
    node, before = inspect_port(); report['identity_before'] = before
    require(before['uid'] in (0, UID) and before['gid'] in (0, GID), 'unexpected capture device owner')
    if not configure:
        require((before['uid'], before['gid'], before['mode']) == (UID, GID, 0o600),
            'capture device must have exact private measurement permissions')
    descriptor = os.open(node, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    report['opened_monotonic_ns'] = time.monotonic_ns()
    try:
        descriptor_matches(descriptor, before)
        if configure:
            os.fchown(descriptor, UID, GID); os.fchmod(descriptor, 0o600)
        after_node, after = inspect_port(); report['identity_after'] = after
        require(after_node == node and all(after[key] == before[key]
            for key in IDENTITY_KEYS - {'uid', 'gid', 'mode'}), 'named capture device changed')
        descriptor_matches(descriptor, after)
        require((after['uid'], after['gid'], after['mode']) == (UID, GID, 0o600),
            'actual capture device permissions differ')
    finally:
        os.close(descriptor); report['closed_monotonic_ns'] = time.monotonic_ns()
    report['status'] = 'GRANTED' if configure else 'OPENED'
    return report


def grant(report): return operate(report, configure=True)


def main():
    require(sys.argv[1:] == ['probe'], 'only the fixed nonroot canonical device probe is supported')
    report = {}
    try: operate(report, configure=False)
    except Exception as error: report.update(status='FAIL', error=type(error).__name__ + ': ' + str(error)[:1024])
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] != 'OPENED')


if __name__ == '__main__': raise SystemExit(main())
