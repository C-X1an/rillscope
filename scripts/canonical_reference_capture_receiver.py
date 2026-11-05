"""Stoppable byte receiver on the controller's already granted socket.

This process never allocates a guest or accepts a second lifetime exchange.
The real root parent must retain the prior reservation and pass the original
deadline. All capture frames and CAS validators remain the unchanged method.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import struct
import time

import archive_capture
import canonical_reference_allocation as allocation
from canonical_reference_reservation import source_check
from kvm_pilot_common import write_json
from kvm_reference_channel import Receiver
from reference_allocation import read_bounded


def peer_credentials(raw, expected_pid):
    allocation.require(type(raw) is bytes and len(raw) == 12 and allocation.integer(expected_pid),
        'exact original UNIX peer credentials required')
    pid, uid, gid = struct.unpack('3i', raw)
    allocation.require(pid == expected_pid and uid >= 0 and gid >= 0,
        'inherited capture socket does not belong to the original QEMU peer')
    return {'pid': pid, 'uid': uid, 'gid': gid}


def interrupted(_number, _frame): raise KeyboardInterrupt('owned canonical receiver interrupted')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fd', type=int, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--grant', type=Path, required=True)
    parser.add_argument('--controller-pid', type=int, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        print(json.dumps({'status': 'BLOCKED', 'reason': 'actual existing Linux root inherited socket required'})); return 77
    allocation.require(type(args.fd) is int and args.fd >= 3
        and allocation.integer(args.controller_pid) and os.getppid() == args.controller_pid,
        'actual original controller parent and inherited descriptor required')
    grant_path = archive_capture.owned(args.grant)
    allocation.require(grant_path.lstat().st_uid == 0 and not grant_path.lstat().st_mode & 0o022,
        'original root-owned private grant required')
    raw = read_bounded(grant_path, allocation.FRAME_LIMIT)
    grant = allocation.decode(raw)
    request = {key: grant[key] for key in allocation.REQUEST_KEYS}; request['kind'] = allocation.REQUEST_KIND
    allocation.validate_grant(grant, request)
    allocation.require(grant['authority']['controller']['pid'] == args.controller_pid,
        'original grant controller differs from actual parent')
    source_check(grant['commit'], grant['source_sha256'])
    out = archive_capture.owned(args.out)
    connection = socket.socket(fileno=args.fd)
    receiver = None
    report = {'status': 'FAIL', 'method': allocation.METHOD, 'reference_qualified': False,
        'grant_sha256': hashlib.sha256(raw).hexdigest(), 'controller_pid': args.controller_pid,
        'started_monotonic_ns': time.monotonic_ns(),
        'scope': 'Inherited prior-grant socket and original three CAS frames only; ACK is not a semantic or canonical qualification.'}
    for number in (signal.SIGINT, signal.SIGTERM): signal.signal(number, interrupted)
    try:
        allocation.require(connection.family == socket.AF_UNIX and connection.type == socket.SOCK_STREAM,
            'actual inherited UNIX stream required')
        report['peer'] = peer_credentials(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
            grant['authority']['qemu']['pid'])
        receiver = Receiver(connection, out, commit=grant['commit'], source_sha256=grant['source_sha256'])
        while not receiver.eof:
            allocation.require(time.monotonic_ns() < grant['host_vm_deadline_monotonic_ns'],
                'original granted VM deadline exhausted; no receiver-time reset')
            receiver.drain(); time.sleep(.005)
        allocation.require(receiver.completion()['status'] == 'VERIFIED HOST BYTES',
            'original three capture frames missing; partial bytes remain failed')
        source_check(grant['commit'], grant['source_sha256'])
        allocation.require(read_bounded(args.grant, allocation.FRAME_LIMIT) == raw, 'original allocation grant changed')
        report['status'] = 'VERIFIED HOST BYTES'
    except (Exception, KeyboardInterrupt) as error:
        report.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048])
    finally:
        for number in (signal.SIGINT, signal.SIGTERM): signal.signal(number, signal.SIG_IGN)
        try:
            if receiver is not None: receiver.close()
            else: connection.close()
        except Exception as error: report.update(status='FAIL', close_error=type(error).__name__)
        report.update(transfers=receiver.records if receiver else [],
            completion=receiver.completion() if receiver else None, finished_monotonic_ns=time.monotonic_ns())
        write_json(out.parent / 'capture-receiver-result.json', report)
    print(json.dumps({'status': report['status'], 'method': allocation.METHOD,
        'captures': len(report['transfers']), 'reference_qualified': False}))
    return 0 if report['status'] == 'VERIFIED HOST BYTES' else 1


if __name__ == '__main__': raise SystemExit(main())
