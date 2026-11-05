"""Owned Linux receiver process, independent of the coordinator sampler."""
import argparse
import json
import os
from pathlib import Path
import platform
import signal
import socket
import stat
import time

import archive_capture
from evidence import source_identity
from kvm_capture_channel import Receiver
from kvm_pilot_common import VM_SECONDS, require, write_json


def interrupted(_signal, _frame): raise KeyboardInterrupt('owned receiver interrupted')


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True); parser.add_argument('--timeout', type=int, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux':
        print(json.dumps({'status': 'BLOCKED', 'reason': 'requires actual Linux virtio host socket',
            'reference_qualified': False})); return 77
    require(1 <= args.timeout <= VM_SECONDS, 'closed receiver deadline required')
    path = archive_capture.owned(args.socket); out = archive_capture.owned(args.out)
    require(stat.S_ISSOCK(path.lstat().st_mode), 'owned UNIX capture socket required')
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); connection.settimeout(2)
    receiver = None; started = time.monotonic()
    report = {'status': 'FAIL', 'reference_qualified': False, 'source_before': source_identity()}
    for number in (signal.SIGINT, signal.SIGTERM): signal.signal(number, interrupted)
    try:
        connection.connect(str(path)); receiver = Receiver(connection, out)
        while not receiver.eof:
            require(time.monotonic() - started < args.timeout, 'owned capture receiver deadline exhausted')
            receiver.drain(); time.sleep(.005)
        require(len(receiver.records) == 3, 'receiver ended without all three original archives')
        report['status'] = 'PASS'
    except (Exception, KeyboardInterrupt) as error:
        report.update(error=type(error).__name__, reason=str(error)[:2048])
    finally:
        for number in (signal.SIGINT, signal.SIGTERM): signal.signal(number, signal.SIG_IGN)
        try:
            if receiver is not None: receiver.close()
            else: connection.close()
        except Exception as error: report.update(status='FAIL', close_error=type(error).__name__)
    report.update(transfers=receiver.records if receiver else [], elapsed_seconds=time.monotonic() - started,
                  source_after=source_identity())
    if report['source_after'] != report['source_before']: report['status'] = 'FAIL'
    write_json(out.parent / 'receiver-result.json', report)
    print(json.dumps({'status': report['status'], 'archives': len(report['transfers']), 'reference_qualified': False}))
    return int(report['status'] != 'PASS')


if __name__ == '__main__': raise SystemExit(main())
