"""Finite Linux receiver for the separate full fresh-reference byte method."""
import argparse
import json
from pathlib import Path
import platform
import signal
import socket
import stat
import subprocess
import time

import archive_capture
from evidence import source_identity
from kvm_pilot_common import require, write_json
from kvm_reference_channel import Receiver
from kvm_reference_common import METHOD, identity

ROOT = Path(__file__).resolve().parents[1]
MAX_SECONDS = 21600


def interrupted(_signal, _frame): raise KeyboardInterrupt('owned reference receiver interrupted')


def git_identity(commit):
    command = ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'safe.directory=' + str(ROOT)]
    head = subprocess.check_output(command + ['rev-parse', 'HEAD'], cwd=ROOT, timeout=10).decode().strip()
    dirty = subprocess.check_output(command + ['status', '--porcelain'], cwd=ROOT, timeout=10)
    require(head == commit and not dirty.strip(), 'receiver must use the exact clean captured commit')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket', type=Path, required=True); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--timeout', type=int, required=True); parser.add_argument('--commit', required=True)
    parser.add_argument('--source-sha256', required=True); args = parser.parse_args()
    if platform.system() != 'Linux':
        print(json.dumps({'status': 'BLOCKED', 'reason': 'actual Linux owned virtio socket required',
            'method': METHOD, 'reference_qualified': False})); return 77
    identity(args.commit, args.source_sha256)
    require(1 <= args.timeout <= MAX_SECONDS, 'finite receiver lifetime within provider ceiling required')
    path = archive_capture.owned(args.socket); out = archive_capture.owned(args.out)
    require(stat.S_ISSOCK(path.lstat().st_mode), 'owned UNIX capture socket required')
    report = {'status': 'FAIL', 'method': METHOD, 'reference_qualified': False,
        'all_record_validation': 'NOT RUN', 'source_before': source_identity(),
        'scope': 'CAS bytes and method declarations only; original command failure and full outcome/allocation/fresh qualification remain separate'}
    require(report['source_before']['sha256'] == args.source_sha256, 'receiver exact source differs from expected session')
    git_identity(args.commit)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); connection.settimeout(2)
    receiver = None; started = time.monotonic()
    for number in (signal.SIGINT, signal.SIGTERM): signal.signal(number, interrupted)
    try:
        connection.connect(str(path))
        receiver = Receiver(connection, out, commit=args.commit, source_sha256=args.source_sha256)
        while not receiver.eof:
            require(time.monotonic() - started < args.timeout, 'owned reference capture deadline exhausted')
            receiver.drain(); time.sleep(.005)
        require(receiver.completion()['status'] == 'VERIFIED HOST BYTES',
                'receiver ended with missing full-method stages; every available frame remains retained')
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
        transport_completion=receiver.completion() if receiver else None, source_after=source_identity())
    if report['source_after'] != report['source_before']: report['status'] = 'FAIL'
    write_json(out.parent / 'reference-receiver-result.json', report)
    print(json.dumps({'status': report['status'], 'method': METHOD, 'archives': len(report['transfers']),
        'all_record_validation': 'NOT RUN', 'reference_qualified': False}))
    return int(report['status'] != 'PASS')


if __name__ == '__main__': raise SystemExit(main())
