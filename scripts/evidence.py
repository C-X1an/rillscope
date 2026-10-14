#!/usr/bin/env python3
"""Capture an actual command and immutable byte hashes; never accept a PASS flag."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', '.local-runs', '__pycache__', 'target', 'verification'}


def digest(data: bytes) -> str: return hashlib.sha256(data).hexdigest()


def source_identity(root: Path = ROOT) -> dict:
    files = []
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if any(x in EXCLUDED for x in rel.parts) or not path.is_file(): continue
        if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
            raise ValueError('source identity cannot follow a symbolic link or reparse point')
        files.append([rel.as_posix(), digest(path.read_bytes())])
    return {'sha256': digest(json.dumps(files, separators=(',', ':')).encode()), 'files': files}


def git_state() -> dict:
    def run(*args):
        try:
            p = subprocess.run(['git', *args], cwd=ROOT, capture_output=True, text=True, timeout=5)
            return p.stdout.strip() if p.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired): return None
    status = run('status', '--porcelain')
    return {'commit': run('rev-parse', 'HEAD'), 'dirty': None if status is None else bool(status)}


def verify_receipt(path: Path) -> bool:
    data = json.loads(path.read_text())
    return all(digest((path.parent / data[key]['file']).read_bytes()) == data[key]['sha256']
               for key in ('stdout', 'stderr'))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=300)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command: parser.error('command required after --')
    if args.out.exists(): parser.error('evidence directory must be new')
    args.out.mkdir(parents=True)
    before, git_before = source_identity(), git_state()
    started, clock = dt.datetime.now(dt.timezone.utc).isoformat(), time.perf_counter()
    outcome = 'EXECUTED'
    try:
        p = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=args.timeout)
        code, stdout, stderr = p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        code, stdout, stderr, outcome = 77, b'', b'Required executable not found\n', 'BLOCKED'
    except subprocess.TimeoutExpired as error:
        code, stdout, stderr, outcome = 124, error.stdout or b'', error.stderr or b'', 'TIMEOUT'
    elapsed = time.perf_counter() - clock
    after = source_identity()
    if before['sha256'] != after['sha256'] and code == 0:
        # A mutating command's success remains real, but is not a stable-source verification.
        outcome = 'SOURCE_CHANGED'
    (args.out / 'stdout.txt').write_bytes(stdout); (args.out / 'stderr.txt').write_bytes(stderr)
    receipt = {'schema_version': 1, 'command': command, 'cwd': str(ROOT), 'started_utc': started,
               'finished_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'elapsed_seconds': elapsed,
               'exit_code': code, 'execution_outcome': outcome,
               'verification_status': 'BLOCKED' if outcome == 'BLOCKED' else ('PASS' if code == 0 and outcome == 'EXECUTED' else 'FAIL'),
               'environment': {'python': platform.python_version(), 'sqlite': sqlite3.sqlite_version,
                               'system': platform.system(), 'machine': platform.machine(),
                               'cpu_count': os.cpu_count()},
               'source_before': before, 'source_after_sha256': after['sha256'], 'git': git_before,
               'stdout': {'file': 'stdout.txt', 'sha256': digest(stdout)},
               'stderr': {'file': 'stderr.txt', 'sha256': digest(stderr)}}
    (args.out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    sys.stdout.buffer.write(stdout); sys.stderr.buffer.write(stderr)
    print(json.dumps({'receipt': str(args.out / 'receipt.json'), 'exit_code': code, 'status': receipt['verification_status']}))
    return code


if __name__ == '__main__': raise SystemExit(main())
