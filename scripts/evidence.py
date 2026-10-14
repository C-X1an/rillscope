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

def input_identity(path: Path) -> dict:
    limit = 256 * 1024 * 1024
    hasher, size = hashlib.sha256(), 0
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            size += len(block)
            if size > limit: raise ValueError('evidence input exceeds capture limit')
            hasher.update(block)
    return {'path': str(path), 'sha256': hasher.hexdigest(), 'bytes': size}


def source_identity(root: Path = ROOT) -> dict:
    files = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            rel = path.relative_to(root)
            if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
                raise ValueError('source identity cannot follow a symbolic link or reparse point')
            if any(x in EXCLUDED - {'verification'} for x in rel.parts): continue
            if rel.parts[0] == 'verification' and rel.as_posix() not in ('verification', 'verification/spec-lock.json'): continue
            if path.is_dir(): pending.append(path)
            elif path.is_file(): files.append([rel.as_posix(), digest(path.read_bytes())])
            else: raise ValueError('source identity requires regular files/directories')
    files.sort()
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
    parser.add_argument('--input', type=Path, action='append', default=[], help='external operator input to fingerprint before/after')
    parser.add_argument('--stdin', type=Path, help='explicit bytes supplied to child stdin; never inherit unidentified input')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command: parser.error('command required after --')
    if args.out.exists(): parser.error('evidence directory must be new')
    args.out.mkdir(parents=True)
    before, git_before = source_identity(), git_state()
    started, clock = dt.datetime.now(dt.timezone.utc).isoformat(), time.perf_counter()
    outcome = 'EXECUTED'
    input_paths = list(args.input)
    stdin_required = False
    for i, item in enumerate(command[:-1]):
        if item in ('--catalog', '--context', '--query'):
            value = command[i + 1]
            if value == '-' and item == '--query': stdin_required = True
            else:
                path = Path(value)
                input_paths.append(path if path.is_absolute() else ROOT / path)
    if args.stdin is not None: input_paths.append(args.stdin)
    input_paths = sorted({path.resolve() for path in input_paths})
    inputs, inputs_after, stdin_sha256 = [], [], None
    try:
        if stdin_required and args.stdin is None: raise ValueError('explicit --stdin file required for --query -')
        inputs = [input_identity(path) for path in input_paths]
        stdin_data = args.stdin.read_bytes() if args.stdin is not None else None
        stdin_sha256 = digest(stdin_data) if stdin_data is not None else None
        p = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=args.timeout,
                           input=stdin_data, stdin=subprocess.DEVNULL if stdin_data is None else None)
        code, stdout, stderr = p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        code, stdout, stderr, outcome = 77, b'', b'Required executable or operator input file not found\n', 'BLOCKED'
    except subprocess.TimeoutExpired as error:
        code, stdout, stderr, outcome = 124, error.stdout or b'', error.stderr or b'', 'TIMEOUT'
    except ValueError:
        code, stdout, stderr, outcome = 77, b'', b'Required input provenance unavailable\n', 'BLOCKED'
    if inputs:
        try: inputs_after = [input_identity(path) for path in input_paths]
        except (OSError, ValueError): inputs_after = []
        if inputs_after != inputs and code == 0: outcome = 'INPUT_CHANGED'
    elapsed = time.perf_counter() - clock
    after = source_identity()
    if before['sha256'] != after['sha256'] and code == 0:
        # A mutating command's success remains real, but is not a stable-source verification.
        outcome = 'SOURCE_CHANGED'
    (args.out / 'stdout.txt').write_bytes(stdout); (args.out / 'stderr.txt').write_bytes(stderr)
    receipt = {'schema_version': 1, 'command': command, 'cwd': str(ROOT), 'started_utc': started,
               'finished_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'elapsed_seconds': elapsed,
               'exit_code': code, 'execution_outcome': outcome,
               'inputs_before': inputs, 'inputs_after': inputs_after,
               'stdin': None if args.stdin is None else {'file': str(args.stdin), 'sha256': stdin_sha256},
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
