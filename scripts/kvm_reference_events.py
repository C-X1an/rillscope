"""Closed, source-bound full collection lifecycle on the owned serial stream."""
import base64
import json
from pathlib import Path
import re
import time

from kvm_pilot_common import require
from kvm_reference_common import METHOD, identity, strict_json

PREFIX = 'RILLSCOPE_FULL_CAPTURE_V1 '
PHASES = {'setup-start', 'setup-end', 'ready', 'guest-failure', 'guest-exit'}
MAX_RECORD = 65536
MAX_EVENTS = 16


def check(row):
    require(type(row) is dict and row.get('phase') in PHASES and row.get('method') == METHOD
        and row.get('reference_qualified') is False
        and isinstance(row.get('boot_id'), str)
        and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', row['boot_id'])
        and all(type(row.get(key)) is int and row[key] > 0 for key in ['utc_ns', 'monotonic_ns']),
        'full collection lifecycle method, boot or clock differs')
    if row['phase'] == 'ready':
        identity(row.get('commit'), row.get('source_sha256'))
        require(row.get('stage') == 'grid' and type(row.get('binary_sha256')) is dict
            and set(row['binary_sha256']) == {'rillscope', 'rillscope-measure'}
            and all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
                    for value in row['binary_sha256'].values())
            and all(isinstance(row.get(key), str) and re.fullmatch('[0-9a-f]{64}', row[key])
                    for key in ['request_sha256', 'config_sha256']), 'full collection ready identity differs')
    return row


def emit(phase, **fields):
    row = check({'phase': phase, 'method': METHOD,
        'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(),
        'reference_qualified': False, **fields})
    data = json.dumps(row, separators=(',', ':'), allow_nan=False).encode()
    require(len(data) <= MAX_RECORD, 'full collection lifecycle record exceeds bound')
    print(PREFIX + base64.b64encode(data).decode('ascii'), flush=True)
    return row


def parse(serial):
    rows = []
    for line in serial.splitlines():
        if PREFIX not in line: continue
        data = line.split(PREFIX, 1)[1].strip()
        require(len(data) <= 90000, 'full collection serial frame exceeds bound')
        decoded = base64.b64decode(data, validate=True)
        require(len(decoded) <= MAX_RECORD, 'decoded full collection frame exceeds bound')
        row = check(strict_json(decoded)); rows.append(row)
        require(len(rows) <= MAX_EVENTS, 'full collection lifecycle count exceeds bound')
    if rows:
        require(len({row['boot_id'] for row in rows}) == 1
            and all(b['monotonic_ns'] > a['monotonic_ns'] for a, b in zip(rows, rows[1:])),
            'full collection lifecycle rebooted or reversed its clock')
        require(sum(row['phase'] == 'ready' for row in rows) <= 1
            and sum(row['phase'] == 'guest-exit' for row in rows) <= 1,
            'full collection readiness or exit was replayed')
    return rows
