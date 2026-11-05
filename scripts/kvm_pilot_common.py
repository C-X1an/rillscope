"""Bounded transport and deadlines for the unqualified KVM feasibility pilot."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

PREFIX = 'RILLSCOPE_KVM_PILOT_V1 '
STAGES = (('instrument', 'instrumentation-pilot', 1200),
          ('tail', 'kvm-cost-tail-pilot', 1800), ('cancel', 'cancellation-only', 600))
HOST_PREP_SECONDS = 600
SETUP_SECONDS = 900
PACKAGE_SECONDS = 180
VM_SECONDS = SETUP_SECONDS + sum(row[2] for row in STAGES) + 3 * PACKAGE_SECONDS + 60
RECOVERY_SECONDS = 600
CLEANUP_SECONDS = 120
RESERVE_SECONDS = 180
TOTAL_SECONDS = HOST_PREP_SECONDS + VM_SECONDS + RECOVERY_SECONDS + CLEANUP_SECONDS + RESERVE_SECONDS
PHASES = {'ready', 'network-down', 'stage-start', 'stage-end', 'pack-start', 'pack-end',
          'guest-exit', 'guest-failure'}
MAX_LOG = 128 * 1024**2
MAX_RECORD = 65536
MAX_PAYLOAD_FILES = 4096
MAX_PAYLOAD_BYTES = 512 * 1024**2
MAX_PAYLOAD_FILE = 64 * 1024**2


def require(condition, message):
    if not condition: raise ValueError(message)


def sha(path, limit=256 * 1024**2):
    digest = hashlib.sha256(); size = 0
    with Path(path).open('rb') as stream:
        while block := stream.read(1024 * 1024):
            size += len(block); require(size <= limit, 'file exceeds explicit hash bound')
            digest.update(block)
    return digest.hexdigest()


def read_json(path, limit=4 * 1024**2):
    with Path(path).open('rb') as stream: data = stream.read(limit + 1)
    require(len(data) <= limit, 'JSON exceeds explicit byte bound')
    return json.loads(data)


def write_json(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')
    require(len(data) <= 4 * 1024**2, 'metadata exceeds explicit byte bound')
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + '.pending-' + str(time.time_ns()))
    with pending.open('xb') as stream:
        require(stream.write(data) == len(data), 'metadata write was incomplete')
        stream.flush(); os.fsync(stream.fileno())
    # Bounded retry for a transient sharing lock on an owned metadata file.
    # Persistent permission errors still fail and retain the exact pending bytes.
    for attempt in range(4):
        try: os.replace(pending, path); break
        except PermissionError:
            if attempt == 3: raise
            time.sleep(.02 * (attempt + 1))


def append_json(path, value, *, limit=MAX_LOG):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
    require(len(data) <= MAX_RECORD, 'observation exceeds record bound')
    with Path(path).open('ab') as stream:
        require(stream.tell() + len(data) <= limit, 'observation log exceeds byte bound')
        require(stream.write(data) == len(data), 'observation write was incomplete')
        stream.flush()


def emit(phase, **fields):
    require(phase in PHASES, 'unknown guest protocol phase')
    row = {'phase': phase, 'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(),
           'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
           'reference_qualified': False, **fields}
    data = json.dumps(row, separators=(',', ':'), allow_nan=False).encode()
    require(len(data) <= MAX_RECORD, 'guest protocol record exceeds bound')
    print(PREFIX + base64.b64encode(data).decode('ascii'), flush=True)
    return row


def parse_events(serial):
    rows = []
    for line in serial.splitlines():
        if PREFIX not in line: continue
        encoded = line.split(PREFIX, 1)[1].strip()
        require(len(encoded) <= 90000, 'guest serial record exceeds bound')
        data = base64.b64decode(encoded, validate=True)
        require(len(data) <= MAX_RECORD, 'decoded guest record exceeds bound')
        row = json.loads(data)
        require(isinstance(row, dict) and row.get('phase') in PHASES
                and row.get('reference_qualified') is False
                and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', row.get('boot_id', ''))
                and all(type(row.get(k)) is int and row[k] > 0 for k in ('utc_ns', 'monotonic_ns')),
                'guest protocol identity/clock differs')
        rows.append(row); require(len(rows) <= 64, 'guest phase count exceeds bound')
    if rows:
        require(len({row['boot_id'] for row in rows}) == 1, 'guest rebooted')
        require(all(b['monotonic_ns'] > a['monotonic_ns'] for a, b in zip(rows, rows[1:])),
                'guest phase clock did not advance')
    return rows


def payload_files(root):
    """Hash the exact public checkout, Git metadata and selected build artifacts."""
    root = Path(root).resolve(); rows = []; total = 0; pending = [root]
    while pending:
        for path in sorted(pending.pop().iterdir()):
            relative = path.relative_to(root).as_posix()
            if relative == '.local-runs/kvm-input/payload.json' or relative.startswith('.local-runs/kvm-pilot/'):
                continue
            value = path.lstat()
            require(not path.is_symlink(), 'payload cannot contain links')
            if stat.S_ISDIR(value.st_mode): pending.append(path); continue
            require(stat.S_ISREG(value.st_mode), 'payload requires regular files')
            require(len(rows) < MAX_PAYLOAD_FILES and value.st_size <= MAX_PAYLOAD_FILE,
                    'payload file count/size exceeds bound')
            total += value.st_size; require(total <= MAX_PAYLOAD_BYTES, 'payload total exceeds bound')
            rows.append({'path': relative, 'bytes': value.st_size,
                         'mode': stat.S_IMODE(value.st_mode), 'sha256': sha(path, MAX_PAYLOAD_FILE)})
    return sorted(rows, key=lambda row: row['path'])
