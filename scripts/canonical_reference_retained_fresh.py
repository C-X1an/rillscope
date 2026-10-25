"""Replay retained native fresh receipts without recreating their checkout.

The original source paths remain data. Included byte custody and recorded fresh
execution do not establish allocator authority or benchmark qualification.
"""
import datetime as dt
import hashlib
import math
import os
from pathlib import PurePosixPath
import re
import stat

import archive_capture
from canonical_reference_allocation import require, hex_value
from canonical_reference_attempt_check import canonical_shape
from kvm_reference_common import strict_json
from verify_sequence import read_plan

MAX_FILES = 1024
MAX_FILE = 16 * 1024**2
MAX_BYTES = 64 * 1024**2
NATIVE_ROOT = PurePosixPath('/work/c')


def relative(value):
    require(type(value) is str and 0 < len(value) <= 4096 and '\\' not in value
        and ':' not in value and '\x00' not in value, 'closed original relative evidence path required')
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value
        and all(part not in ('', '.', '..') for part in value.split('/')),
        'original evidence path must be canonical and cannot traverse parents')
    return path


def bounded_hash(path, limit):
    before = path.stat()
    require(path.is_file() and not path.is_symlink() and 0 <= before.st_size <= limit,
        'bounded regular retained file required')
    value = hashlib.sha256(); size = 0
    with path.open('rb') as stream:
        while block := stream.read(1024**2):
            size += len(block); require(size <= before.st_size, 'retained file grew while checking')
            value.update(block)
    after = path.stat()
    require(size == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'retained file changed while checking')
    return value.hexdigest(), size


def read_bounded_file(path, limit, expected_sha256=None):
    """One bounded descriptor read; growth is rejected before unbounded allocation."""
    require(type(limit) is int and 0 <= limit <= MAX_BYTES, 'explicit bounded retained metadata read required')
    path = archive_capture.owned(path); before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink() and 0 <= before.st_size <= limit,
        'bounded regular retained file required before reading')
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    chunks = []; size = 0; value = hashlib.sha256()
    with path.open('rb') as stream:
        descriptor = os.fstat(stream.fileno())
        require(stat.S_ISREG(descriptor.st_mode) and identity(descriptor) == identity(before),
            'retained descriptor identity differs before reading')
        while block := stream.read(min(65536, limit - size + 1)):
            size += len(block); require(size <= limit and size <= before.st_size, 'retained file grew beyond original byte bound')
            value.update(block); chunks.append(block)
        require(identity(os.fstat(stream.fileno())) == identity(before), 'retained descriptor changed during read')
    require(size == before.st_size and identity(path.lstat()) == identity(before)
        and (expected_sha256 is None or value.hexdigest() == expected_sha256),
        'retained file changed or original digest differs')
    return b''.join(chunks)


class RetainedMetadata:
    """Closed original-path index, backed only by digest-checked included bytes."""

    def __init__(self, root):
        self.root = archive_capture.owned(root)
        self.manifest_path = archive_capture.owned(self.root / 'retention.json')
        manifest_raw = read_bounded_file(self.manifest_path, MAX_FILE)
        self.manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
        self.manifest = strict_json(manifest_raw)
        require(type(self.manifest) is dict and self.manifest.get('status') == 'RETAINED',
            'complete original release retention record required')
        rows = self.manifest.get('metadata')
        require(type(rows) is list and 0 < len(rows) <= MAX_FILES, 'bounded nonempty retained metadata index required')
        self.rows = {}; destinations = set(); total = 0
        for row in rows:
            require(type(row) is dict and set(row) == {'source', 'file', 'bytes', 'sha256'}
                and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE
                and hex_value(row['sha256'], 64), 'closed retained metadata identity required')
            source, destination = relative(row['source']), relative(row['file'])
            require(source.parts[0] == '.local-runs' and destination.parts[0] == 'metadata'
                and row['source'] not in self.rows and row['file'] not in destinations,
                'duplicate or unrelated retained metadata path')
            total += row['bytes']; require(total <= MAX_BYTES, 'retained metadata aggregate bound exceeded')
            path = archive_capture.owned(self.root / destination.as_posix())
            require(path.is_relative_to(self.root) and bounded_hash(path, MAX_FILE) == (row['sha256'], row['bytes']),
                'retained original metadata bytes differ')
            self.rows[row['source']] = row; destinations.add(row['file'])
        require(type(self.manifest.get('metadata_bytes')) is int and self.manifest['metadata_bytes'] == total,
            'retained metadata byte total differs')

    def raw(self, source, limit=MAX_FILE):
        name = relative(str(source)).as_posix()
        require(name in self.rows and self.rows[name]['bytes'] <= limit, 'required original retained metadata absent or oversized')
        row = self.rows[name]; path = archive_capture.owned(self.root / row['file'])
        data = read_bounded_file(path, row['bytes'], row['sha256'])
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'],
            'retained original metadata changed since indexing')
        return data

    def document(self, source, limit=MAX_FILE):
        row = strict_json(self.raw(source, limit))
        require(type(row) is dict, 'original retained metadata object required')
        return row

    def unchanged(self):
        require(bounded_hash(self.manifest_path, MAX_FILE)[0] == self.manifest_sha256,
            'original retention manifest changed during validation')
        for name in self.rows: self.raw(name)


def instant(value):
    require(type(value) is str and len(value) <= 64, 'bounded original UTC timestamp required')
    result = dt.datetime.fromisoformat(value)
    require(result.tzinfo is not None and result.utcoffset() == dt.timedelta(0),
        'original UTC offset required')
    return result


def receipt(metadata, directory, *, source, commit, command, cwd):
    directory = relative(str(directory)); row = metadata.document(directory / 'receipt.json', 8 * 1024**2)
    require(type(row.get('schema_version')) is int and row['schema_version'] == 1
        and row.get('command') == command and row.get('cwd') == str(cwd)
        and row.get('source_before') == source and row.get('source_after_sha256') == source['sha256']
        and row.get('verification_status') == 'PASS' and row.get('execution_outcome') == 'EXECUTED'
        and type(row.get('exit_code')) is int and row['exit_code'] == 0,
        'original native command/source/status differs')
    cleanup = row.get('process_cleanup'); environment = row.get('environment'); git = row.get('git')
    require(type(cleanup) is dict and cleanup.get('status') == 'PASS'
        and type(cleanup.get('remaining_active_processes')) is int and cleanup['remaining_active_processes'] == 0
        and type(environment) is dict and environment.get('system') == 'Linux'
        and type(git) is dict and git.get('commit') == commit and git.get('dirty') is False,
        'original command lacks clean source/native runtime/complete cleanup')
    require(type(row.get('elapsed_seconds')) in (int, float) and math.isfinite(row['elapsed_seconds'])
        and row['elapsed_seconds'] >= 0 and instant(row['started_utc']) <= instant(row['finished_utc']),
        'original command interval is invalid')
    for name in ('stdout', 'stderr'):
        stream = row.get(name)
        require(type(stream) is dict and set(stream) == {'file', 'sha256'}
            and stream['file'] == name + '.txt'
            and hashlib.sha256(metadata.raw(directory / stream['file'])).hexdigest() == stream['sha256'],
            'original command raw output digest differs')
    before, after = row.get('inputs_before'), row.get('inputs_after')
    require(type(before) is list and type(after) is list and len(before) <= 128 and before == after,
        'complete unchanged original input provenance arrays required')
    require('stdin' in row and row['stdin'] is None, 'original fixed clone/make commands must retain explicit absent stdin')
    for entries in (before, after):
        paths = set()
        for entry in entries:
            require(type(entry) is dict and set(entry) == {'path', 'sha256', 'bytes'}
                and type(entry['path']) is str and 0 < len(entry['path']) <= 4096
                and '\\' not in entry['path'] and ':' not in entry['path'] and '\x00' not in entry['path']
                and hex_value(entry['sha256'], 64) and type(entry['bytes']) is int and 0 <= entry['bytes'] < 2**63,
                'closed original input identity required')
            path = PurePosixPath(entry['path'])
            require(path.is_absolute() and path.as_posix() == entry['path'] and '..' not in path.parts
                and entry['path'] not in paths, 'duplicate or noncanonical original input identity path')
            paths.add(entry['path'])
    return row


def validate_fresh(metadata, *, commit, source, validator_root):
    require(hex_value(commit, 40) and type(source) is dict and hex_value(source.get('sha256'), 64),
        'exact expected native fresh identity required')
    attempts = sorted(name for name in metadata.rows
        if re.fullmatch(r'\.local-runs/clean-[A-Za-z0-9_-]+/results\.json', name))
    require(len(attempts) == 1, 'exactly one retained original fresh attempt required; never select latest')
    result_name = PurePosixPath(attempts[0]); attempt = result_name.parent
    result = metadata.document(result_name, 1024**2)
    commands = canonical_shape(result, commit=commit, source_sha256=source['sha256'])
    clone = attempt / 'c'; native_clone = NATIVE_ROOT / clone
    require(result.get('checkout') == clone.as_posix(), 'original exact fresh checkout path differs')
    preparation = result.get('preparation')
    require(type(preparation) is list and len(preparation) == 1 and type(preparation[0]) is dict
        and preparation[0].get('operation') == 'clone' and preparation[0].get('state') == 'COMPLETED'
        and preparation[0].get('status') == 'PASS' and type(preparation[0].get('exit_code')) is int
        and preparation[0]['exit_code'] == 0
        and preparation[0].get('receipt') == (attempt / 'preparation/clone').as_posix(),
        'one original completed fresh clone preparation required')
    first = receipt(metadata, attempt / 'preparation/clone', source=source, commit=commit,
        command=['git', 'clone', '--no-local', '--config', 'core.autocrlf=false', str(NATIVE_ROOT), str(native_clone)],
        cwd=NATIVE_ROOT)
    previous_end = instant(first['finished_utc']); enclosing = None
    for row in commands:
        directory = attempt / 'commands' / row['target']
        require(row.get('receipt') == directory.as_posix()
            and row.get('source_before') == row.get('source_after') == source['sha256'],
            'canonical command pointer/source differs')
        proof = receipt(metadata, directory, source=source, commit=commit,
            command=['make', row['target']], cwd=native_clone)
        require(previous_end <= instant(proof['started_utc']), 'original canonical command intervals overlap or reorder')
        previous_end = instant(proof['finished_utc'])
        if row['target'] == 'verify': enclosing = proof
    ledger_name = clone / '.local-runs/verify-ledger/ledger.json'
    ledger = metadata.document(ledger_name, 1024**2); plan = read_plan(validator_root)
    require(type(ledger.get('schema_version')) is int and ledger['schema_version'] == 1
        and ledger.get('source_sha256') == source['sha256'] and ledger.get('plan') == plan
        and ledger.get('status') == 'PASS' and type(ledger.get('commands')) is list
        and len(ledger['commands']) == len(plan) == 18,
        'all eighteen original authoritative gates required')
    previous_end = instant(enclosing['started_utc'])
    for target, step in zip(plan, ledger['commands']):
        directory = PurePosixPath('.local-runs/verify-ledger/commands') / target
        require(type(step) is dict and step.get('target') == target and step.get('state') == 'COMPLETED'
            and step.get('status') == 'PASS' and type(step.get('exit_code')) is int and step['exit_code'] == 0
            and step.get('receipt') == directory.as_posix()
            and hashlib.sha256(metadata.raw(clone / directory / 'receipt.json')).hexdigest() == step.get('receipt_sha256'),
            'original ledger step/hash/order differs')
        proof = receipt(metadata, clone / directory, source=source, commit=commit,
            command=['make', target], cwd=native_clone)
        require(previous_end <= instant(proof['started_utc']) <= instant(proof['finished_utc'])
            <= instant(enclosing['finished_utc']), 'original gate interval is outside canonical verify or reordered')
        previous_end = instant(proof['finished_utc'])
    metadata.unchanged()
    return {'status': 'CHECKED RECORDED FRESH', 'commit': commit, 'source_sha256': source['sha256'],
        'fresh_checkout': clone.as_posix(), 'fresh_result_sha256': hashlib.sha256(metadata.raw(result_name)).hexdigest(),
        'ledger_sha256': hashlib.sha256(metadata.raw(ledger_name)).hexdigest(), 'gates': 18,
        'command_receipts_checked': 22, 'reference_qualified': False,
        'scope': 'All original retained clone/bootstrap/verify/demo and eighteen gate receipts/streams replayed. Source inventories and native recorded runtime checked; allocator authority, binary objects and every benchmark record require separate validation.'}
