"""Separate full-method byte channel; neither ACK nor scope declarations qualify results."""
import hashlib
import os
from pathlib import Path
import re
import time
import zipfile

import archive_capture
import kvm_capture_channel as transport
from kvm_pilot_common import require, sha
from kvm_reference_common import METHOD, STAGES, MANIFEST_LIMIT, identity, strict_json, validate_scope

PORT_NAME = 'org.rillscope.reference-capture'
DEVICE = '/dev/virtio-ports/' + PORT_NAME


def header(value, *, commit, source_sha256):
    identity(commit, source_sha256)
    require(type(value) is dict and set(value) == {'schema_version', 'method', 'stage', 'bytes',
        'sha256', 'commit', 'source_sha256', 'reference_qualified'}, 'closed full-method header required')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
            and value['method'] == METHOD and value['stage'] in STAGES
            and value['commit'] == commit and value['source_sha256'] == source_sha256
            and value['reference_qualified'] is False
            and type(value['bytes']) is int and 0 < value['bytes'] <= archive_capture.MAX_ARCHIVE
            and isinstance(value['sha256'], str) and re.fullmatch('[0-9a-f]{64}', value['sha256']),
            'full-method stage/source/length/digest differs')
    return value


class Device(transport.Device):
    def __init__(self): self.fd = os.open(DEVICE, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)


def send_archive(archive, stage, deadline, *, commit, source_sha256, connection=None):
    archive = Path(archive)
    require(archive.is_file() and not archive.is_symlink(), 'regular owned full-method archive required')
    value = header({'schema_version': 1, 'method': METHOD, 'stage': stage,
        'bytes': archive.stat().st_size, 'sha256': sha(archive, archive_capture.MAX_ARCHIVE),
        'commit': commit, 'source_sha256': source_sha256, 'reference_qualified': False},
        commit=commit, source_sha256=source_sha256)
    owned = connection is None
    connection = Device() if owned else connection
    try: return transport._send_frame(archive, value, deadline, connection=connection)
    finally:
        if owned: connection.close()


def inspected_manifest(archive, rows):
    # inspect() already checked every object. Read only this bounded metadata
    # object; a second expanded copy of the entire raw capture is unnecessary.
    matches = [row for row in rows if row['path'] == 'manifest.json']
    require(len(matches) == 1 and matches[0]['bytes'] <= MANIFEST_LIMIT,
            'one bounded original experiment manifest required')
    row = matches[0]
    with zipfile.ZipFile(archive) as bundle, bundle.open('objects/' + row['sha256']) as stream:
        data = stream.read(MANIFEST_LIMIT + 1)
    require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'],
            'inspected manifest bytes changed')
    return strict_json(data)


class Receiver(transport.Receiver):
    def __init__(self, connection, out, *, commit, source_sha256):
        identity(commit, source_sha256)
        self.expected_commit = commit; self.expected_source = source_sha256
        super().__init__(connection, out)

    def begin(self):
        require(len(self.records) < len(STAGES), 'extra full-method capture frame')
        row = header(strict_json(self.head), commit=self.expected_commit, source_sha256=self.expected_source)
        previous = STAGES.index(self.records[-1]['stage']) if self.records else -1
        require(STAGES.index(row['stage']) > previous, 'full-method stage repeats or reverses order')
        target = self.out / row['stage']; target.mkdir(exist_ok=False)
        transport.fsync_directory(self.out)
        self.current = row; self.received = 0; self.digest = hashlib.sha256()
        self.started = {'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()}
        self.stream = (target / 'capture.zip.pending').open('xb'); self.head.clear()

    def inspect_capture(self, archive):
        rows, metadata = archive_capture.inspect(archive)
        validate_scope(inspected_manifest(archive, rows), self.current['stage'],
            commit=self.expected_commit, source_sha256=self.expected_source)
        return metadata

    def completion(self):
        stages = [row['stage'] for row in self.records]
        return {'status': 'VERIFIED HOST BYTES' if stages == list(STAGES) else 'INCOMPLETE',
            'method': METHOD, 'missing_stages': [name for name in STAGES if name not in stages],
            'all_record_validation': 'NOT RUN', 'reference_qualified': False,
            'scope': 'Every acknowledged CAS object and declared method checked; missing/failed observations, '
                     'canonical command results, allocation and all-record qualification remain separate.'}
