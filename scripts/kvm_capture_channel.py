"""Bounded guest-to-host CAS transfer over one owned virtio serial port.

The receiver acknowledges only fsynced, hash-checked and fully inspected CAS
bytes. This channel exposes no host paths, command execution or networking.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import time

import archive_capture
from kvm_pilot_common import STAGES, require, sha, write_json

PORT_NAME = 'org.rillscope.capture'
DEVICE = '/dev/virtio-ports/' + PORT_NAME
HEADER_LIMIT = 1024
CHUNK = 65536
DRAIN_LIMIT = 4 * 1024**2


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def header(value, expected):
    require(isinstance(value, dict) and set(value) == {'schema_version', 'stage', 'bytes', 'sha256',
            'reference_qualified'}, 'closed capture header required')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
            and value['stage'] == expected and value['reference_qualified'] is False
            and type(value['bytes']) is int and 0 < value['bytes'] <= archive_capture.MAX_ARCHIVE
            and isinstance(value['sha256'], str) and re.fullmatch('[0-9a-f]{64}', value['sha256']),
            'capture order, size, type or digest differs')
    return value


class Device:
    """Linux character device implementing the small nonblocking socket API."""
    def __init__(self):
        self.fd = os.open(DEVICE, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)

    def send(self, value): return os.write(self.fd, value)
    def recv(self, count): return os.read(self.fd, count)
    def fileno(self): return self.fd
    def close(self): os.close(self.fd)


def send_archive(archive, stage, deadline, *, connection=None):
    archive = Path(archive)
    require(archive.is_file() and not archive.is_symlink(), 'regular guest archive required')
    size = archive.stat().st_size
    value = header({'schema_version': 1, 'stage': stage, 'bytes': size,
        'sha256': sha(archive, archive_capture.MAX_ARCHIVE), 'reference_qualified': False}, stage)
    require(stage in [row[0] for row in STAGES], 'unknown capture stage')
    owned = connection is None
    connection = Device() if owned else connection
    if hasattr(connection, 'setblocking'): connection.setblocking(False)
    started = time.monotonic_ns()
    def remaining():
        seconds = deadline - time.monotonic()
        require(seconds > 0, 'guest capture transfer/ack deadline exceeded')
        return min(seconds, 1)
    def send(data):
        view = memoryview(data)
        while view:
            select.select([], [connection], [], remaining())
            try: count = connection.send(view)
            except BlockingIOError: continue
            require(count > 0, 'capture channel closed during guest send')
            view = view[count:]
    try:
        send(json.dumps(value, separators=(',', ':')).encode('ascii') + b'\n')
        digest = hashlib.sha256(); sent = 0
        with archive.open('rb') as stream:
            while block := stream.read(CHUNK):
                sent += len(block); require(sent <= size, 'archive grew during transfer')
                digest.update(block); send(block)
        require(sent == size and digest.hexdigest() == value['sha256'], 'archive changed during transfer')
        expected = ('OK ' + value['sha256'] + '\n').encode('ascii'); actual = bytearray()
        while len(actual) < len(expected):
            select.select([connection], [], [], remaining())
            try: block = connection.recv(len(expected) - len(actual))
            except BlockingIOError: continue
            require(block, 'host closed before verified capture acknowledgement')
            actual.extend(block)
        require(bytes(actual) == expected, 'host capture acknowledgement differs')
        return {'status': 'HOST ACKNOWLEDGED', **value, 'elapsed_ns': time.monotonic_ns() - started}
    finally:
        if owned: connection.close()


class Receiver:
    def __init__(self, connection, out):
        self.connection = connection; connection.setblocking(False)
        self.out = Path(out)
        require(self.out.parent.is_dir() and not self.out.parent.is_symlink(), 'existing output parent required')
        self.out.mkdir(exist_ok=True)
        fsync_directory(self.out.parent)
        self.head = bytearray(); self.current = None; self.stream = None
        self.digest = None; self.received = 0; self.pending_ack = b''
        self.records = []; self.eof = False; self.started = None

    def begin(self):
        require(len(self.records) < len(STAGES), 'extra or duplicate capture frame')
        row = header(json.loads(self.head), STAGES[len(self.records)][0])
        target = self.out / row['stage']; target.mkdir(exist_ok=False)
        fsync_directory(self.out)
        self.current = row; self.received = 0; self.digest = hashlib.sha256()
        self.started = {'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()}
        self.stream = (target / 'capture.zip.pending').open('xb'); self.head.clear()

    def complete(self):
        row = self.current; target = self.out / row['stage']
        self.stream.flush(); os.fsync(self.stream.fileno()); self.stream.close(); self.stream = None
        require(self.received == row['bytes'] and self.digest.hexdigest() == row['sha256'],
                'received capture byte count or digest differs')
        pending = target / 'capture.zip.pending'
        _, metadata = archive_capture.inspect(pending)
        os.replace(pending, target / 'capture.zip')
        record = {'status': 'VERIFIED HOST BYTES', **row, 'started': self.started,
            'finished': {'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()}, 'metadata': metadata}
        write_json(target / 'transfer.json', record)
        fsync_directory(target)
        fsync_directory(self.out)
        self.records.append(record); self.pending_ack = ('OK ' + row['sha256'] + '\n').encode('ascii')
        self.current = None

    def drain(self):
        if self.eof: return
        count = 0
        while count < DRAIN_LIMIT:
            if self.pending_ack:
                try: sent = self.connection.send(self.pending_ack)
                except BlockingIOError: return
                require(sent > 0, 'capture acknowledgement channel closed')
                self.pending_ack = self.pending_ack[sent:]
                if self.pending_ack: return
            limit = 1 if self.current is None else min(CHUNK, self.current['bytes'] - self.received)
            try: block = self.connection.recv(limit)
            except BlockingIOError: return
            if not block:
                self.eof = True
                require(self.current is None and not self.head, 'capture channel ended during a frame')
                return
            count += len(block)
            if self.current is None:
                if block == b'\n': self.begin()
                else:
                    self.head.extend(block)
                    require(len(self.head) <= HEADER_LIMIT, 'capture header exceeds bound')
            else:
                require(self.stream.write(block) == len(block), 'host capture write incomplete')
                self.digest.update(block); self.received += len(block)
                if self.received == self.current['bytes']: self.complete()

    def close(self):
        # Incomplete originals stay at .pending; they never receive an ACK.
        if self.stream is not None:
            self.stream.flush(); os.fsync(self.stream.fileno()); self.stream.close(); self.stream = None
        self.connection.close()
