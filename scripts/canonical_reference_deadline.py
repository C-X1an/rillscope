"""One cancellable inspection budget for the new allocator, never a lease reset."""
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import time

import canonical_reference_allocation as protocol
from run import environment
from evidence import EXCLUDED

POLL_SECONDS = .05
MAX_REPLY = 1024**2
MAX_COMMAND_OUTPUT = 65536


class AllocationDeadline:
    def __init__(self, deadline_ns, cancelled):
        protocol.require(protocol.integer(deadline_ns) and callable(cancelled),
            'original absolute exchange deadline and cancellation check required')
        self.deadline_ns, self.cancelled = deadline_ns, cancelled
        self.check()

    def check(self):
        stopped = self.cancelled()
        protocol.require(type(stopped) is bool and not stopped,
            'original allocation exchange cancelled')
        remaining = self.deadline_ns - time.monotonic_ns()
        protocol.require(0 < remaining <= 30 * 10**9,
            'original allocation exchange deadline exhausted')
        return remaining / 10**9

    def read(self, path, limit):
        protocol.require(type(limit) is int and 0 < limit <= 256 * 1024**2,
            'bounded original inspection read required')
        self.check(); raw = bytearray()
        with Path(path).open('rb') as stream:
            while True:
                self.check(); block = stream.read(min(65536, limit + 1 - len(raw)))
                self.check()
                if not block: break
                raw.extend(block)
                protocol.require(len(raw) <= limit, 'original inspection read exceeds bound')
        self.check()
        return bytes(raw)

    def digest(self, path, limit, *, allow_empty=False):
        protocol.require(type(limit) is int and 0 < limit <= 256 * 1024**2,
            'bounded original executable hash required')
        self.check(); size = 0; value = hashlib.sha256()
        with Path(path).open('rb') as stream:
            while True:
                self.check(); block = stream.read(65536); self.check()
                if not block: break
                size += len(block)
                protocol.require(size <= limit, 'actual executable exceeds inspection bound')
                value.update(block)
        protocol.require(allow_empty or size > 0, 'actual executable is empty')
        self.check()
        return value.hexdigest()

    def source_identity(self, root):
        """Match evidence.py's unchanged source selection and digest format."""
        self.check(); files = []; pending = [root]; count = 0
        while pending:
            directory = pending.pop(); self.check()
            for path in sorted(directory.iterdir()):
                self.check(); count += 1
                protocol.require(count <= 4096, 'allocation source inspection entry count exceeded')
                rel = path.relative_to(root)
                protocol.require(not path.is_symlink()
                    and not (hasattr(path, 'is_junction') and path.is_junction()),
                    'source identity cannot follow a symbolic link or reparse point')
                if any(part in EXCLUDED - {'verification'} for part in rel.parts): continue
                if rel.parts[0] == 'verification' and rel.as_posix() not in ('verification', 'verification/spec-lock.json'): continue
                if path.is_dir(): pending.append(path)
                elif path.is_file():
                    files.append([rel.as_posix(), self.digest(path, 64 * 1024**2, allow_empty=True)])
                else: raise ValueError('source identity requires regular files/directories')
        files.sort(); self.check()
        return {'sha256': hashlib.sha256(json.dumps(files, separators=(',', ':')).encode()).hexdigest(), 'files': files}

    def command(self, command, cwd):
        """Poll the exact Git child so cancellation spends the same deadline."""
        self.check()
        process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            streams = [(process.stdout, bytearray()), (process.stderr, bytearray())]
            eof = set()
            for stream, _ in streams: os.set_blocking(stream.fileno(), False)
            while True:
                self.check()
                for stream, raw in streams:
                    if stream in eof: continue
                    for _ in range(16):
                        self.check()
                        try: block = os.read(stream.fileno(), min(65536, MAX_COMMAND_OUTPUT + 1 - len(raw)))
                        except BlockingIOError: break
                        except OSError as error:
                            if getattr(error, 'winerror', None) != 109: raise
                            block = b''
                        if not block: eof.add(stream); break
                        raw.extend(block)
                        protocol.require(len(raw) <= MAX_COMMAND_OUTPUT,
                            'original Git inspection output exceeds bound')
                if process.poll() is not None and len(eof) == 2: break
                time.sleep(min(POLL_SECONDS, self.check()))
            self.check()
            protocol.require(process.returncode == 0, 'original Git source inspection failed')
            return bytes(streams[0][1])
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=1)
            process.stdout.close(); process.stderr.close()

    def _ready(self, connection, *, writing=False):
        while True:
            wait = min(POLL_SECONDS, self.check())
            readable, writable, exceptional = select.select(
                [] if writing else [connection], [connection] if writing else [], [connection], wait)
            self.check()
            protocol.require(not exceptional, 'original QMP connection failed')
            if (writable if writing else readable): return

    def qmp(self, port, command):
        protocol.require(type(port) is int and 0 < port < 65536
            and command in {'query-cpus-fast', 'query-kvm', 'query-status',
                'query-memory-size-summary', 'query-memory-devices'},
            'closed read-only allocation QMP request required')
        self.check()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.setblocking(False)
            code = connection.connect_ex(('127.0.0.1', port))
            protocol.require(code in {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
                getattr(errno, 'WSAEWOULDBLOCK', errno.EWOULDBLOCK)}, 'original QMP connect failed')
            if code:
                self._ready(connection, writing=True)
                protocol.require(connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0,
                    'original QMP connect failed')
            pending = bytearray()
            def reply():
                for _ in range(50):
                    while b'\n' not in pending:
                        self._ready(connection)
                        try: block = connection.recv(min(65536, MAX_REPLY + 1 - len(pending)))
                        except BlockingIOError: continue
                        protocol.require(block, 'original QMP closed before reply')
                        pending.extend(block)
                        protocol.require(len(pending) <= MAX_REPLY, 'original QMP reply exceeds bound')
                    raw, _, rest = pending.partition(b'\n'); pending[:] = rest
                    self.check(); value = json.loads(raw)
                    protocol.require(type(value) is dict, 'original QMP object required')
                    if 'event' not in value: return value
                raise ValueError('original QMP event count exceeds bound')
            def send(row):
                data = memoryview(json.dumps(row, separators=(',', ':')).encode('ascii') + b'\n')
                while data:
                    self._ready(connection, writing=True)
                    try: count = connection.send(data)
                    except BlockingIOError: continue
                    protocol.require(count > 0, 'original QMP closed during send')
                    data = data[count:]
            protocol.require('QMP' in reply(), 'original QMP greeting missing')
            send({'execute': 'qmp_capabilities'})
            protocol.require('return' in reply(), 'original QMP capabilities failed')
            send({'execute': command}); result = reply(); self.check()
            return result

    def snapshot(self, pid, port):
        """Same observed fields as the original sampler, under this one budget."""
        protocol.require(protocol.integer(pid), 'actual original QEMU PID required')
        fields = {}
        for line in self.read(Path('/proc', str(pid), 'status'), 65536).decode().splitlines():
            key, _, value = line.partition(':'); fields[key] = value.strip()
        cpus = self.qmp(port, 'query-cpus-fast').get('return', [])
        protocol.require(type(cpus) is list and len(cpus) == 4
            and all(type(row) is dict and protocol.integer(row.get('thread-id')) for row in cpus),
            'exact four original QMP vCPU tasks required')
        actual = environment(); self.check()
        result = {'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(), 'environment': actual,
            'qemu_pid': pid, 'process_status': fields, 'qemu_affinity': sorted(os.sched_getaffinity(pid)),
            'vcpu_threads': [{'thread_id': row['thread-id'],
                'affinity': sorted(os.sched_getaffinity(row['thread-id']))} for row in cpus],
            'kvm': self.qmp(port, 'query-kvm'), 'run_status': self.qmp(port, 'query-status'),
            'memory': self.qmp(port, 'query-memory-size-summary'),
            'hotplug_memory': self.qmp(port, 'query-memory-devices'),
            'smaps_rollup': self.read(Path('/proc', str(pid), 'smaps_rollup'), 65536).decode(),
            'vmstat': {line.split()[0]: int(line.split()[1])
                for line in self.read('/proc/vmstat', 65536).decode().splitlines()
                if line.split()[0] in ('pswpin', 'pswpout', 'pgmajfault')},
            'pressure': {name: self.read(Path('/proc/pressure', name), 65536).decode()
                for name in ('cpu', 'memory', 'io')},
            'clock_properties': str(time.get_clock_info('monotonic')),
            'clock_source': self.read('/sys/devices/system/clocksource/clocksource0/current_clocksource', 1024).decode().strip()}
        self.check()
        return result
