"""Finite full-attempt guest observations with an actual post-stop endpoint."""
import json
import os
import platform
import re
import threading
import time

from archive_capture import owned
from guest_resource_probe import snapshot
from kvm_pilot_common import require, append_json
from kvm_pilot_guest import interfaces, network_down
from kvm_reference_common import METHOD
from kvm_reference_budget import (VM_SECONDS, GUEST_PERIOD_SECONDS, MAX_GUEST_SAMPLES,
    MAX_SAMPLE_BYTES, MAX_GUEST_LOG_BYTES, MAX_GAP_NS)


class GuestObserver:
    def __init__(self, path, deadline_ns):
        require(platform.system() == 'Linux', 'full sampler requires actual Linux guest')
        self.path = owned(path)
        require(self.path.parent.is_dir() and not self.path.exists(), 'new owned guest observation log required')
        require(type(deadline_ns) is int and 0 < deadline_ns - time.monotonic_ns() <= VM_SECONDS * 10**9,
                'finite live full guest deadline required')
        self.deadline_ns = deadline_ns; self.stop = threading.Event(); self.ready = threading.Event()
        self.error = None; self.count = 0; self.final_sampled = False; self.first = None; self.last = None
        self.maximum_gap_ns = 0; self.append_calls = 0; self.append_wall_ns = 0; self.append_cpu_ns = 0
        self.append_wall_max_ns = 0; self.final_fsync_ns = None
        self.thread = threading.Thread(target=self.run, name='owned-full-guest-observer', daemon=True)

    def check(self, row):
        require(all(type(row.get(key)) is int and row[key] > 0 for key in ['utc_ns', 'monotonic_ns']),
                'actual guest observation clocks missing')
        require(isinstance(row.get('boot_id'), str)
            and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', row['boot_id'])
            and row.get('clock_source') == 'kvm-clock' and row['clock_properties'].get('monotonic') is True
            and row['clock_properties'].get('adjustable') is False, 'actual KVM guest clock/boot differs')
        if self.first is not None:
            gap = row['monotonic_ns'] - self.last['monotonic_ns']
            self.maximum_gap_ns = max(gap, self.maximum_gap_ns)
            require(0 < gap <= MAX_GAP_NS and row['boot_id'] == self.first['boot_id'],
                    'guest clock reversed, gap exceeded or boot changed')
            require(row['vmstat']['values']['pswpin'] == self.first['vmstat']['values']['pswpin']
                and row['vmstat']['values']['pswpout'] == self.first['vmstat']['values']['pswpout'],
                'guest swap changed during observed interval')
        env = row['environment']
        require(env.get('system') == 'Linux' and env.get('machine') == 'x86_64'
            and env.get('resource_inspection_status') == 'MEASURED'
            and env.get('effective_cpu_capacity') == 4 and env.get('logical_processors') == 4
            and env.get('process_affinity_cpu_count') == 4
            and 7.5 * 1024**3 <= env.get('physical_memory_bytes', 0) <= 8.5 * 1024**3
            and all(env.get(key) is None or type(env[key]) is int and env[key] >= 7.5 * 1024**3
                    for key in ['cgroup_memory_limit_bytes', 'cgroup_memory_high_bytes'])
            and row['vmstat']['status'] == 'MEASURED', 'actual guest resources/swap inspection differs')
        network_down(row['network'])

    def observe(self, kind):
        require(self.count < MAX_GUEST_SAMPLES, 'full guest observation count exceeds bound before write')
        require(time.monotonic_ns() < self.deadline_ns, 'full guest observation deadline exhausted')
        started = time.monotonic_ns(); cpu = time.thread_time_ns()
        row = snapshot('interval'); row.update(method=METHOD, sample_kind=kind, network=interfaces(), observation_status='OBSERVED')
        try: self.check(row)
        except Exception as fault:
            row.update(observation_status='FAIL', observation_error=type(fault).__name__, observation_reason=str(fault)[:2048])
        row.update(observer_wall_ns=time.monotonic_ns() - started, observer_cpu_ns=time.thread_time_ns() - cpu)
        encoded = json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        require(len(encoded) <= MAX_SAMPLE_BYTES, 'full guest observation record exceeds byte bound')
        before = time.monotonic_ns(); cpu = time.thread_time_ns()
        append_json(self.path, row, limit=MAX_GUEST_LOG_BYTES)
        elapsed = time.monotonic_ns() - before
        self.append_wall_ns += elapsed; self.append_cpu_ns += time.thread_time_ns() - cpu
        self.append_wall_max_ns = max(self.append_wall_max_ns, elapsed); self.append_calls += 1
        self.count += 1; self.last = row
        if self.first is None: self.first = row
        require(row['observation_status'] == 'OBSERVED', 'full guest observation failed: ' + row.get('observation_reason', 'unknown'))
        self.ready.set()

    def run(self):
        try:
            while not self.stop.is_set():
                self.observe('interval'); self.stop.wait(GUEST_PERIOD_SECONDS)
            self.observe('final')
            self.final_sampled = True
        except Exception as fault:
            self.error = type(fault).__name__ + ': ' + str(fault)[:2048]

    def close(self):
        self.stop.set(); self.thread.join(timeout=5)
        if self.thread.is_alive(): self.error = self.error or 'TimeoutError: full guest observer did not stop within5seconds'
        require(not self.thread.is_alive() and self.error is None and self.final_sampled and self.count > 0,
                'full guest observer failed: ' + str(self.error))
        started = time.monotonic_ns()
        try:
            with self.path.open('ab') as stream: stream.flush(); os.fsync(stream.fileno())
            self.final_fsync_ns = time.monotonic_ns() - started
        except OSError as fault:
            self.error = type(fault).__name__ + ': ' + str(fault)[:2048]; raise

    def summary(self):
        passed = self.error is None and self.count > 0 and self.final_sampled and not self.thread.is_alive() and self.final_fsync_ns is not None
        return {'status': 'OBSERVED' if passed else 'FAIL', 'observations': self.count, 'final_sampled': self.final_sampled,
            'error': self.error, 'maximum_gap_ns': self.maximum_gap_ns, 'gap_bound_ns': MAX_GAP_NS,
            'first_monotonic_ns': self.first['monotonic_ns'] if self.first else None,
            'last_monotonic_ns': self.last['monotonic_ns'] if self.last else None,
            'append_calls_completed': self.append_calls, 'append_wall_total_ns': self.append_wall_ns,
            'append_wall_max_ns': self.append_wall_max_ns, 'append_cpu_total_ns': self.append_cpu_ns,
            'final_fsync_ns': self.final_fsync_ns, 'sample_cap': MAX_GUEST_SAMPLES,
            'record_byte_cap': MAX_SAMPLE_BYTES, 'log_byte_cap': MAX_GUEST_LOG_BYTES,
            'method': METHOD, 'reference_qualified': False,
            'scope': 'Bounded sampled records and actual append/flush costs, with final file fsync; '
                     'no uninterrupted residency, physical exclusivity, full-method or reference qualification.'}
