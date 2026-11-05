"""Bounded new-method guest sampling through prefix and measured commands.

This records sampled facts and observer cost. It cannot grant a guest, prove
uninterrupted residency or physical exclusivity, or certify a benchmark.
"""
import json
import os
from pathlib import Path
import platform
import stat
import threading
import time

import canonical_reference_allocation as allocation
from guest_resource_probe import snapshot
from kvm_pilot_common import append_json
from kvm_pilot_guest import interfaces, network_down

PERIOD_SECONDS = 2
MAX_GAP_NS = 15_000_000_000
MAX_RECORD_BYTES = 16 * 1024
MAX_SAMPLES = allocation.MAX_LEASE_NS // (PERIOD_SECONDS * 10**9) + 4
MAX_LOG_BYTES = MAX_SAMPLES * MAX_RECORD_BYTES


def check_sample(row, *, boot_id, previous=None, first=None, measured=False):
    allocation.require(type(row) is dict and allocation.boot(boot_id)
        and row.get('boot_id') == boot_id and row.get('clock_source') == 'kvm-clock'
        and type(row.get('clock_properties')) is dict
        and row['clock_properties'].get('monotonic') is True
        and row['clock_properties'].get('adjustable') is False
        and all(allocation.integer(row.get(key)) for key in ('utc_ns', 'monotonic_ns')),
        'actual stable KVM boot and clocks required')
    allocation.require(type(row.get('environment')) is dict
        and allocation.ENV_KEYS <= set(row['environment']), 'complete actual guest environment required')
    allocation.validate_environment({key: row['environment'][key] for key in allocation.ENV_KEYS})
    vmstat = row.get('vmstat')
    allocation.require(type(vmstat) is dict and vmstat.get('status') == 'MEASURED'
        and type(vmstat.get('values')) is dict
        and all(type(vmstat['values'].get(key)) is int and vmstat['values'][key] >= 0
            for key in ('pswpin', 'pswpout')), 'actual guest swap counters required')
    if previous is not None:
        gap = row['monotonic_ns'] - previous['monotonic_ns']
        allocation.require(0 < gap <= MAX_GAP_NS, 'guest sample clock reversed or gap exceeded')
    if first is not None:
        allocation.require(all(vmstat['values'][key] == first['vmstat']['values'][key]
            for key in ('pswpin', 'pswpout')), 'guest swap changed during observed attempt')
    allocation.require(type(measured) is bool and type(row.get('network')) is dict,
        'actual network observations and explicit measurement phase required')
    if measured: network_down(row['network'])


class CanonicalObserver:
    def __init__(self, path, deadline_ns, boot_id):
        allocation.require(platform.system() == 'Linux' and os.geteuid() == 0,
            'actual existing canonical Linux root owner required')
        path = Path(path)
        allocation.require(path.is_absolute() and path.parent.is_dir() and not path.exists(),
            'new absolute guest sample log in an existing parent required')
        for component in (path, *path.parents):
            allocation.require(not component.is_symlink(), 'link-free guest sample path required')
        allocation.require(type(deadline_ns) is int
            and 0 < deadline_ns - time.monotonic_ns() <= allocation.MAX_LEASE_NS
            and allocation.boot(boot_id), 'original finite guest deadline and boot required')
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        allocation.require(stat.S_ISREG(path.lstat().st_mode) and path.lstat().st_uid == 0,
            'root-owned regular guest sample log required')
        self.path, self.deadline_ns, self.boot_id = path, deadline_ns, boot_id
        self.stop, self.ready, self.measurement = threading.Event(), threading.Event(), threading.Event()
        self.measurement_ready = threading.Event()
        self.thread = threading.Thread(target=self.run, name='owned-canonical-guest-observer', daemon=True)
        self.error = None; self.count = 0; self.first = self.last = None
        self.maximum_gap_ns = 0; self.final_sampled = False; self.fsync_ns = None
        self.append_wall_ns = self.append_cpu_ns = self.append_calls = 0

    def arm_measurement(self):
        allocation.require(not self.measurement.is_set() and self.ready.is_set() and self.error is None,
            'one prior actual observer required before measurement')
        network_down(interfaces())
        self.measurement.set()

    def observe(self, kind):
        allocation.require(self.count < MAX_SAMPLES and time.monotonic_ns() < self.deadline_ns,
            'canonical guest sample count or original deadline exhausted')
        started, cpu = time.monotonic_ns(), time.thread_time_ns()
        measured = self.measurement.is_set()
        row = snapshot('interval')
        row.update(method=allocation.METHOD, sample_kind=kind, network=interfaces(),
            phase='measurement' if measured else 'prefix', observation_status='OBSERVED')
        try: check_sample(row, boot_id=self.boot_id, previous=self.last, first=self.first, measured=measured)
        except Exception as error:
            row.update(observation_status='FAIL', observation_error=type(error).__name__,
                observation_reason=str(error)[:2048])
        row.update(observer_wall_ns=time.monotonic_ns() - started, observer_cpu_ns=time.thread_time_ns() - cpu)
        raw = json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        allocation.require(len(raw) <= MAX_RECORD_BYTES, 'canonical guest sample exceeds record bound')
        started, cpu = time.monotonic_ns(), time.thread_time_ns()
        append_json(self.path, row, limit=MAX_LOG_BYTES)
        self.append_wall_ns += time.monotonic_ns() - started
        self.append_cpu_ns += time.thread_time_ns() - cpu; self.append_calls += 1
        if self.last: self.maximum_gap_ns = max(self.maximum_gap_ns, row['monotonic_ns'] - self.last['monotonic_ns'])
        self.last = row; self.count += 1
        if self.first is None: self.first = row
        allocation.require(row['observation_status'] == 'OBSERVED',
            'actual canonical guest sample failed: ' + row.get('observation_reason', 'unknown'))
        self.ready.set()
        if measured: self.measurement_ready.set()

    def run(self):
        try:
            while not self.stop.is_set():
                self.observe('interval'); self.stop.wait(PERIOD_SECONDS)
            self.observe('final'); self.final_sampled = True
        except Exception as error: self.error = type(error).__name__ + ': ' + str(error)[:2048]

    def close(self):
        self.stop.set(); self.thread.join(timeout=5)
        allocation.require(not self.thread.is_alive() and self.error is None and self.final_sampled,
            'canonical guest observer failed or did not stop: ' + str(self.error))
        started = time.monotonic_ns()
        with self.path.open('rb') as stream: os.fsync(stream.fileno())
        descriptor = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
        self.fsync_ns = time.monotonic_ns() - started

    def summary(self):
        passed = (self.error is None and not self.thread.is_alive() and self.final_sampled
            and self.fsync_ns is not None and self.count > 0)
        return {'status': 'OBSERVED' if passed else 'FAIL', 'method': allocation.METHOD,
            'boot_id': self.boot_id, 'observations': self.count, 'error': self.error,
            'final_sampled': self.final_sampled, 'measurement_armed': self.measurement.is_set(),
            'measurement_sample_observed': self.measurement_ready.is_set(),
            'first_monotonic_ns': self.first['monotonic_ns'] if self.first else None,
            'last_monotonic_ns': self.last['monotonic_ns'] if self.last else None,
            'maximum_gap_ns': self.maximum_gap_ns, 'gap_bound_ns': MAX_GAP_NS,
            'append_wall_total_ns': self.append_wall_ns, 'append_cpu_total_ns': self.append_cpu_ns,
            'append_calls_completed': self.append_calls, 'final_fsync_ns': self.fsync_ns,
            'sample_cap': MAX_SAMPLES, 'record_byte_cap': MAX_RECORD_BYTES, 'log_byte_cap': MAX_LOG_BYTES,
            'reference_qualified': False,
            'scope': 'Sampled prefix and network-down measurement observations and actual observer costs only; no uninterrupted residency or physical-exclusivity verdict.'}
