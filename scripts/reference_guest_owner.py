"""Root guest owner coordinates fixed source-bound requests, never guest commands."""
import threading
import time

import reference_measurement_barrier as barrier
from feasibility_profile import exact
from kvm_pilot_common import require
from kvm_pilot_guest import interfaces, network_down
from kvm_reference_common import METHOD, STAGES, strict_json
from reference_guest_observer import GuestObserver


class Coordinator:
    def __init__(self, on_ready, on_failure):
        self.config = barrier.configuration()
        require(self.config is not None, 'actual source-bound guest measurement config required')
        self.on_ready = on_ready; self.on_failure = on_failure
        self.stop = threading.Event(); self.error = None; self.armed = []; self.observer = None
        self.network_before = None; self.network_after = None; self.worker_cpu_ns = None
        self.thread = threading.Thread(target=self.run, name='owned-reference-coordinator', daemon=True)

    def live(self, deadline):
        require(not self.stop.is_set() and time.monotonic() < deadline,
                'guest measurement owner stopped or handshake deadline exhausted')

    def request(self, stage):
        config = barrier.configuration()
        require(config is not None and config['bytes'] == self.config['bytes'], 'original guest owner config changed')
        path = barrier.CONTROL_ROOT / (stage + '-request.json')
        data = barrier.bounded(path); row = strict_json(data)
        expected = {key: config['value'][key] for key in ['schema_version', 'method', 'session', 'commit', 'source_sha256', 'boot_id', 'reference_qualified']}
        expected.update(stage=stage, config_sha256=config['sha256'])
        require(type(row) is dict and set(row) == barrier.REQUEST_KEYS
            and all(exact(row.get(key), value) for key, value in expected.items())
            and all(type(row.get(key)) is int and row[key] > 0 for key in ['utc_ns', 'monotonic_ns'])
            and row['monotonic_ns'] <= time.monotonic_ns(), 'guest measurement request source/boot/types differ')
        require(not self.armed or STAGES.index(stage) > STAGES.index(self.armed[-1]), 'guest measurement order reversed or replayed')
        require(all((barrier.CONTROL_ROOT / (other + '-end.json')).is_file() for other in self.armed),
                'guest measurement requests overlap an unfinished operation')
        deadline = min((row['monotonic_ns'] / 10**9) + config['value']['handshake_seconds'],
                       config['value']['deadline_monotonic_ns'] / 10**9)
        self.live(deadline)
        if self.observer is None:
            self.network_before = interfaces()
            # This callback emits a fixed protocol phase to the owned host.
            # Only that host may perform its own QMP link-down operation.
            self.on_ready(stage, row)
            while True:
                self.live(deadline); actual = interfaces()
                try: network_down(actual)
                except ValueError: self.stop.wait(.01); continue
                self.network_after = actual; break
            path = barrier.CONTROL_ROOT.parent / 'exports/guest-samples.jsonl'
            self.observer = GuestObserver(path, config['value']['deadline_monotonic_ns'])
            self.observer.thread.start()
            while not self.observer.ready.is_set():
                self.live(deadline)
                require(self.observer.error is None, 'initial actual guest sample failed: ' + str(self.observer.error))
                self.stop.wait(.01)
        require(self.observer.error is None and self.observer.count > 0, 'actual guest observer failed before arm')
        network_down(interfaces()); self.live(deadline)
        import hashlib
        ack = {**row, 'status': 'ARMED', 'request_sha256': hashlib.sha256(data).hexdigest(),
            'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()}
        barrier.exclusive_json(barrier.CONTROL_ROOT / (stage + '-armed.json'), ack)
        self.armed.append(stage)

    def run(self):
        cpu = time.thread_time_ns()
        try:
            while not self.stop.is_set():
                require(time.monotonic_ns() < self.config['value']['deadline_monotonic_ns'],
                        'whole guest coordinator deadline exhausted')
                if self.observer is not None:
                    require(self.observer.error is None, 'actual interval guest observation failed: ' + str(self.observer.error))
                pending = [stage for stage in STAGES if stage not in self.armed
                           and (barrier.CONTROL_ROOT / (stage + '-request.json')).exists()]
                require(len(pending) <= 1, 'concurrent guest measurement requests are forbidden')
                if pending: self.request(pending[0])
                self.stop.wait(.05)
        except (Exception, KeyboardInterrupt) as fault:
            self.error = {'error': type(fault).__name__, 'reason': str(fault)[:2048]}
            if not self.stop.is_set():
                try: self.on_failure(self.error)
                except Exception as callback_error: self.error['failure_callback_error'] = type(callback_error).__name__
        finally: self.worker_cpu_ns = time.thread_time_ns() - cpu

    def close(self):
        self.stop.set(); self.thread.join(timeout=5)
        if self.thread.is_alive(): self.error = self.error or {'error': 'TimeoutError', 'reason': 'guest coordinator did not stop within5seconds'}
        # Independently obtain the sampler endpoint even if coordination failed.
        if self.observer is not None:
            try: self.observer.close()
            except Exception as fault:
                self.error = self.error or {'error': type(fault).__name__, 'reason': str(fault)[:2048]}
        return self.summary()

    def summary(self):
        sample = self.observer.summary() if self.observer is not None else None
        passed = self.error is None and not self.thread.is_alive() and sample is not None and sample['status'] == 'OBSERVED'
        status = 'OBSERVED' if passed else ('NOT STARTED' if self.error is None and self.observer is None else 'FAIL')
        return {'status': status, 'method': METHOD, 'armed_stages': self.armed.copy(),
            'missing_stages': [stage for stage in STAGES if stage not in self.armed], 'error': self.error,
            'network_before': self.network_before, 'network_after': self.network_after,
            'sampler': sample, 'coordinator_cpu_ns': self.worker_cpu_ns, 'reference_qualified': False,
            'scope': 'Guest-local sampled coordination only; actual host launch/link ACK and canonical '
                     'command results, captures, full-method validation and reference qualification remain separate.'}
