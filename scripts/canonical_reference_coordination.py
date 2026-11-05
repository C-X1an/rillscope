"""New outer owner, unchanged closed inner measurement protocol and stage order."""
import hashlib
import time

import canonical_reference_allocation as allocation
import reference_measurement_barrier as barrier
from feasibility_profile import exact
from kvm_pilot_guest import interfaces, network_down
from kvm_reference_common import METHOD as INNER_METHOD, STAGES, strict_json
from reference_guest_owner import Coordinator
from reference_allocation import read_bounded, DOCUMENT_LIMIT


class CanonicalCoordinator(Coordinator):
    def __init__(self, observer, receipt_path, receipt_sha256, on_ready, on_failure):
        super().__init__(on_ready, on_failure)
        self.observer = observer
        self.receipt_path, self.receipt_sha256 = receipt_path, receipt_sha256
        self.check_allocation_input()

    def check_allocation_input(self):
        allocation.require(hashlib.sha256(read_bounded(self.receipt_path, DOCUMENT_LIMIT)).hexdigest()
            == self.receipt_sha256, 'original prior allocation receipt changed')

    def request(self, stage):
        self.check_allocation_input()
        config = barrier.configuration()
        allocation.require(config is not None and config['bytes'] == self.config['bytes'],
            'original inner measurement config changed')
        allocation.require(len(self.armed) < len(STAGES) and stage == STAGES[len(self.armed)],
            'canonical inner stages must follow the complete original order without replay')
        allocation.require(all((barrier.CONTROL_ROOT / (prior + '-end.json')).is_file() for prior in self.armed),
            'canonical measured stages cannot overlap')
        data = barrier.bounded(barrier.CONTROL_ROOT / (stage + '-request.json'))
        row = strict_json(data)
        expected = {key: config['value'][key] for key in ('schema_version', 'method', 'session',
            'commit', 'source_sha256', 'boot_id', 'reference_qualified')}
        expected.update(stage=stage, config_sha256=config['sha256'])
        allocation.require(type(row) is dict and set(row) == barrier.REQUEST_KEYS
            and all(exact(row.get(key), value) for key, value in expected.items())
            and all(allocation.integer(row.get(key)) for key in ('utc_ns', 'monotonic_ns'))
            and row['monotonic_ns'] <= time.monotonic_ns(), 'actual inner source/boot/request differs')
        deadline = min(row['monotonic_ns'] / 10**9 + config['value']['handshake_seconds'],
            config['value']['deadline_monotonic_ns'] / 10**9)
        self.live(deadline)
        if not self.armed:
            self.network_before = interfaces()
            self.on_ready(stage, row)
            while True:
                self.live(deadline); actual = interfaces()
                try: network_down(actual)
                except ValueError: self.stop.wait(.01); continue
                self.network_after = actual; break
            self.observer.arm_measurement()
            while not self.observer.measurement_ready.is_set():
                self.live(deadline)
                allocation.require(self.observer.error is None, 'actual pre-arm measurement sample failed')
                self.stop.wait(.01)
        allocation.require(self.observer.ready.is_set() and self.observer.error is None,
            'actual prior canonical guest sampling required')
        network_down(interfaces()); self.check_allocation_input(); self.live(deadline)
        ack = {**row, 'status': 'ARMED', 'request_sha256': hashlib.sha256(data).hexdigest(),
            'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()}
        barrier.exclusive_json(barrier.CONTROL_ROOT / (stage + '-armed.json'), ack)
        self.armed.append(stage)

    def summary(self):
        row = super().summary()
        row.update(method=allocation.METHOD, inner_measurement_method=INNER_METHOD,
            allocation_receipt_sha256=self.receipt_sha256)
        return row
