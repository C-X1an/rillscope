"""Guest-owner coordination controls; no host, signal, VM or real allocation."""
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
import reference_guest_owner as owner
import reference_guest_observer as observer_module
import reference_measurement_barrier as barrier
import test_reference_measurement_barrier as barrier_tests
BOOT = barrier_tests.BOOT


class GuestOwner(unittest.TestCase):
    def setUp(self):
        self.fixture = barrier_tests.MeasurementBarrier('test_real_request_ack_and_boundaries_surround_one_original_operation')
        self.fixture.setUp(); (self.fixture.base / 'exports').mkdir()
        self.context = self.fixture.patches(); self.context.__enter__()
        self.network = self.fixture.network
        self.calls = []; self.failures = []; self.failed = threading.Event()
        def snapshot(phase):
            return {'phase': phase, 'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(), 'boot_id': BOOT,
                'clock_source': 'kvm-clock', 'clock_properties': {'monotonic': True, 'adjustable': False},
                'vmstat': {'status': 'MEASURED', 'values': {'pswpin': 0, 'pswpout': 0}},
                'environment': {'synthetic_resource_fixture': True, 'system': 'Linux', 'machine': 'x86_64',
                    'resource_inspection_status': 'MEASURED', 'effective_cpu_capacity': 4,
                    'logical_processors': 4, 'process_affinity_cpu_count': 4, 'physical_memory_bytes': 8 * 1024**3,
                    'cgroup_memory_limit_bytes': None, 'cgroup_memory_high_bytes': None}}
        self.context.enter_context(patch.object(observer_module, 'snapshot', side_effect=snapshot))
        self.context.enter_context(patch.object(observer_module, 'interfaces', return_value=self.network))
        self.context.enter_context(patch.object(owner, 'interfaces', return_value=self.network))
        self.coordinator = None

    def tearDown(self):
        if self.coordinator is not None and self.coordinator.thread.is_alive(): self.coordinator.close()
        self.context.__exit__(None, None, None); self.fixture.tearDown()

    def failed_callback(self, record):
        self.failures.append(record); self.failed.set()

    def ready_callback(self, stage, request):
        self.calls.append((stage, request['source_sha256']))
        self.network['interfaces'][1].update(carrier='0', operstate='down')

    def test_three_original_operations_arm_once_after_first_actual_sample(self):
        self.network['interfaces'][1].update(carrier='1', operstate='up')
        self.coordinator = owner.Coordinator(self.ready_callback, self.failed_callback)
        self.coordinator.thread.start()
        for stage in ['grid', 'cancel', 'sort-null']:
            self.assertEqual(barrier.collect(stage, lambda: 0), 0)
        result = self.coordinator.close()
        self.assertEqual([stage for stage, _ in self.calls], ['grid'])
        self.assertEqual(result['armed_stages'], ['grid', 'cancel', 'sort-null'])
        self.assertEqual(result['sampler']['status'], 'OBSERVED')
        self.assertEqual(result['status'], 'OBSERVED'); self.assertEqual(self.failures, [])
        end = json.loads((self.fixture.control / 'sort-null-end.json').read_bytes())
        self.assertGreaterEqual(result['sampler']['last_monotonic_ns'], end['sample']['monotonic_ns'])
        self.assertFalse(result['reference_qualified'])

    def test_invalid_source_request_never_receives_owner_ack(self):
        request = {key: self.fixture.value[key] for key in ['schema_version', 'method', 'session', 'commit', 'source_sha256', 'boot_id', 'reference_qualified']}
        request.update(stage='grid', config_sha256=self.fixture.env[barrier.CONFIG_DIGEST], utc_ns=time.time_ns(),
            monotonic_ns=time.monotonic_ns(), source_sha256='e' * 64)
        barrier.exclusive_json(self.fixture.control / 'grid-request.json', request)
        self.coordinator = owner.Coordinator(self.ready_callback, self.failed_callback)
        self.coordinator.thread.start()
        self.assertTrue(self.failed.wait(2))
        result = self.coordinator.close()
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(len(self.failures), 1)
        self.assertEqual(self.calls, []); self.assertFalse((self.fixture.control / 'grid-armed.json').exists())

    def test_missing_host_cutover_fails_with_no_arm_or_sampler_success(self):
        self.network['interfaces'][1].update(carrier='1', operstate='up')
        self.coordinator = owner.Coordinator(lambda *_: None, self.failed_callback)
        self.coordinator.thread.start()
        with self.assertRaisesRegex(ValueError, 'deadline'): barrier.collect('grid', lambda: self.fail('no link-down'))
        self.assertTrue(self.failed.wait(2))
        result = self.coordinator.close()
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse((self.fixture.control / 'grid-armed.json').exists())


if __name__ == '__main__': unittest.main()
