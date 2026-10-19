"""Full-lifetime sampler controls with real clocks/threads and synthetic resources."""
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_guest_observer as module


class FullGuestObserver(unittest.TestCase):
    def exercise(self, fault=None):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='go-', dir=ROOT / '.local-runs') as temporary:
            path = Path(temporary) / 'samples.jsonl'; entered = threading.Event(); release = threading.Event()
            calls = 0; original_append = module.append_json; appends = 0
            def snapshot(phase):
                nonlocal calls
                calls += 1
                row = {'phase': phase, 'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(),
                    'boot_id': '11111111-2222-3333-4444-555555555555',
                    'clock_source': 'kvm-clock', 'clock_properties': {'monotonic': True, 'adjustable': False},
                    'vmstat': {'status': 'MEASURED', 'values': {'pswpin': 0, 'pswpout': 0}},
                    'environment': {'synthetic_resource_fixture': True, 'system': 'Linux', 'machine': 'x86_64',
                        'resource_inspection_status': 'MEASURED', 'effective_cpu_capacity': 4,
                        'logical_processors': 4, 'process_affinity_cpu_count': 4, 'physical_memory_bytes': 8 * 1024**3,
                        'cgroup_memory_limit_bytes': None, 'cgroup_memory_high_bytes': None}}
                if calls == 1 and fault == 'in-flight':
                    entered.set()
                    if not release.wait(2): raise RuntimeError('test release missing')
                if fault == 'oversize': row['oversize_unit_record'] = 'x' * 20000
                return row
            network = {'interfaces': [{'name': 'unit0', 'carrier': '0', 'operstate': 'down'}]}
            def append(*args, **kwargs):
                nonlocal appends
                appends += 1
                if fault == 'write' and appends == 2: raise OSError('deliberate final write fault')
                return original_append(*args, **kwargs)
            with patch.object(module.platform, 'system', return_value='Linux'), \
                    patch.object(module, 'snapshot', side_effect=snapshot), \
                    patch.object(module, 'interfaces', return_value=network), \
                    patch.object(module, 'append_json', side_effect=append), \
                    patch.object(module, 'MAX_GUEST_SAMPLES', 1 if fault == 'count' else 9004):
                observer = module.GuestObserver(path, time.monotonic_ns() + 10_000_000_000)
                observer.thread.start()
                try:
                    if fault == 'in-flight':
                        self.assertTrue(entered.wait(2)); boundary = time.monotonic_ns()
                        observer.stop.set(); release.set()
                    elif fault != 'oversize':
                        self.assertTrue(observer.ready.wait(2)); boundary = time.monotonic_ns()
                    else:
                        boundary = time.monotonic_ns()
                    if fault == 'network': network['interfaces'][0].update(carrier='1', operstate='up')
                    if fault == 'deadline': observer.deadline_ns = time.monotonic_ns() - 1
                    if fault in {'network', 'write', 'count', 'oversize', 'deadline'}:
                        with self.assertRaises(ValueError): observer.close()
                    else: observer.close()
                finally:
                    observer.stop.set(); release.set(); observer.thread.join(timeout=3)
                self.assertFalse(observer.thread.is_alive())
                rows = [json.loads(line) for line in path.read_bytes().splitlines()] if path.exists() else []
                summary = observer.summary()
                self.assertFalse(summary['reference_qualified'])
                if fault is None or fault == 'in-flight':
                    self.assertTrue(summary['final_sampled']); self.assertEqual(summary['status'], 'OBSERVED')
                    self.assertGreaterEqual(rows[-1]['monotonic_ns'], boundary)
                    self.assertEqual(rows[-1]['sample_kind'], 'final')
                    self.assertEqual(summary['observations'], len(rows))
                    self.assertEqual(summary['append_calls_completed'], len(rows))
                elif fault == 'network':
                    self.assertEqual(rows[-1]['observation_status'], 'FAIL')
                    self.assertEqual(rows[-1]['network']['interfaces'][0]['carrier'], '1')
                    self.assertFalse(summary['final_sampled'])
                else:
                    self.assertEqual(len(rows), 0 if fault == 'oversize' else 1)
                    self.assertEqual(summary['status'], 'FAIL')

    def test_actual_final_sample_follows_stop_and_records_append_overhead(self): self.exercise()
    def test_old_in_flight_sample_needs_a_distinct_later_record(self): self.exercise('in-flight')
    def test_network_failure_is_retained_in_the_failed_original_record(self): self.exercise('network')
    def test_final_write_failure_never_acknowledges_completion(self): self.exercise('write')
    def test_count_cap_is_enforced_before_an_additional_write(self): self.exercise('count')
    def test_record_byte_cap_fails_without_inventing_a_truncated_sample(self): self.exercise('oversize')
    def test_whole_deadline_prevents_a_late_final_success(self): self.exercise('deadline')


if __name__ == '__main__': unittest.main()
