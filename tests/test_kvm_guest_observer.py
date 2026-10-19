"""Real thread/clock endpoint controls using explicit synthetic resource records."""
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
import kvm_pilot_guest as guest


class GuestObserverEndpoint(unittest.TestCase):
    def exercise(self, fault=None):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='ko-', dir=ROOT / '.local-runs') as temporary:
            base = Path(temporary); (base / 'exports').mkdir()
            ready = threading.Event(); release = threading.Event()
            original_append = guest.append_json; snapshots = 0; networks = 0
            def snapshot(phase):
                nonlocal snapshots
                snapshots += 1
                row = {'phase': phase, 'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(),
                    'boot_id': 'explicit-unit-boot', 'environment': {'unit_fixture': True}}
                if fault == 'in-flight' and snapshots == 1:
                    ready.set()
                    if not release.wait(2): raise RuntimeError('unit snapshot release missing')
                if fault == 'resource' and snapshots == 2: raise OSError('deliberate final resource fault')
                return row
            def interfaces():
                nonlocal networks
                networks += 1
                if fault == 'network' and networks == 2: raise OSError('deliberate final network fault')
                return {'interfaces': [{'name': 'unit0', 'carrier': '0', 'operstate': 'down'}]}
            def append(path, row):
                original_append(path, row)
                if fault != 'in-flight': ready.set()
            observer = guest.GuestObserver()
            if fault == 'bound': observer.count = 2999
            with patch.object(guest, 'BASE', base), patch.object(guest, 'snapshot', side_effect=snapshot), \
                    patch.object(guest, 'interfaces', side_effect=interfaces), patch.object(guest, 'append_json', side_effect=append):
                observer.thread.start()
                try:
                    self.assertTrue(ready.wait(2), 'first real thread record must be obtained')
                    boundary = time.monotonic_ns()
                    if fault == 'in-flight': observer.stop.set(); release.set()
                    if fault in {'resource', 'network', 'bound'}:
                        with self.assertRaisesRegex(ValueError, 'guest observer failed'):
                            observer.close()
                    else:
                        observer.close()
                finally:
                    observer.stop.set(); release.set(); observer.thread.join(timeout=3)
                self.assertFalse(observer.thread.is_alive())
                rows = [json.loads(line) for line in (base / 'exports/guest-samples.jsonl').read_bytes().splitlines()]
            if fault in {'resource', 'network', 'bound'}:
                self.assertEqual(len(rows), 1, 'a failed final sample cannot create successful evidence')
                self.assertIsNotNone(observer.error)
            else:
                self.assertGreaterEqual(len(rows), 2)
                self.assertLess(rows[0]['monotonic_ns'], boundary)
                self.assertGreaterEqual(rows[-1]['monotonic_ns'], boundary,
                    'the actual final sample must follow the stop request, including an in-flight old snapshot')
                self.assertEqual(rows[-1]['network']['interfaces'][0]['carrier'], '0')
                self.assertEqual(rows[-1]['boot_id'], 'explicit-unit-boot')
                for key in ('observer_wall_ns', 'observer_cpu_ns'):
                    self.assertIs(type(rows[-1][key]), int); self.assertGreaterEqual(rows[-1][key], 0)
                self.assertEqual(observer.count, len(rows))

    def test_final_sample_brackets_actual_stop_request(self): self.exercise()
    def test_in_flight_old_sample_cannot_replace_post_request_sample(self): self.exercise('in-flight')
    def test_final_resource_failure_cannot_be_reported_as_collected(self): self.exercise('resource')
    def test_final_network_failure_cannot_be_reported_as_collected(self): self.exercise('network')
    def test_final_sample_cannot_exceed_existing_pilot_observation_bound(self): self.exercise('bound')


if __name__ == '__main__': unittest.main()
