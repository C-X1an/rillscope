"""Owned file-handshake unit controls; synthetic allocation is never VM proof."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import reference_measurement_barrier as barrier

COMMIT = 'b' * 40
SOURCE = 'a' * 64
BOOT = '11111111-2222-3333-4444-555555555555'


class MeasurementBarrier(unittest.TestCase):
    def setUp(self):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='kb-', dir=ROOT / '.local-runs')
        self.base = Path(self.temporary.name); self.control = self.base / 'control'; self.control.mkdir()
        self.config = self.base / 'measurement.json'
        self.value = {'schema_version': 1, 'method': 'rillscope-full-capture-v1',
            'commit': COMMIT, 'source_sha256': SOURCE, 'boot_id': BOOT, 'session': 'c' * 32,
            'control_root': str(self.control), 'deadline_monotonic_ns': time.monotonic_ns() + 10_000_000_000,
            'handshake_seconds': 1, 'reference_qualified': False}
        self.config.write_text(json.dumps(self.value), encoding='utf-8')
        self.env = {'RILLSCOPE_REFERENCE_MEASUREMENT_CONFIG': str(self.config),
            'RILLSCOPE_REFERENCE_MEASUREMENT_CONFIG_SHA256': hashlib.sha256(self.config.read_bytes()).hexdigest()}
        self.network = {'interfaces': [{'name': 'lo', 'carrier': '1', 'operstate': 'unknown'},
            {'name': 'unit0', 'carrier': '0', 'operstate': 'down'}], 'ipv4_routes': '', 'ipv6_routes': ''}
        self.snapshots = []

    def tearDown(self): self.temporary.cleanup()

    def snapshot(self, phase):
        row = {'phase': phase, 'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(),
            'boot_id': BOOT, 'environment': {'explicit_unit_fixture': True}}
        self.snapshots.append(row); return row

    def patches(self):
        from contextlib import ExitStack
        stack = ExitStack()
        for context in [patch.dict(os.environ, self.env, clear=True), patch.object(barrier, 'CONTROL_ROOT', self.control),
            patch.object(barrier.platform, 'system', return_value='Linux'), patch.object(barrier, 'boot_id', return_value=BOOT),
            patch.object(barrier, 'source_identity', return_value={'sha256': SOURCE}), patch.object(barrier, 'git_identity'),
            patch.object(barrier, 'snapshot', side_effect=self.snapshot), patch.object(barrier, 'interfaces', side_effect=lambda: self.network),
            patch.object(barrier, 'fsync_directory')]: stack.enter_context(context)
        return stack

    def acknowledge(self, stage, changed=None):
        errors = []
        def work():
            try:
                path = self.control / (stage + '-request.json'); deadline = time.monotonic() + 2
                while not path.exists():
                    if time.monotonic() >= deadline: raise RuntimeError('unit request not obtained')
                    time.sleep(.001)
                data = path.read_bytes(); request = json.loads(data)
                row = {**request, 'status': 'ARMED', 'request_sha256': hashlib.sha256(data).hexdigest(),
                    'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(), **(changed or {})}
                barrier.exclusive_json(self.control / (stage + '-armed.json'), row)
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=work); thread.start()
        return thread, errors

    def test_unconfigured_ordinary_collection_preserves_its_actual_exit(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(barrier.collect('grid', lambda: 19), 19)
        self.assertEqual(list(self.control.iterdir()), [])

    def test_real_request_ack_and_boundaries_surround_one_original_operation(self):
        with self.patches():
            thread, errors = self.acknowledge('grid'); calls = []
            def operation():
                self.assertTrue((self.control / 'grid-start.json').is_file())
                self.assertFalse((self.control / 'grid-end.json').exists())
                calls.append(time.monotonic_ns()); return 0
            try: self.assertEqual(barrier.collect('grid', operation), 0)
            finally: thread.join(timeout=3)
            self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
        start = json.loads((self.control / 'grid-start.json').read_bytes())
        end = json.loads((self.control / 'grid-end.json').read_bytes())
        self.assertLessEqual(start['sample']['monotonic_ns'], calls[0])
        self.assertGreaterEqual(end['sample']['monotonic_ns'], calls[0])
        self.assertEqual(end['collection_exit_code'], 0); self.assertFalse(end['reference_qualified'])

    def test_no_parent_ack_fails_closed_and_retains_exact_original_request(self):
        with self.patches(), self.assertRaisesRegex(ValueError, 'deadline'):
            barrier.collect('grid', lambda: self.fail('collection cannot precede ACK'))
        self.assertTrue((self.control / 'grid-request.json').is_file())
        self.assertFalse((self.control / 'grid-start.json').exists())

    def test_ack_for_other_source_cannot_start_collection(self):
        with self.patches():
            thread, errors = self.acknowledge('grid', {'source_sha256': 'd' * 64})
            try:
                with self.assertRaisesRegex(ValueError, 'acknowledgement'):
                    barrier.collect('grid', lambda: self.fail('wrong source cannot start'))
            finally: thread.join(timeout=3)
            self.assertEqual(errors, [])
        self.assertFalse((self.control / 'grid-start.json').exists())

    def test_failed_collection_keeps_original_exit_and_observed_end(self):
        with self.patches():
            thread, errors = self.acknowledge('grid')
            try: self.assertEqual(barrier.collect('grid', lambda: 23), 23)
            finally: thread.join(timeout=3)
            self.assertEqual(errors, [])
        self.assertEqual(json.loads((self.control / 'grid-end.json').read_bytes())['collection_exit_code'], 23)

    def test_link_returning_up_after_operation_is_retained_and_fails_gate(self):
        with self.patches():
            thread, errors = self.acknowledge('grid')
            def operation():
                self.network['interfaces'][1].update(carrier='1', operstate='up'); return 0
            try:
                with self.assertRaisesRegex(ValueError, 'network'):
                    barrier.collect('grid', operation)
            finally: thread.join(timeout=3)
            self.assertEqual(errors, [])
        end = json.loads((self.control / 'grid-end.json').read_bytes())
        self.assertEqual(end['status'], 'FAIL')
        self.assertEqual(end['network']['interfaces'][1]['carrier'], '1')

    def test_existing_request_is_never_overwritten_or_replayed(self):
        path = self.control / 'grid-request.json'; original = b'original failure bytes\n'; path.write_bytes(original)
        with self.patches(), self.assertRaisesRegex(ValueError, 'exists|original|replay'):
            barrier.collect('grid', lambda: self.fail('no replay'))
        self.assertEqual(path.read_bytes(), original)

    def test_ack_already_present_after_handshake_deadline_cannot_start(self):
        original = barrier.exclusive_json
        def publish(path, row):
            digest = original(path, row)
            if path.name.endswith('-request.json'):
                original(self.control / 'grid-armed.json', {**row, 'status': 'ARMED', 'request_sha256': digest,
                    'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()})
            return digest
        with self.patches(), patch.object(barrier, 'exclusive_json', side_effect=publish), \
                patch.object(barrier.time, 'monotonic', side_effect=[0, 2]), \
                self.assertRaisesRegex(ValueError, 'deadline'):
            barrier.collect('grid', lambda: self.fail('late ACK cannot start collection'))

    def test_boolean_schema_and_numeric_qualification_ack_are_not_typed_matches(self):
        with self.patches():
            thread, errors = self.acknowledge('grid', {'schema_version': True, 'reference_qualified': 0})
            try:
                with self.assertRaisesRegex(ValueError, 'acknowledgement'):
                    barrier.collect('grid', lambda: self.fail('incorrect ACK types cannot start'))
            finally: thread.join(timeout=3)
            self.assertEqual(errors, [])


if __name__ == '__main__': unittest.main()
