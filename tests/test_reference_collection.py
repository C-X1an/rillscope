"""Original full collection orchestration, with failed raw retention and no reruns."""
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_collection as collection


class FullCollection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.local-runs')
        self.base = Path(self.temp.name)
        self.payload = {'bins': {'rillscope': {'path': '.local-runs/bin/rillscope'},
            'rillscope-measure': {'path': '.local-runs/bin/rillscope-measure'}},
            'build_receipt': {'path': '.local-runs/build/build.json'}, 'source': {'sha256': 'a' * 64}}
        self.deadline = time.monotonic_ns() + 60_000_000_000

    def tearDown(self): self.temp.cleanup()

    def stage(self, code=0, ack='HOST ACKNOWLEDGED'):
        events = []
        def run(name, command, timeout, inputs=()):
            events.append(('command', name, command))
            raw = self.base / 'raw/grid'; raw.mkdir(parents=True)
            (raw / 'original-error.txt').write_bytes(b'original bytes including failures')
            if code: raise RuntimeError('original command failure')
            return b''
        def measured(stage, operation):
            events.append(('measurement', stage))
            return operation()
        def pack(name, command, timeout, inputs=()):
            events.append(('pack', name, command))
            target = self.base / 'exports/packages/grid'; target.mkdir(parents=True)
            (target / 'capture.zip').write_bytes(b'original CAS bytes')
            return b''
        def checked(name, command, timeout, inputs=()):
            return (pack if name.startswith('pack-') else run)(name, command, timeout, inputs)
        with patch.object(collection.measurement, 'collect', side_effect=measured), \
             patch.object(collection, 'export_capture', side_effect=lambda path, stage:
                 events.append(('export', stage, path.read_bytes())) or {'status': ack}), \
             patch.object(collection, 'read_json', return_value={'verification_status': 'PASS', 'exit_code': 0,
                 'source_before': {'sha256': 'a' * 64}, 'source_after_sha256': 'a' * 64,
                 'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0}}):
            result = collection.collect_stage('grid', self.payload, self.base, checked, self.deadline)
        return result, events

    def test_locked_full_and_null_commands_never_select_pilot_or_change_repetitions(self):
        grid = collection.command_for('grid', self.payload, self.base / 'grid')
        null = collection.command_for('sort-null', self.payload, self.base / 'null')
        cancel = collection.command_for('cancel', self.payload, self.base / 'cancel')
        self.assertEqual(grid[grid.index('--profile') + 1], 'full')
        self.assertEqual(null[null.index('--profile') + 1], 'sort-null-supplement')
        self.assertEqual(Path(cancel[1]).name, 'cancellation.py')
        self.assertNotIn('--repetitions', grid + null + cancel)
        self.assertNotIn('--warmups', grid + null + cancel)
        self.assertNotIn('--seeds', grid + null + cancel)
        with self.assertRaises(ValueError): collection.command_for('instrument', self.payload, self.base)

    def test_source_command_success_and_host_ack_still_do_not_qualify_results(self):
        result, events = self.stage()
        self.assertEqual([row[0] for row in events], ['measurement', 'command', 'pack', 'export'])
        self.assertEqual(result['status'], 'COLLECTED')
        self.assertEqual(result['all_record_validation'], 'NOT RUN')
        self.assertFalse(result['reference_qualified'])

    def test_failed_command_retains_and_exports_original_bytes_once(self):
        result, events = self.stage(code=1)
        self.assertEqual([row[0] for row in events], ['measurement', 'command', 'pack', 'export'])
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['package_status'], 'HOST ACKNOWLEDGED')
        self.assertEqual(result['failures'][0]['phase'], 'collection')
        self.assertEqual(events[-1][2], b'original CAS bytes')

    def test_missing_host_ack_does_not_replay_an_original_success(self):
        result, events = self.stage(ack='FAIL')
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(sum(row[0] == 'command' for row in events), 1)
        self.assertTrue((self.base / 'exports/packages/grid/capture.zip').is_file())

    def test_expired_collection_budget_still_attempts_retention_in_finish_reserve(self):
        self.deadline = time.monotonic_ns() - 1
        result, events = self.stage()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(events, [])
        self.assertEqual(result['package_status'], 'MISSING RAW')


if __name__ == '__main__': unittest.main()
