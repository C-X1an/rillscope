"""Export hook fault controls using tiny real CAS; never benchmark observations."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import dispatch
import reference_gate
import reference_capture_export as exporter
import reference_measurement_barrier as measurement
from workloads import descriptors

COMMIT = 'b' * 40
FILES = [['Cargo.toml', 'a' * 64]]
SOURCE = {'files': FILES, 'sha256': hashlib.sha256(json.dumps(FILES, separators=(',', ':')).encode()).hexdigest()}


class CaptureExport(unittest.TestCase):
    def setUp(self):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='ke-', dir=ROOT / '.local-runs')
        self.base = Path(self.temporary.name)
        self.config = self.base / 'export-config.json'
        self.value = {'schema_version': 1, 'method': 'rillscope-full-capture-v1',
            'commit': COMMIT, 'source_sha256': SOURCE['sha256'], 'transfer_seconds': 180,
            'deadline_monotonic_ns': time.monotonic_ns() + 300_000_000_000}
        self.config.write_text(json.dumps(self.value), encoding='utf-8')
        self.env = {'RILLSCOPE_REFERENCE_EXPORT_CONFIG': str(self.config),
            'RILLSCOPE_REFERENCE_EXPORT_CONFIG_SHA256': hashlib.sha256(self.config.read_bytes()).hexdigest()}
        raw = self.base / 'raw'; raw.mkdir()
        self.manifest = {'source': copy.deepcopy(SOURCE), 'schema_version': 3, 'commit': COMMIT,
            'dirty': False, 'profile': 'full', 'warmups': 5, 'repetitions': 30,
            'seeds': [20261014, 20261015, 20261016, 20261017, 20261018],
            'chosen_workloads': descriptors(), 'expected_cases': 410, 'expected_observations': 43050}
        (raw / 'manifest.json').write_text(json.dumps(self.manifest), encoding='utf-8')
        (raw / 'original-error.bin').write_bytes(b'original-failure\0\xff')
        archive_capture.pack(raw, self.base / 'package')
        self.archive = self.base / 'package/capture.zip'
        self.original = self.archive.read_bytes()

    def tearDown(self): self.temporary.cleanup()

    def invoke(self, sender=None, **changes):
        with patch.dict(os.environ, self.env, clear=True), \
                patch.object(exporter, 'source_identity', return_value=copy.deepcopy(SOURCE)), \
                patch.object(exporter, 'git_identity'), \
                patch.object(exporter, 'send_archive', side_effect=sender) as send:
            result = exporter.export_capture(self.archive, changes.get('stage', 'grid'))
        self.assertEqual(self.archive.read_bytes(), self.original)
        return result, send

    def test_no_config_does_not_open_a_device_or_claim_export(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(exporter, 'send_archive') as send:
            result = exporter.export_capture(self.archive, 'grid')
        self.assertEqual(result['status'], 'NOT REQUESTED'); send.assert_not_called()

    def test_acknowledged_original_bytes_still_have_no_all_record_or_reference_verdict(self):
        def ack(archive, stage, deadline, **identity):
            self.assertEqual((archive, stage), (self.archive, 'grid'))
            self.assertEqual(identity, {'commit': COMMIT, 'source_sha256': SOURCE['sha256']})
            self.assertGreater(deadline, time.monotonic())
            return {'status': 'HOST ACKNOWLEDGED', 'sha256': hashlib.sha256(self.original).hexdigest()}
        result, send = self.invoke(ack)
        self.assertEqual(result['status'], 'HOST ACKNOWLEDGED'); self.assertEqual(send.call_count, 1)
        self.assertFalse(result['reference_qualified'])
        self.assertEqual(result['all_record_validation'], 'NOT RUN')
        saved = json.loads((self.archive.parent / 'host-export-result.json').read_bytes())
        self.assertEqual(saved, result)

    def test_changed_configuration_hash_fails_without_sending(self):
        self.config.write_bytes(self.config.read_bytes() + b' ')
        result, send = self.invoke()
        self.assertEqual(result['status'], 'FAIL'); send.assert_not_called()

    def test_duplicate_config_key_fails_without_sending(self):
        self.config.write_bytes(b'{"schema_version":1,' + self.config.read_bytes()[1:])
        self.env['RILLSCOPE_REFERENCE_EXPORT_CONFIG_SHA256'] = hashlib.sha256(self.config.read_bytes()).hexdigest()
        result, send = self.invoke()
        self.assertEqual(result['status'], 'FAIL'); send.assert_not_called()

    def test_expired_whole_attempt_deadline_does_not_start_transfer(self):
        self.value['deadline_monotonic_ns'] = time.monotonic_ns() - 1
        self.config.write_text(json.dumps(self.value), encoding='utf-8')
        self.env['RILLSCOPE_REFERENCE_EXPORT_CONFIG_SHA256'] = hashlib.sha256(self.config.read_bytes()).hexdigest()
        result, send = self.invoke()
        self.assertEqual(result['status'], 'FAIL'); send.assert_not_called()

    def test_mid_transfer_configuration_change_is_a_failure_after_retaining_ack(self):
        def change(*_args, **_kwargs):
            self.config.write_bytes(self.config.read_bytes() + b' ')
            return {'status': 'HOST ACKNOWLEDGED', 'sha256': hashlib.sha256(self.original).hexdigest()}
        result, send = self.invoke(change)
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(send.call_count, 1)
        self.assertEqual(result['host_transfer']['status'], 'HOST ACKNOWLEDGED')

    def test_missing_ack_propagates_failure_with_original_archive_intact(self):
        result, _ = self.invoke(lambda *_args, **_kwargs: {'status': 'FAIL'})
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['reference_qualified'])

    def test_unknown_stage_does_not_start_transfer(self):
        result, send = self.invoke(stage='instrument')
        self.assertEqual(result['status'], 'FAIL'); send.assert_not_called()

    def test_existing_original_export_result_cannot_be_overwritten_or_replayed(self):
        original = b'{"status":"FAIL","original":true}\n'
        target = self.archive.parent / 'host-export-result.json'; target.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'overwritten'): self.invoke()
        self.assertEqual(target.read_bytes(), original)

    def test_reference_gate_cannot_ignore_a_failed_configured_export(self):
        out = self.base / 'gate'; (out / 'grid').mkdir(parents=True)
        (out / 'grid/failure.bin').write_bytes(b'real retained unit failure')
        with patch.object(exporter, 'export_capture', return_value={'status': 'FAIL', 'reference_qualified': False}) as send:
            code = reference_gate.retain_capture(out, 'grid')
        self.assertNotEqual(code, 0)
        self.assertEqual(send.call_count, 1)
        self.assertTrue((out / 'capture-grid/capture.zip').is_file())

    def test_null_sort_original_failure_is_retained_before_return_without_a_validator_rerun(self):
        calls = []
        proof = {'bins': {'rillscope-measure': {'path': 'unit-no-binary'}}}
        def run(command, **_kwargs):
            calls.append(Path(command[1]).name)
            raw = Path(command[command.index('--out') + 1]); raw.mkdir(parents=True)
            (raw / 'original.bin').write_bytes(b'original unit collector failure')
            return 19
        with patch.object(dispatch, 'ROOT', self.base), patch.object(archive_capture, 'ROOT', self.base), \
                patch.object(dispatch, 'build_release', return_value=proof), \
                patch.object(dispatch.subprocess, 'call', side_effect=run), \
                patch.object(exporter, 'export_capture', return_value={'status': 'HOST ACKNOWLEDGED'}) as send, \
                patch.object(sys, 'argv', ['dispatch.py', '--profile', 'sort-null-supplement']):
            code = dispatch.main()
        self.assertEqual(code, 19); self.assertEqual(calls, ['run.py'])
        self.assertEqual(send.call_count, 1)
        self.assertEqual(send.call_args.args[1], 'sort-null')
        self.assertTrue(send.call_args.args[0].is_file())

    def test_null_sort_coordination_and_export_precede_mandatory_inline_validator(self):
        events = []
        proof = {'bins': {'rillscope-measure': {'path': 'unit-no-binary'}}}
        def run(command, **_kwargs):
            name = Path(command[1]).name
            if name == 'run.py':
                raw = Path(command[command.index('--out') + 1]); raw.mkdir(parents=True)
                (raw / 'unit.bin').write_bytes(b'explicit tiny orchestration fixture')
                events.append('collect'); return 0
            self.assertEqual(name, 'verify.py'); events.append('validate'); return 29
        def coordinated(stage, operation):
            events.append('begin-' + stage); code = operation(); events.append('end-' + stage); return code
        def export(archive, stage):
            self.assertTrue(archive.is_file()); self.assertEqual(stage, 'sort-null')
            events.append('export'); return {'status': 'HOST ACKNOWLEDGED'}
        with patch.object(dispatch, 'ROOT', self.base), patch.object(archive_capture, 'ROOT', self.base), \
                patch.object(dispatch, 'build_release', return_value=proof), \
                patch.object(dispatch.subprocess, 'call', side_effect=run), \
                patch.object(measurement, 'collect', side_effect=coordinated), \
                patch.object(exporter, 'export_capture', side_effect=export), \
                patch.object(sys, 'argv', ['dispatch.py', '--profile', 'sort-null-supplement']):
            code = dispatch.main()
        self.assertEqual(code, 29, 'export must never replace a failing canonical validator')
        self.assertEqual(events, ['begin-sort-null', 'collect', 'end-sort-null', 'export', 'validate'])


if __name__ == '__main__': unittest.main()
