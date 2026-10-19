"""Guest finalization faults with real tiny CAS bytes; no VM or root operations."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import archive_capture
import kvm_pilot_guest as guest


class GuestFinalization(unittest.TestCase):
    def exercise(self, fault):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='kg-', dir=ROOT / '.local-runs') as temporary:
            fixture = Path(temporary); base = fixture / '.local-runs/kvm-pilot'
            for name in ('exports/packages', 'raw', 'raw-receipts', 'home'):
                (base / name).mkdir(parents=True, exist_ok=True)
            payload = {'files': [], 'host_build_environment': {},
                'bins': {'rillscope': {'path': 'cli'}, 'rillscope-measure': {'path': 'measure'}},
                'build_receipt': {'path': 'build.json'}}
            calls = []; after = False
            identity = {'commit': '1' * 40, 'source_sha256': '2' * 64, 'binary_sha256': {}}
            def probe(_):
                if fault == 'identity' and after: raise ValueError('deliberate post-stage identity failure')
                return identity
            def snapshot(phase):
                if fault == 'keyboard' and phase == 'instrument-after':
                    raise KeyboardInterrupt('deliberate post-stage interruption')
                if fault == 'snapshot' and phase.endswith('-after'):
                    raise ValueError('deliberate post-stage resource failure')
                return {'phase': phase}
            def interfaces():
                carrier = '1' if fault == 'network' and after else '0'
                return {'interfaces': [{'name': 'lo', 'carrier': '1', 'operstate': 'unknown'},
                    {'name': 'ens3', 'carrier': carrier, 'operstate': 'up' if carrier == '1' else 'down'}],
                    'ipv4_routes': 'retained actual route fixture', 'ipv6_routes': ''}
            def checked(name, command, **_):
                nonlocal after
                if name == 'serial-getty-state': return b'LoadState=masked\nActiveState=inactive\n'
                if name.startswith('campaign-'):
                    label = name.removeprefix('campaign-'); calls.append(label)
                    if fault == 'no-raw': raise OSError('deliberate launch failure before raw creation')
                    raw = base / 'raw' / label; raw.mkdir()
                    (raw / 'actual.bin').write_bytes(b'original-tiny-capture\0\xff')
                    receipt = base / 'raw-receipts' / label; receipt.mkdir()
                    (receipt / 'receipt.json').write_text(json.dumps({'verification_status': 'PASS', 'exit_code': 0}), encoding='utf-8')
                    after = True
                    if fault == 'interrupt' and label == 'instrument':
                        raise guest.TrialInterrupted('deliberate handled campaign interruption')
                elif name.startswith('pack-'):
                    source = Path(command[command.index('--source') + 1])
                    out = Path(command[command.index('--out') + 1])
                    archive_capture.pack(source, out)
            observer = SimpleNamespace(error=None, count=1,
                thread=SimpleNamespace(start=lambda: None), close=lambda: None)
            account = SimpleNamespace(pw_uid=65534, pw_gid=65534)
            caught = None; result = None
            with patch.object(guest, 'BASE', base), patch.object(guest, 'TrialCommands', return_value=checked), \
                    patch.object(guest, 'payload_files', return_value=[]), patch.object(guest, 'probe_identity', side_effect=probe), \
                    patch.object(guest, 'snapshot', side_effect=snapshot), patch.object(guest, 'interfaces', side_effect=interfaces), \
                    patch.object(guest.platform, 'libc_ver', return_value=('fixture-libc', '1')), \
                    patch.object(guest, 'emit'), patch.object(guest, 'GuestObserver', return_value=observer), \
                    patch.object(guest, 'send_archive', return_value={'status': 'HOST ACKNOWLEDGED'}), \
                    patch.object(guest.os, 'chown', create=True), patch.object(guest.os, 'sync', create=True), \
                    patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwnam=lambda _: account)}), \
                    patch.object(archive_capture, 'ROOT', fixture):
                try: result = guest.collect(payload, None)
                except ValueError as error: caught = error
                if fault in ('network', 'interrupt', 'keyboard', 'no-raw'):
                    self.assertEqual(calls, ['instrument'], 'a link returning UP must prevent later child launches')
                if fault not in ('network', 'no-raw'):
                    package = base / 'exports/packages/instrument/capture.zip'
                    self.assertTrue(package.is_file(), 'post-stage diagnostics must not prevent raw packaging')
                    restored = fixture / '.local-runs/restored'
                    archive_capture.restore(package, restored)
                    self.assertEqual((restored / 'actual.bin').read_bytes(), b'original-tiny-capture\0\xff')
                self.assertIsNone(caught, 'stage failure must remain durably reported without escaping finalization')
                self.assertEqual(result['status'], 'FAIL')
                recorded = json.loads((base / 'exports/campaigns.json').read_bytes())
                self.assertEqual(recorded[0]['status'], 'FAIL')
                if fault in ('interrupt', 'keyboard'):
                    self.assertEqual(len(recorded),1,'interruption must stop after independent finalization')
                    self.assertIs(recorded[0]['interrupted'],True)
                self.assertFalse(result['reference_qualified'])

    def test_post_stage_resource_failure_still_packages_original_bytes(self): self.exercise('snapshot')
    def test_post_stage_identity_failure_still_packages_original_bytes(self): self.exercise('identity')
    def test_network_returning_up_prevents_later_campaign_launch(self): self.exercise('network')
    def test_handled_campaign_interruption_packages_and_stops(self): self.exercise('interrupt')
    def test_post_stage_keyboard_interruption_packages_and_stops(self): self.exercise('keyboard')
    def test_launch_failure_before_raw_stops_without_host_ack(self): self.exercise('no-raw')


if __name__ == '__main__': unittest.main()
