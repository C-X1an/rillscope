"""Recovery fault controls with original tiny CAS bytes; external disk tools stubbed."""
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import kvm_benchmark_pilot as pilot


class Recovery(unittest.TestCase):
    def exercise(self, fault=None):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='kd-', dir=ROOT / '.local-runs') as temporary:
            base = Path(temporary); out = base / 'out'; (out / 'artifact/packages').mkdir(parents=True)
            guest = base / 'guest'; (guest / 'exports/packages').mkdir(parents=True)
            for name in ('commands', 'raw-receipts'):
                (guest / name).mkdir(); (guest / name / 'retained.txt').write_bytes(b'original command bytes')
            for stage, _, _ in pilot.STAGES:
                raw = guest / 'raw' / stage; raw.mkdir(parents=True)
                (raw / 'actual.bin').write_bytes(('original-' + stage).encode())
                if fault != 'missing-tail' or stage != 'tail':
                    archive_capture.pack(raw, guest / 'exports/packages' / stage)
            instrument = out / 'artifact/packages/instrument'; instrument.mkdir()
            shutil.copy2(guest / 'exports/packages/instrument/capture.zip', instrument / 'capture.zip')
            original_instrument = (instrument / 'capture.zip').read_bytes()
            if fault == 'host-mismatch': (instrument / 'capture.zip').write_bytes(b'preserve mismatching host bytes')
            calls = []
            def checked(name, command, **_):
                calls.append(name)
                if name == 'recover-filesystem-state':
                    return b'Filesystem state: clean\n' if fault != 'unclean' else b'Filesystem state: not clean\n'
                if command[0] == 'fixture-rdump':
                    source, destination = command[1:]
                    actual = guest / source.removeprefix('/c/.local-runs/kvm-pilot/')
                    if fault == 'exports-error' and actual == guest / 'exports': raise OSError('deliberate export failure')
                    shutil.copytree(actual, destination, dirs_exist_ok=True); return b''
                if '--source' in command:
                    source = Path(command[command.index('--source') + 1]); destination = Path(command[command.index('--out') + 1])
                    archive_capture.pack(source, destination); return b''
                self.fail('unexpected recovery command: ' + str(command))
            def debugfs(_image, source, destination, **_): return ['fixture-rdump', source, str(destination)]
            disk = {'bytes': pilot.DISK_BYTES, 'sha256': '1' * 64}
            with patch.object(pilot, 'disk_identity', return_value=disk), patch.object(pilot, 'debugfs_command', side_effect=debugfs):
                result = pilot.recover(out, checked, time.monotonic() + 10)
            self.assertTrue((out / 'artifact/guest-helper-commands/retained.txt').is_file())
            self.assertTrue((out / 'artifact/guest-command-receipts/retained.txt').is_file())
            self.assertEqual(result['disk_before'], result['disk_after'])
            self.assertEqual(len(result['packages']), 3)
            self.assertEqual((instrument / 'capture.zip').read_bytes(),
                b'preserve mismatching host bytes' if fault == 'host-mismatch' else original_instrument)
            self.assertEqual(result['status'], 'PASS' if fault is None else 'FAIL')
            if fault == 'missing-tail':
                self.assertEqual([row['status'] for row in result['packages']],
                    ['VERIFIED', 'VERIFIED INCLUDED BYTES', 'VERIFIED'])
                restored = base / 'restored'
                archive_capture.restore(out / 'artifact/partial-packages/tail/capture.zip', restored)
                self.assertEqual((restored / 'actual.bin').read_bytes(), b'original-tail')
            if fault == 'exports-error':
                self.assertEqual([row['status'] for row in result['packages']], ['VERIFIED INCLUDED BYTES'] * 3)
            return result

    def test_exact_original_archives_match_acknowledged_host_bytes(self): self.exercise()
    def test_missing_middle_archive_preserves_partial_raw_and_later_archive(self): self.exercise('missing-tail')
    def test_export_failure_does_not_suppress_receipts_or_any_partial_raw(self): self.exercise('exports-error')
    def test_unclean_filesystem_never_becomes_success_from_valid_cas(self): self.exercise('unclean')
    def test_host_mismatch_never_overwrites_either_original(self): self.exercise('host-mismatch')

    def test_debugfs_command_is_read_only_and_closed(self):
        command = pilot.debugfs_command('/owned/work.raw', '/c/.local-runs/kvm-pilot/raw/tail', '/owned/export', directory=True)
        self.assertEqual(command, ['debugfs', '-R', 'rdump /c/.local-runs/kvm-pilot/raw/tail /owned/export', '/owned/work.raw'])
        for source, destination in (('/c/../other', '/owned/export'), ('/c;evil', '/owned/export'), ('/c', '/owned/a b')):
            with self.subTest(source=source), self.assertRaises(ValueError):
                pilot.debugfs_command('/owned/work.raw', source, destination)


if __name__ == '__main__': unittest.main()
