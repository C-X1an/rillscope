"""Actual owned metadata replacement and explicit directory-fsync platform scope."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import kvm_pilot_common as common
from kvm_capture_channel import fsync_directory


class Metadata(unittest.TestCase):
    def setUp(self):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='km-', dir=ROOT / '.local-runs')
        self.base = Path(self.temporary.name)

    def tearDown(self): self.temporary.cleanup()

    def test_transient_replace_retries_preserving_exact_new_bytes(self):
        target = self.base / 'state.json'; target.write_bytes(b'old original bytes')
        actual_replace = os.replace; calls = []
        def replace(source, destination):
            calls.append((source, destination))
            if len(calls) < 3: raise PermissionError('deliberate transient sharing fixture')
            actual_replace(source, destination)
        with patch.object(common.os, 'replace', side_effect=replace), patch.object(common.time, 'sleep'):
            common.write_json(target, {'actual': 'new bytes', 'status': 'FAIL'})
        self.assertEqual(len(calls), 3)
        self.assertEqual(json.loads(target.read_bytes()), {'actual': 'new bytes', 'status': 'FAIL'})
        self.assertEqual(list(self.base.iterdir()), [target])

    def test_persistent_failure_retains_original_and_full_pending_bytes(self):
        target = self.base / 'state.json'; target.write_bytes(b'old original bytes')
        with patch.object(common.os, 'replace', side_effect=PermissionError('deliberate persistent fixture')) as replace, \
                patch.object(common.time, 'sleep'), self.assertRaises(PermissionError):
            common.write_json(target, {'status': 'FAIL', 'original': 'new metadata retained'})
        self.assertEqual(replace.call_count, 4)
        self.assertEqual(target.read_bytes(), b'old original bytes')
        pending = list(self.base.glob('state.json.pending-*')); self.assertEqual(len(pending), 1)
        self.assertEqual(json.loads(pending[0].read_bytes()), {'status': 'FAIL', 'original': 'new metadata retained'})

    def test_actual_directory_fsync_has_explicit_platform_scope(self):
        if os.name == 'posix':
            fsync_directory(self.base)
        else:
            with self.assertRaises((AttributeError, OSError)): fsync_directory(self.base)


if __name__ == '__main__': unittest.main()
