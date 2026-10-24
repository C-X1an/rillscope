"""Pinned version and actual-platform guards; no installer is executed here."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_guest_setup as setup


class NativeSetupControls(unittest.TestCase):
    def outputs(self):
        return [b'rustup 1.28.2 (literal fixture)\n',
            b'rustc 1.99.0 (literal)\nhost: x86_64-unknown-linux-gnu\nrelease: 1.99.0\n',
            b'cargo 1.99.0 (literal fixture)\n', b'cargo-audit 0.22.2\n', b'cargo-deny 0.20.2\n']

    def test_actual_version_parser_rejects_wrong_native_host_versions_or_duplicate_fields(self):
        self.assertEqual(setup.check_rust_versions(*self.outputs())['rustc']['release'], '1.99.0')
        for index, changed in [(0, b'rustup latest\n'), (1, b'host: x86_64-pc-windows-gnu\nrelease: 1.99.0\n'),
            (1, b'host: x86_64-unknown-linux-gnu\nrelease: 1.99.0\nrelease: 1.99.0\n'),
            (2, b'cargo 1.98.0\n'), (3, b'cargo-audit 0.22.1\n'), (4, b'cargo-deny 0.20.1\n'),
            (0, b'\n'), (2, b'\n'), (1, b'x' * 16385)]:
            with self.subTest(index=index, changed=changed[:40]):
                raw = self.outputs(); raw[index] = changed
                with self.assertRaises(ValueError): setup.check_rust_versions(*raw)

    def test_unowned_runtime_cannot_install_or_retire_any_files(self):
        with patch.object(setup.device, 'guard', side_effect=ValueError('actual owned guest required')), \
            patch.object(setup, 'durable_mkdir') as mkdir, patch.object(setup.shutil, 'rmtree') as retire:
            with self.assertRaisesRegex(ValueError, 'actual owned guest'): setup.setup({})
            with self.assertRaisesRegex(ValueError, 'actual owned guest'): setup.retire_tool_target()
            mkdir.assert_not_called(); retire.assert_not_called()


if __name__ == '__main__': unittest.main()
