"""Literal file-custody fixtures only; no compilation or native execution."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import canonical_reference_binaries as binaries
import canonical_reference_guest_owner as owner
from evidence import source_identity


def digest(raw): return hashlib.sha256(raw).hexdigest()


def elf(label):
    raw = bytearray(64); raw[:6] = b'\x7fELF\x02\x01'; raw[18:20] = (62).to_bytes(2, 'little')
    return bytes(raw) + b'SYNTHETIC NONEXECUTABLE FIXTURE ONLY: ' + label


class NativeBinaryCustody(unittest.TestCase):
    def write(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); return path

    def build(self, root, receipt, target, profile, data):
        compiler = 'rustc 1.99.0 (synthetic fixture only)\nhost: x86_64-unknown-linux-gnu\n'
        raw = {'cargo.stdout': b'SYNTHETIC cargo bytes; no compiler was run\n', 'cargo.stderr': b'',
            'compiler.stdout': compiler.encode(), 'compiler.stderr': b''}
        opt, debug = ('3', False) if profile == 'release' else ('0', True)
        bins = {}
        for name, content in data.items():
            path = self.write(root / target / name, content)
            bins[name] = {'path': path.relative_to(root).as_posix(), 'sha256': digest(content),
                'actual_profile': {'opt_level': opt, 'debug_assertions': debug, 'test': False}}
        row = {'schema_version': 2, 'status': 'PASS', 'exit_code': 0, 'profile': profile,
            'fresh_target_directory': profile == 'release', 'target_directory': target,
            'source': source_identity(root), 'source_after_sha256': source_identity(root)['sha256'],
            'cargo_lock_sha256': digest((root / 'Cargo.lock').read_bytes()), 'bins': bins,
            'compiler_selection': 'explicit pinned sysroot executable passed as RUSTC', 'compiler': compiler,
            'compiler_configuration': {'RUSTUP_TOOLCHAIN': '1.99.0', 'RUSTC_WRAPPER': '',
                'RUSTC_WORKSPACE_WRAPPER': '', 'CARGO_ENCODED_RUSTFLAGS': ''},
            'raw_stdout_sha256': digest(raw['cargo.stdout']), 'raw_stderr_sha256': digest(raw['cargo.stderr']),
            'raw_compiler_stdout_sha256': digest(raw['compiler.stdout']), 'raw_compiler_stderr_sha256': digest(raw['compiler.stderr'])}
        for name, content in raw.items(): self.write(receipt.parent / name, content)
        self.write(receipt, json.dumps(row).encode()); return row

    def fixture(self, root):
        clone = root / '.local-runs/clean-1/c'
        self.write(root / 'Cargo.lock', b'SYNTHETIC dependency lock\n')
        self.write(clone / 'Cargo.lock', b'SYNTHETIC dependency lock\n')
        identity = source_identity(root)['sha256']; self.assertEqual(identity, source_identity(clone)['sha256'])
        self.write(clone.parent / 'results.json', json.dumps({'commit': 'a' * 40, 'source_sha256': identity,
            'checkout': '.local-runs/clean-1/c', 'status': 'FAIL', 'fixture': 'No native attempt executed'}).encode())
        dev = clone / '.local-runs/build/dev-123/build.json'
        self.build(clone, dev, 'target/debug', 'dev', {'rillscope': elf(b'functional')})
        self.write(clone / 'target/debug/rillscope.build.json', b'{"receipt":".local-runs/build/dev-123/build.json"}')
        full = clone / '.local-runs/benchmark-123'; supplement = clone / '.local-runs/bench/s-123'
        full_row = self.build(clone, full / 'build/build.json', '.local-runs/t/full-123', 'release',
            {'rillscope': elf(b'cancel'), 'rillscope-measure': elf(b'measure')})
        null_row = self.build(clone, supplement / 'build/build.json', '.local-runs/t/sort-123', 'release',
            {'rillscope': elf(b'cancel'), 'rillscope-measure': elf(b'measure')})
        for experiment, stage, profile, name, build in [(full, 'grid', 'full', 'rillscope-measure', full_row),
            (full, 'cancel', None, 'rillscope', full_row),
            (supplement, 'grid', 'sort-null-supplement', 'rillscope-measure', null_row)]:
            self.write(experiment / stage / 'manifest.json', json.dumps({'profile': profile, 'build': build,
                'source': build['source'], 'binary_sha256': build['bins'][name]['sha256'],
                'build_receipt_sha256': digest((experiment / 'build/build.json').read_bytes())}).encode())
        return clone, identity

    def retain(self, root, identity):
        out = root / '.local-runs/native-binaries'
        # File bytes/hashes run for real on either OS. This adapter does not
        # claim Linux directory-fsync or actual guest runtime was exercised.
        with patch.object(binaries, 'ROOT', root), patch.object(archive_capture, 'ROOT', root), \
            patch.object(binaries, 'actual_guest'), patch.object(binaries, 'fsync_directory'):
            result = binaries.retain(out, commit='a' * 40, source_sha256=identity,
                cutoff_ns=time.monotonic_ns() + 30 * 10**9)
        return out, result

    def workspace(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='nb-', dir=local)

    def test_exact_four_associations_share_only_identical_original_bytes(self):
        with self.workspace() as folder:
            root = Path(folder); clone, identity = self.fixture(root)
            out, result = self.retain(root, identity)
            self.assertEqual(result['status'], 'RETAINED ORIGINAL BYTES', result['errors'])
            self.assertEqual([row['role'] for row in result['associations']], ['functional', 'full-grid', 'full-cancel', 'sort-null'])
            self.assertEqual(len(result['objects']), 3)
            self.assertEqual(result['upstream_fresh_status'], 'FAIL')
            self.assertIs(result['reference_qualified'], False)
            expected = {'functional': elf(b'functional'), 'full-grid': elf(b'measure'),
                'full-cancel': elf(b'cancel'), 'sort-null': elf(b'measure')}
            for row in result['associations']:
                self.assertEqual((out / row['object']).read_bytes(), expected[row['role']])
                self.assertEqual((root / row['original_binary']).read_bytes(), expected[row['role']])
            self.assertEqual(result['associations'][1]['object'], result['associations'][3]['object'])
            for row in result['metadata']:
                self.assertEqual((out / row['file']).read_bytes(), (root / row['source']).read_bytes())
            self.assertEqual(json.loads((clone.parent / 'results.json').read_bytes())['status'], 'FAIL')

    def test_changed_shared_second_binary_cannot_borrow_first_receipt_hash(self):
        with self.workspace() as folder:
            root = Path(folder); clone, identity = self.fixture(root)
            (clone / '.local-runs/t/sort-123/rillscope-measure').write_bytes(elf(b'TAMPERED'))
            out, result = self.retain(root, identity)
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['associations'][-1]['status'], 'FAIL')
            self.assertEqual(len(result['objects']), 3)
            self.assertTrue(any(row['role'] == 'sort-null' for row in result['errors']))

    def test_manifest_hash_mismatch_retains_other_roles_without_relabeling(self):
        with self.workspace() as folder:
            root = Path(folder); clone, identity = self.fixture(root)
            path = clone / '.local-runs/benchmark-123/grid/manifest.json'
            row = json.loads(path.read_bytes()); row['build_receipt_sha256'] = '0' * 64; path.write_text(json.dumps(row))
            out, result = self.retain(root, identity)
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['associations'][1]['status'], 'FAIL')
            self.assertEqual(result['associations'][2]['status'], 'RETAINED ORIGINAL BYTES')
            self.assertEqual(result['associations'][3]['status'], 'RETAINED ORIGINAL BYTES')

    def test_ambiguous_attempt_is_never_resolved_by_timestamps(self):
        with self.workspace() as folder:
            root = Path(folder); clone, identity = self.fixture(root)
            (root / '.local-runs/clean-999').mkdir()
            out, result = self.retain(root, identity)
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['objects'], [])
            self.assertIn('ambiguous original native attempt', result['errors'][0]['reason'])

    def test_arbitrary_windows_bytes_are_not_native_elf_evidence(self):
        for raw in (b'MZ' + b'\x00' * 70, b'\x7fELF\x01\x01' + b'\x00' * 60, b'\x7fELF\x02\x01' + b'\x00' * 60):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, 'native Linux x86_64 ELF64'):
                    binaries.native_prefix(raw)

    def test_later_valid_build_cannot_replace_the_already_retained_proof_snapshot(self):
        with self.workspace() as folder:
            root = Path(folder); clone, identity = self.fixture(root)
            real_verify = binaries.verify_build; replaced = []
            def interleave(receipt, binary, **kwargs):
                if kwargs['profile'] == 'dev' and not replaced:
                    replaced.append(True)
                    self.build(clone, receipt, 'target/debug', 'dev', {'rillscope': elf(b'LATER VALID BUILD')})
                return real_verify(receipt, binary, **kwargs)
            with patch.object(binaries, 'verify_build', side_effect=interleave):
                out, result = self.retain(root, identity)
            self.assertEqual(replaced, [True])
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['associations'][0]['status'], 'FAIL')
            self.assertIn('retained proof snapshot', result['errors'][0]['reason'])
            for row in result['associations']:
                if row['status'] != 'RETAINED ORIGINAL BYTES': continue
                kept = json.loads((out / row['metadata'][0]).read_bytes())
                self.assertEqual(kept['bins'][row['binary_name']]['sha256'], row['sha256'])

    def test_expired_or_unavailable_runtime_cannot_create_output(self):
        with self.workspace() as folder:
            root = Path(folder); clone, identity = self.fixture(root); out = root / '.local-runs/none'
            with patch.object(binaries, 'actual_guest', side_effect=ValueError('actual owned Linux guest missing')):
                with self.assertRaisesRegex(ValueError, 'actual owned Linux guest'):
                    binaries.retain(out, commit='a' * 40, source_sha256=identity, cutoff_ns=1)
            self.assertFalse(out.exists())
            with patch.object(binaries, 'actual_guest'):
                with self.assertRaisesRegex(ValueError, 'finite original'):
                    binaries.retain(out, commit='a' * 40, source_sha256=identity, cutoff_ns=1)
            self.assertFalse(out.exists())


class OriginalRetentionReserve(unittest.TestCase):
    def test_late_final_child_return_fails_the_earlier_shared_reserve(self):
        for finished, expected in [(20 * 10**9, 'RETAINED'), (22 * 10**9, 'FAIL')]:
            with self.subTest(finished=finished):
                clock = {'now': 10**9}
                def direct(name, command, **kwargs):
                    clock['now'] = 2 * 10**9 if name == 'retain-native-binaries' else finished
                    return b'{"status":"RETAINED ORIGINAL BYTES","reference_qualified":false}'
                with patch.object(owner.time, 'monotonic_ns', side_effect=lambda: clock['now']):
                    row = owner.retain_original_outputs(direct, cutoff_ns=90 * 10**9, retention_seconds=20,
                        identity={'commit': 'a' * 40, 'source_sha256': 'b' * 64}, receipt_path=Path('/original'))
                self.assertEqual(row['cutoff_monotonic_ns'], 21 * 10**9)
                self.assertEqual(row['status'], expected)
                self.assertEqual(row['native_binaries'], 'RETAINED')
                if expected == 'FAIL':
                    self.assertEqual(row['release_metadata'], 'FAIL')
                    self.assertTrue(row['errors'])

    def test_both_steps_spend_one_reserve_and_original_earlier_cutoff(self):
        for cutoff, expected in [(15 * 10**9, 15 * 10**9), (90 * 10**9, 21 * 10**9)]:
            with self.subTest(cutoff=cutoff):
                seen = []
                def direct(name, command, **kwargs):
                    seen.append((name, command, kwargs))
                    return b'{"status":"RETAINED ORIGINAL BYTES","reference_qualified":false}'
                with patch.object(owner.time, 'monotonic_ns',
                    side_effect=[10**9, 2 * 10**9, 3 * 10**9, 7 * 10**9, 8 * 10**9, 9 * 10**9]):
                    row = owner.retain_original_outputs(direct, cutoff_ns=cutoff, retention_seconds=20,
                        identity={'commit': 'a' * 40, 'source_sha256': 'b' * 64}, receipt_path=Path('/original'))
                self.assertEqual(row['status'], 'RETAINED')
                self.assertEqual(row['cutoff_monotonic_ns'], expected)
                self.assertEqual([item[0] for item in seen], ['retain-native-binaries', 'retain-canonical'])
                self.assertEqual(seen[0][2]['timeout'], expected / 10**9 - 2)
                self.assertEqual(seen[1][2]['timeout'], expected / 10**9 - 7)
                self.assertEqual(seen[0][1][-2:], ['--cutoff-monotonic-ns', str(expected)])
                self.assertEqual(seen[0][2]['inputs'], (Path('/original'),))

    def test_failed_native_step_still_preserves_available_original_release_metadata(self):
        calls = []
        def direct(name, command, **kwargs):
            calls.append(name)
            if name == 'retain-native-binaries': raise ValueError('synthetic original binary absent')
            return b''
        with patch.object(owner.time, 'monotonic_ns', return_value=10**9):
            row = owner.retain_original_outputs(direct, cutoff_ns=30 * 10**9, retention_seconds=20,
                identity={'commit': 'a' * 40, 'source_sha256': 'b' * 64}, receipt_path=Path('/original'))
        self.assertEqual(calls, ['retain-native-binaries', 'retain-canonical'])
        self.assertEqual(row['status'], 'FAIL')
        self.assertEqual(row['native_binaries'], 'FAIL')
        self.assertEqual(row['release_metadata'], 'RETAINED')
        self.assertIn('synthetic original binary absent', row['errors'][0]['reason'])


if __name__ == '__main__': raise SystemExit(unittest.main())
