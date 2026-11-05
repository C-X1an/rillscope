"""Synthetic clock-domain and containment controls; no native setup is executed."""
import datetime as dt
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
import canonical_reference_recovered_records as records
from .test_canonical_reference_recovered_records import prerequisite_fixture, raw, reindex


class SetupMonotonicReceipts(unittest.TestCase):
    def literal(self):
        setup = {'started_monotonic_ns': 1_000_000_000, 'finished_monotonic_ns': 10_000_000_000}
        utc = int(dt.datetime(2026, 10, 29, tzinfo=dt.timezone.utc).timestamp()) * 10**9
        setup.update(started_utc_ns=utc, finished_utc_ns=utc + 9 * 10**9)
        proof = {'elapsed_seconds': 2.0, 'started_utc': '2026-10-29T00:00:01+00:00',
            'finished_utc': '2026-10-29T00:00:03.750000+00:00',
            'monotonic': {'schema_version': 1, 'clock': 'time.monotonic_ns',
                'started_ns': 2_000_000_000, 'finished_ns': 4_000_000_000}}
        return proof, setup

    def helper(self, proof, setup):
        function = getattr(records, 'helper_monotonic_span', None)
        self.assertTrue(callable(function), 'Strict native helper monotonic reader is missing')
        return function(proof, setup)

    def test_literal_monotonic_interval_keeps_bounded_UTC_correlation(self):
        proof, setup = self.literal()
        self.assertEqual(records.UTC_CORRELATION_TOLERANCE_NS, 1_000_000_000)
        self.assertEqual(self.helper(proof, setup), (2_000_000_000, 4_000_000_000))

    def test_missing_unknown_boolean_or_wrong_clock_record_is_rejected(self):
        changes = [lambda p: p.pop('monotonic'), lambda p: p.update(monotonic=None),
            lambda p: p['monotonic'].update(schema_version=True), lambda p: p['monotonic'].update(schema_version=2),
            lambda p: p['monotonic'].update(clock='time.time_ns'), lambda p: p['monotonic'].pop('finished_ns'),
            lambda p: p['monotonic'].update(estimated=True)]
        for change in changes:
            with self.subTest(change=change):
                proof, setup = self.literal(); change(proof)
                with self.assertRaises(ValueError): self.helper(proof, setup)

    def test_typed_boundaries_duration_and_original_enclosing_frame_are_required(self):
        changes = [lambda p, s: p['monotonic'].update(started_ns=True),
            lambda p, s: p['monotonic'].update(finished_ns=4_000_000_000.0),
            lambda p, s: p['monotonic'].update(started_ns=-1),
            lambda p, s: p['monotonic'].update(started_ns=5_000_000_000),
            lambda p, s: (p['monotonic'].update(started_ns=999_999_999, finished_ns=2_999_999_999),
                p.update(started_utc='2026-10-29T00:00:00+00:00', finished_utc='2026-10-29T00:00:02+00:00')),
            lambda p, s: (p['monotonic'].update(started_ns=8_000_000_001, finished_ns=10_000_000_001),
                p.update(started_utc='2026-10-29T00:00:07+00:00', finished_utc='2026-10-29T00:00:09+00:00')),
            lambda p, s: p.update(elapsed_seconds=1.0), lambda p, s: p.update(elapsed_seconds=True),
            lambda p, s: p.update(elapsed_seconds=float('nan')), lambda p, s: p.update(elapsed_seconds=float('inf')),
            lambda p, s: p['monotonic'].update(finished_ns=10**1000),
            lambda p, s: s.update(started_monotonic_ns=True), lambda p, s: s.update(finished_monotonic_ns=0),
            lambda p, s: s.pop('started_utc_ns'), lambda p, s: s.update(started_utc_ns=True),
            lambda p, s: s.update(finished_utc_ns=10**1000),
            lambda p, s: s.update(finished_utc_ns=s['finished_utc_ns'] + 1_000_000_001),
            lambda p, s: p.update(started_utc='2000-01-01T00:00:01+00:00')]
        for change in changes:
            with self.subTest(change=change):
                proof, setup = self.literal(); change(proof, setup)
                with self.assertRaises(ValueError): self.helper(proof, setup)

    def temporary(self):
        parent = ROOT / '.local-runs'; parent.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='mono-', dir=parent)

    def native_path(self, name):
        path = Path(name).resolve()
        return Path('\\\\?\\' + str(path)) if sys.platform == 'win32' else path

    def test_full_original_frame_accepts_subsecond_UTC_gap_between_helpers(self):
        with self.temporary() as name:
            root = self.native_path(name); attempt, artifact, terminal, source = prerequisite_fixture(root)
            for stage in ('rustup-version', 'rustc-version', 'cargo-version', 'audit-version', 'deny-version'):
                path = artifact / 'recovery/setup/commands' / stage / 'receipt.json'; proof = json.loads(path.read_bytes())
                for key in ('started_utc', 'finished_utc'):
                    proof[key] = (dt.datetime.fromisoformat(proof[key]) + dt.timedelta(microseconds=752_000)).isoformat()
                path.write_bytes(raw(proof))
            path = artifact / 'recovery/setup/setup-result.json'; setup = json.loads(path.read_bytes())
            setup.update(started_monotonic_ns=12_900_000_000, finished_monotonic_ns=24_100_000_000,
                deadline_monotonic_ns=912_900_000_000, elapsed_seconds=11.2,
                started_utc_ns=setup['started_utc_ns'] + 900_000_000,
                finished_utc_ns=setup['started_utc_ns'] + 12_852_000_000)
            path.write_bytes(raw(setup))
            path = artifact / 'recovery/start/start-result.json'; start = json.loads(path.read_bytes())
            start['native_setup_elapsed_seconds'] = 11.2; path.write_bytes(raw(start))
            reindex(artifact, terminal['collector']['recovery'])
            with patch.object(archive_capture, 'ROOT', root):
                try: checked = records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)
                except ValueError as error: self.fail('Valid same-domain original containment was rejected: ' + str(error))
            self.assertEqual(checked['setup']['elapsed_seconds'], 11.2)
            self.assertFalse(checked['reference_qualified'])

    def test_full_frame_rejects_outside_or_overlapping_monotonic_helpers(self):
        for kind in ('outside', 'overlap'):
            with self.subTest(kind=kind), self.temporary() as name:
                root = self.native_path(name); attempt, artifact, terminal, source = prerequisite_fixture(root)
                stage = 'rustup-version' if kind == 'outside' else 'cargo-version'
                path = artifact / 'recovery/setup/commands' / stage / 'receipt.json'; proof = json.loads(path.read_bytes())
                begin = 112_000_000_001 if kind == 'outside' else 20_999_999_999
                proof['monotonic'].update(started_ns=begin, finished_ns=begin + 1_000_000_000)
                path.write_bytes(raw(proof)); reindex(artifact, terminal['collector']['recovery'])
                with patch.object(archive_capture, 'ROOT', root), self.assertRaisesRegex(ValueError, 'monotonic'):
                    records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)


if __name__ == '__main__': unittest.main()
