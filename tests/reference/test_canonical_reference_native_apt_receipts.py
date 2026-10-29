"""Literal synthetic receipt controls; no APT, role or Linux process executes."""
import copy
import datetime as dt
import hashlib
import itertools
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_recovered_records as records
from . import test_canonical_reference_native_apt as fixtures

SEED = '/work/c/.local-runs/canonical-seed/seed.json'
SOURCE = '/work/c/.local-runs/canonical-native-apt/native.sources'
KEY = '/usr/share/keyrings/ubuntu-archive-keyring.gpg'
SEED_RAW = b'EXPLICITLY SYNTHETIC SEED; no command or native setup executed\n'
OUTPUT = b'EXPLICITLY SYNTHETIC OUTPUT; no APT process executed\n'


def digest(raw): return hashlib.sha256(raw).hexdigest()


class NativeAptReceiptBinding(unittest.TestCase):
    def case(self):
        policy, _ = fixtures.fixture()
        observation = {'nodes': policy['nodes'], 'ancestors': policy['ancestors']}
        self.setup = {'elapsed_seconds': 10, 'started_monotonic_ns': 10 * 10**9, 'finished_monotonic_ns': 20 * 10**9,
            'apt_acquisition': {'policy': policy,
            'checks': [{'stage': name, 'before': copy.deepcopy(observation), 'after': copy.deepcopy(observation)}
                for name in ('apt-update', 'apt-install')]}}
        utc = int(dt.datetime(2026, 10, 29, tzinfo=dt.timezone.utc).timestamp()) * 10**9
        self.setup.update(started_utc_ns=utc - 10**9, finished_utc_ns=utc + 9 * 10**9)
        self.seed = {'commit': 'a' * 40, 'setup_seconds': 900}
        self.source = {'sha256': 'b' * 64, 'files': [['synthetic-only', 'c' * 64]]}
        # Independently spelled lexical order: keyring, acquisition source, seed.
        self.inputs = [{'path': KEY, 'bytes': len(fixtures.PUBLIC_KEY_FIXTURE), 'sha256': digest(fixtures.PUBLIC_KEY_FIXTURE)},
            {'path': SOURCE, 'bytes': len(fixtures.SOURCE), 'sha256': digest(fixtures.SOURCE)},
            {'path': SEED, 'bytes': len(SEED_RAW), 'sha256': digest(SEED_RAW)}]
        prefix = ['/usr/bin/apt-get', '-o', 'Dir::Etc::sourcelist=' + SOURCE,
            '-o', 'Dir::Etc::sourceparts=/work/c/.local-runs/canonical-native-apt/empty-sources.d',
            '-o', 'Acquire::Languages=none', '-o', 'Acquire::AllowInsecureRepositories=false',
            '-o', 'Acquire::AllowWeakRepositories=false', '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false',
            '-o', 'Acquire::Check-Valid-Until=true', '-o', 'APT::Get::AllowUnauthenticated=false']
        self.proofs = {}
        for index, (name, suffix) in enumerate((('apt-update', ['--error-on=any', 'update']),
                ('apt-install', ['install', '--yes', '--no-install-recommends', *fixtures.PACKAGES]))):
            self.proofs[name] = {'schema_version': 1, 'command': prefix + suffix, 'cwd': '/work/c',
                'source_before': copy.deepcopy(self.source), 'source_after_sha256': self.source['sha256'],
                'verification_status': 'PASS', 'execution_outcome': 'EXECUTED', 'exit_code': 0,
                'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0},
                'environment': {'system': 'Linux'}, 'git': {'commit': self.seed['commit'], 'dirty': False},
                'started_utc': '2026-10-29T00:00:0' + str(index * 2) + '+00:00',
                'finished_utc': '2026-10-29T00:00:0' + str(index * 2 + 1) + '+00:00', 'elapsed_seconds': 1,
                'monotonic': {'schema_version': 1, 'clock': 'time.monotonic_ns',
                    'started_ns': (11 + index * 2) * 10**9, 'finished_ns': (12 + index * 2) * 10**9},
                'stdout': {'file': 'stdout.txt', 'sha256': digest(OUTPUT)},
                'stderr': {'file': 'stderr.txt', 'sha256': digest(b'')},
                'inputs_before': copy.deepcopy(self.inputs), 'inputs_after': copy.deepcopy(self.inputs),
                'stdin': None, 'fixture': 'Synthetic metadata only; no command executed'}
        self.cutoff = '2026-10-29T00:00:04+00:00'

    def check(self):
        proofs = self.proofs
        class Original:
            members = {'setup': {'commands/' + name + '/' + leaf: 'commands/' + name + '/' + leaf
                for name in ('apt-update', 'apt-install') for leaf in ('receipt.json', 'stdout.txt', 'stderr.txt')}}
            def raw(self, path, limit=16 * 1024**2):
                _, name, leaf = str(path).split('/')
                raw = (json.dumps(proofs[name], sort_keys=True) + '\n').encode() if leaf == 'receipt.json' else OUTPUT if leaf == 'stdout.txt' else b''
                if len(raw) > limit: raise ValueError('Synthetic record exceeds its requested bound')
                return raw
        return records.native_acquisition(Original(), self.setup, self.seed, SEED_RAW, self.source, before_utc=self.cutoff)

    def test_literal_sorted_inputs_close_both_original_reader_stages(self):
        self.case()
        try: checked = self.check()
        except ValueError as error: self.fail('Canonical literal producer order was rejected: ' + str(error))
        self.assertEqual(len(checked), 2)
        self.assertEqual([row['inputs_before'] for row in checked], [self.inputs, self.inputs])
        self.assertEqual([row['inputs_after'] for row in checked], [self.inputs, self.inputs])

    def test_every_other_input_permutation_is_rejected_in_each_stage(self):
        for name in ('apt-update', 'apt-install'):
            for order in itertools.permutations((0, 1, 2)):
                if order == (0, 1, 2): continue
                with self.subTest(stage=name, order=order):
                    self.case()
                    for field in ('inputs_before', 'inputs_after'):
                        self.proofs[name][field] = [copy.deepcopy(self.inputs[index]) for index in order]
                    with self.assertRaisesRegex(ValueError, 'native APT command/input/clock'):
                        self.check()

    def test_each_identity_is_required_in_both_snapshots(self):
        for name, index, key in itertools.product(('apt-update', 'apt-install'), range(3), ('path', 'bytes', 'sha256')):
            with self.subTest(stage=name, index=index, key=key):
                self.case()
                for field in ('inputs_before', 'inputs_after'):
                    self.proofs[name][field][index][key] = '/different/input' if key == 'path' else 99999 if key == 'bytes' else 'f' * 64
                with self.assertRaisesRegex(ValueError, 'native APT command/input/clock'):
                    self.check()

    def test_missing_duplicate_extra_or_changed_after_input_is_rejected(self):
        for name, kind in itertools.product(('apt-update', 'apt-install'), ('missing', 'duplicate', 'extra', 'changed-after')):
            with self.subTest(stage=name, kind=kind):
                self.case()
                if kind == 'changed-after': self.proofs[name]['inputs_after'][0]['bytes'] += 1
                else:
                    for field in ('inputs_before', 'inputs_after'):
                        values = self.proofs[name][field]
                        if kind == 'missing': values.pop()
                        elif kind == 'duplicate': values.append(copy.deepcopy(values[0]))
                        else: values.append({'path': '/other/input', 'bytes': 1, 'sha256': 'd' * 64})
                with self.assertRaises(ValueError): self.check()

    def test_original_UTC_order_cutoff_elapsed_and_shared_duration_guards_remain(self):
        for kind in ('overlap', 'after-cutoff', 'elapsed-span', 'update-limit', 'install-limit', 'shared-setup-limit'):
            with self.subTest(kind=kind):
                self.case()
                if kind == 'overlap':
                    self.proofs['apt-install'].update(started_utc='2026-10-29T00:00:00.500000+00:00', finished_utc='2026-10-29T00:00:01.500000+00:00')
                    self.proofs['apt-install']['monotonic']['started_ns'] = 11_500_000_000
                elif kind == 'after-cutoff':
                    self.proofs['apt-install'].update(started_utc='2026-10-29T00:00:04+00:00', finished_utc='2026-10-29T00:00:05+00:00')
                    self.proofs['apt-install']['monotonic']['started_ns'] = 15 * 10**9
                elif kind == 'elapsed-span': self.proofs['apt-update']['elapsed_seconds'] = 1.02
                elif kind == 'shared-setup-limit': self.setup['elapsed_seconds'] = 1.9
                elif kind == 'update-limit':
                    self.proofs['apt-update'].update(finished_utc='2026-10-29T00:05:01+00:00', elapsed_seconds=301)
                    self.proofs['apt-install'].update(started_utc='2026-10-29T00:05:02+00:00', finished_utc='2026-10-29T00:05:03+00:00')
                    self.cutoff = '2026-10-29T00:05:04+00:00'; self.setup['elapsed_seconds'] = 800
                    self.setup['finished_monotonic_ns'] = 810 * 10**9
                    self.proofs['apt-install']['monotonic'].update(started_ns=313 * 10**9)
                else:
                    self.proofs['apt-install'].update(finished_utc='2026-10-29T00:10:03+00:00', elapsed_seconds=601)
                    self.cutoff = '2026-10-29T00:10:04+00:00'; self.setup['elapsed_seconds'] = 800
                    self.setup['finished_monotonic_ns'] = 810 * 10**9
                for row in self.proofs.values():
                    row['monotonic']['finished_ns'] = row['monotonic']['started_ns'] + int(row['elapsed_seconds'] * 10**9)
                self.setup['finished_utc_ns'] = self.setup['started_utc_ns'] + self.setup['finished_monotonic_ns'] - self.setup['started_monotonic_ns']
                with self.assertRaisesRegex(ValueError, 'native APT command/input/clock|native APT command durations'):
                    self.check()

    def test_receipt_command_runtime_source_raw_stdin_git_and_cleanup_stay_required(self):
        for kind in ('command', 'runtime', 'source', 'raw', 'stdin', 'git', 'cleanup', 'failed-exit'):
            with self.subTest(kind=kind):
                self.case(); row = self.proofs['apt-install']
                if kind == 'command': row['command'].insert(1, '--allow-unauthenticated')
                elif kind == 'runtime': row['environment']['system'] = 'Windows'
                elif kind == 'source': row['source_after_sha256'] = 'f' * 64
                elif kind == 'raw': row['stdout']['sha256'] = 'f' * 64
                elif kind == 'stdin': row['stdin'] = ''
                elif kind == 'git': row['git']['dirty'] = True
                elif kind == 'cleanup': row['process_cleanup']['remaining_active_processes'] = 1
                else: row['exit_code'] = 1
                with self.assertRaises(ValueError): self.check()


if __name__ == '__main__': unittest.main()
