"""Synthetic clock coverage counterexamples; no VM or physical resource claims."""
import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import verify_kvm_pilot as checker
from kvm_pilot_common import PREFIX


class HostCoverage(unittest.TestCase):
    def fixture(self, base, fragment=False, false_labels=False, active_console=False):
        artifact = base / 'artifact'; guest = artifact / 'guest'; guest.mkdir(parents=True)
        payload = {'commit': '1' * 40, 'source': {'sha256': '2' * 64}, 'bins': {}}
        phases = [('stage-start', 'setup'), ('ready', None), ('network-down', None)]
        for label, _, _ in checker.STAGES:
            phases += [(phase, label) for phase in ('stage-start', 'stage-end', 'pack-start', 'pack-end')]
        phases += [('guest-exit', None)]
        events = []
        for index, (phase, stage) in enumerate(phases):
            row = {'phase': phase, 'utc_ns': (index + 1) * 10**9, 'monotonic_ns': (index + 1) * 10**9,
                'boot_id': '11111111-2222-3333-4444-555555555555', 'reference_qualified': False}
            if stage is not None: row['stage'] = stage
            if phase in ('ready', 'network-down', 'stage-start') and stage != 'setup':
                row.update(commit=payload['commit'], source_sha256=payload['source']['sha256'], binary_sha256={})
            if phase == 'stage-end': row['status'] = 'COLLECTED'
            if phase == 'pack-end': row['status'] = 'PACKED'
            events.append(row)
        checker.write_json(artifact / 'vm-result.json', {'status': 'COLLECTED', 'events': events,
            'post_ready_observation_errors': 0})
        (artifact / 'serial.txt').write_text(''.join(PREFIX + base64.b64encode(json.dumps(row).encode()).decode() + '\n'
            for row in events), encoding='utf-8')
        received = [{'guest': row, 'received_utc_ns': (10 + index * 5) * 10**9,
            'received_monotonic_ns': (10 + index * 5) * 10**9} for index, row in enumerate(events)]
        (artifact / 'received-events.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in received), encoding='utf-8')
        checker.write_json(artifact / 'configuration.json', {'qemu_run_as_uid': 1001})
        host = {'utc_ns': 1, 'monotonic_ns': 1, 'ready': True, 'required_interval': True,
            'observer_wall_ns': 1, 'observer_cpu_ns': 1, 'kvm': {'return': {'enabled': True}},
            'memory': {'return': {'base-memory': 8 * 1024**3}}, 'hotplug_memory': {'return': []},
            'run_status': {'return': {'status': 'running'}},
            'vcpu_threads': [{'affinity': [0, 1, 2, 3]}] * 4,
            'environment': {'effective_cpu_capacity': 4, 'process_affinity_cpu_count': 4},
            'process_status': {'Uid': '1001 1001 1001 1001', 'VmSwap': '0 kB', 'VmRSS': '8388608 kB'}}
        host_times = [50, 51] if fragment else list(range(18, 84, 5))
        hosts = [dict(copy.deepcopy(host), utc_ns=value * 10**9, monotonic_ns=value * 10**9,
                      required_interval=not false_labels) for value in host_times]
        (artifact / 'host-samples.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in hosts), encoding='utf-8')
        network = {'interfaces': [{'name': 'ens3', 'carrier': '0', 'operstate': 'down'}],
            'ipv4_routes': 'original route fixture', 'ipv6_routes': ''}
        sample = {'boot_id': events[0]['boot_id'], 'clock_properties': {'monotonic': True, 'adjustable': False},
            'environment': {'effective_cpu_capacity': 4, 'process_affinity_cpu_count': 4, 'physical_memory_bytes': 8 * 1024**3},
            'observer_wall_ns': 1, 'observer_cpu_ns': 1, 'network': network,
            'cpu_stat': 'cpu 0 0 0 0 0 0 0 0 0', 'vmstat': {'status': 'MEASURED', 'values': {'pswpin': 0, 'pswpout': 0}}}
        guests = [dict(copy.deepcopy(sample), monotonic_ns=value, utc_ns=value) for value in range(3_500_000_000, 16_000_000_000, 2_000_000_000)]
        (guest / 'guest-samples.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in guests), encoding='utf-8')
        campaigns = []
        for label, profile, seconds in checker.STAGES:
            campaigns.append({'stage': label, 'profile': profile, 'declared_timeout_seconds': seconds,
                'status': 'COLLECTED', 'package_status': 'PACKED', 'host_transfer': {'status': 'HOST ACKNOWLEDGED'},
                'export_failed': False})
            for position in ('before', 'after'): checker.write_json(guest / ('network-' + label + '-' + position + '.json'), network)
        checker.write_json(guest / 'campaigns.json', campaigns)
        checker.write_json(guest / 'guest-result.json', {'status': 'COLLECTED', 'campaigns': campaigns, 'cleanup': {'status': 'PASS'}})
        helpers = artifact / 'guest-helper-commands/gnu-time'; helpers.mkdir(parents=True)
        (helpers / 'stderr.txt').write_bytes(b'RILLTIME 0.0 0.0 123\n')
        console = artifact / 'guest-helper-commands/serial-getty-state'; console.mkdir()
        (console / 'stdout.txt').write_bytes(b'LoadState=loaded\nActiveState=active\n' if active_console
                                            else b'LoadState=masked\nActiveState=inactive\n')
        checker.write_json(artifact / 'host-link-down.json', {'response': {'return': {}},
            'requested': {'monotonic_ns': 15_100_000_000}, 'finished_monotonic_ns': 15_200_000_000})
        return artifact, payload, guest

    def exercise(self, fragment=False, false_labels=False, active_console=False):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='kh-', dir=ROOT / '.local-runs') as temporary:
            artifact, payload, guest = self.fixture(Path(temporary), fragment, false_labels, active_console)
            with patch.object(checker, 'passing_receipt'):
                return checker.continuity(artifact, payload, guest)

    def test_complete_synthetic_host_coverage_passes_contract_only(self):
        self.assertEqual(self.exercise()['status'], 'PASS')

    def test_healthy_middle_fragment_cannot_claim_full_host_coverage(self):
        with self.assertRaises(ValueError): self.exercise(fragment=True)

    def test_sample_interval_labels_must_match_received_lifecycle(self):
        # False labels must be rejected explicitly, independently of row count.
        with self.assertRaisesRegex(ValueError, 'label'): self.exercise(false_labels=True)

    def test_an_active_guest_console_owner_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'console policy'): self.exercise(active_console=True)


if __name__ == '__main__': unittest.main()
