"""Published setup ownership and actual missing-owner validation dispatch controls."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/kvm-feasibility-pilot.yml'


class PilotWorkflow(unittest.TestCase):
    def test_dispatch_requires_exact_audited_commit_before_checkout(self):
        source = WORKFLOW.read_text(encoding='utf-8')
        self.assertIn('expected_commit:', source)
        block = source.split('expected_commit:', 1)[1].split('permissions:', 1)[0]
        self.assertIn('required: true', block)
        self.assertIn('EXPECTED_COMMIT: ${{ inputs.expected_commit }}', source)
        line = next(line.strip() for line in source.splitlines() if 'run: python3 -c' in line)
        self.assertLess(source.index(line), source.index('uses: actions/checkout@'))
        arguments = shlex.split(line.removeprefix('run: ')); arguments[0] = sys.executable
        for expected, actual, code in [('a' * 40, 'a' * 40, 0), ('a' * 40, 'b' * 40, 1),
                                       ('', 'a' * 40, 1), ('A' * 40, 'A' * 40, 1)]:
            with self.subTest(expected=expected, actual=actual):
                env = dict(os.environ, EXPECTED_COMMIT=expected, GITHUB_SHA=actual)
                result = subprocess.run(arguments, env=env, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, code)

    def test_work_disk_serial_belongs_to_device_not_raw_backend(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        from kvm_benchmark_pilot import BOOTSTRAP, qemu_command
        command = qemu_command(Path('/owned'), Path('/owned/image.qcow2'), 'runner', 12345)
        drives = [command[index + 1] for index, value in enumerate(command) if value == '-drive']
        work = [value for value in drives if 'work.raw,' in value]
        self.assertEqual(len(work), 1)
        self.assertEqual(work[0].split(',')[1:], ['if=none', 'format=raw', 'id=rillwork-disk'])
        devices = [command[index + 1] for index, value in enumerate(command) if value == '-device']
        self.assertIn('virtio-blk-pci,drive=rillwork-disk,serial=rillwork', devices)
        self.assertIn('/dev/disk/by-id/virtio-rillwork', BOOTSTRAP)

    def test_runner_creates_parent_before_first_root_capture(self):
        source = WORKFLOW.read_text(encoding='utf-8')
        self.assertIn('mkdir -p .local-runs', source, 'runner must own the shared capture parent before sudo')
        self.assertLess(source.index('mkdir -p .local-runs'), source.index('sudo -n python3 scripts/evidence.py'))

    def test_missing_owner_still_launches_verifier_and_reports_every_campaign_failure(self):
        source = WORKFLOW.read_text(encoding='utf-8')
        line = next(line.strip() for line in source.splitlines() if 'run:' in line and 'scripts/verify_kvm_pilot.py' in line)
        command = shlex.split(line.removeprefix('run: '))
        self.assertEqual(command[:3], ['sudo', '-n', 'python3'])
        command = command[2:]; command[0] = sys.executable
        separator = command.index('--'); outer = command[:separator]; inner = command[separator + 1:]
        inner[0] = sys.executable
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='kw-', dir=ROOT / '.local-runs') as temporary:
            base = Path(temporary); owner = base / 'missing-owner/receipt.json'
            for arguments, flag, value in ((outer, '--out', base / 'command'), (outer, '--timeout', 20),
                    (inner, '--artifact', base / 'missing-artifact'), (inner, '--owner-receipt', owner),
                    (inner, '--out', base / 'verified')):
                arguments[arguments.index(flag) + 1] = str(value)
            if '--input' in outer: outer[outer.index('--input') + 1] = str(owner)
            result = subprocess.run([*outer, '--', *inner], cwd=ROOT, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 1, 'missing input must produce an executed verifier FAIL, not suppress it with BLOCKED77')
            receipt = json.loads((base / 'command/receipt.json').read_bytes())
            self.assertEqual(receipt['execution_outcome'], 'EXECUTED')
            self.assertEqual(receipt['verification_status'], 'FAIL')
            report = json.loads((base / 'verified/results.json').read_bytes())
            self.assertEqual(report['status'], 'FAIL')
            self.assertEqual([row['stage'] for row in report['campaigns']], ['instrument', 'tail', 'cancel'])
            self.assertEqual([row['status'] for row in report['campaigns']], ['FAIL'] * 3)
            self.assertFalse(report['reference_qualified'])


if __name__ == '__main__': unittest.main()
