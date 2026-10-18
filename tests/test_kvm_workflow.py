"""Published setup ownership and actual missing-owner validation dispatch controls."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/kvm-feasibility-pilot.yml'


class PilotWorkflow(unittest.TestCase):
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
