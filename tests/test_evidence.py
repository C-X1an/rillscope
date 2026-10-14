import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result

class EvidenceTests(unittest.TestCase):
    def run_receipt(self, command, timeout=10):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'receipt'
            completed = subprocess.run([sys.executable, str(ROOT / 'scripts/evidence.py'),
                                        '--out', str(out), '--timeout', str(timeout), '--', *command],
                                       cwd=ROOT, capture_output=True, timeout=20)
            receipt = json.loads((out / 'receipt.json').read_text())
            self.assertTrue(module('evidence').verify_receipt(out / 'receipt.json'))
            self.assertEqual(receipt['exit_code'], completed.returncode)
            self.assertEqual(receipt['source_before']['sha256'], receipt['source_after_sha256'])
            self.assertTrue(receipt['source_before']['files'])
            return receipt

    def test_real_success_receipt(self):
        receipt = self.run_receipt([sys.executable, '-c', 'print("synthetic success")'])
        self.assertEqual(receipt['verification_status'], 'PASS')
        self.assertEqual(receipt['exit_code'], 0)

    def test_real_failure_receipt(self):
        receipt = self.run_receipt([sys.executable, '-c', 'raise SystemExit(9)'])
        self.assertEqual(receipt['verification_status'], 'FAIL')
        self.assertEqual(receipt['exit_code'], 9)

    def test_real_timeout_receipt(self):
        receipt = self.run_receipt([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=0.2)
        self.assertEqual(receipt['verification_status'], 'FAIL')
        self.assertEqual(receipt['execution_outcome'], 'TIMEOUT')
        self.assertEqual(receipt['exit_code'], 124)

    def test_missing_executable_receipt(self):
        receipt = self.run_receipt(['rillscope-synthetic-nonexistent-executable-8c4f'])
        self.assertEqual(receipt['verification_status'], 'BLOCKED')
        self.assertEqual(receipt['exit_code'], 77)

    def test_output_tampering(self):
        evidence = module('evidence')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ['stdout.txt', 'stderr.txt']: (root / name).write_bytes(b'actual output\n')
            receipt = {key: {'file': key + '.txt', 'sha256': evidence.digest(b'actual output\n')} for key in ['stdout', 'stderr']}
            path = root / 'receipt.json'; path.write_text(json.dumps(receipt))
            self.assertTrue(evidence.verify_receipt(path))
            (root / 'stdout.txt').write_bytes(b'edited to PASS')
            self.assertFalse(evidence.verify_receipt(path))

    def test_html_escape(self):
        demo = module('demo_reference')
        text = demo.render([('<script>alert(1)</script>', {'rows': [['<img src=x onerror=alert(1)>']], 'implementation': 'python-reference'})])
        self.assertNotIn('<script>', text); self.assertNotIn('<img ', text)
        self.assertIn('&lt;script&gt;', text); self.assertIn('default-src', text)

if __name__ == '__main__': unittest.main()
