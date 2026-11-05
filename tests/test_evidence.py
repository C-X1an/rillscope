import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
import time
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

    def test_nonexecutable_launch_retains_failed_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'not-executable'
            path.write_text('synthetic nonexecutable input')
            receipt = self.run_receipt([str(path)])
            self.assertEqual(receipt['verification_status'], 'FAIL')
            self.assertEqual(receipt['execution_outcome'], 'LAUNCH_FAILED')
            self.assertEqual(receipt['exit_code'], 126)

    def test_timeout_stops_owned_descendant_before_next_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'survived'
            worker = 'import time; from pathlib import Path; time.sleep(2); Path(' + repr(str(marker)) + ').write_text("survived")'
            parent = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",' + repr(worker) + ']); print("child-started",flush=True); time.sleep(20)'
            receipt = self.run_receipt([sys.executable, '-c', parent], timeout=1)
            self.assertEqual(receipt['execution_outcome'], 'TIMEOUT')
            time.sleep(2)
            self.assertFalse(marker.exists(), 'timed-out worker survived into a subsequent gate')
            self.assertEqual(receipt['process_cleanup']['status'], 'PASS')

    def test_timeout_stops_descendant_after_its_root_has_exited(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'survived-exited-root'
            worker = 'import time; from pathlib import Path; time.sleep(3); Path(' + repr(str(marker)) + ').write_text("survived")'
            parent = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c",' + repr(worker) + ']); print("root-exiting",flush=True)'
            receipt = self.run_receipt([sys.executable, '-c', parent], timeout=1)
            time.sleep(3)
            self.assertFalse(marker.exists(), 'worker survived its exited root and evidence timeout')
            self.assertEqual(receipt['execution_outcome'], 'TIMEOUT')
            self.assertEqual(receipt['process_cleanup']['status'], 'PASS')

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

    def test_external_stdin_and_file_inputs_have_actual_hashes(self):
        evidence = module('evidence')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            external = root / 'catalog.json'; external.write_bytes(b'synthetic operator bytes')
            digests = []
            for i, data in enumerate((b'a', b'b')):
                source = root / ('query-' + str(i) + '.sql'); source.write_bytes(data)
                out = root / ('run-' + str(i))
                command = [sys.executable, str(ROOT / 'scripts/evidence.py'), '--out', str(out),
                           '--input', str(external), '--stdin', str(source), '--', sys.executable,
                           '-c', 'import sys; print(len(sys.stdin.buffer.read()))', '--query', '-']
                result = subprocess.run(command, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0)
                receipt = json.loads((out / 'receipt.json').read_text())
                self.assertEqual(receipt['verification_status'], 'PASS')
                self.assertEqual(receipt['stdin']['sha256'], evidence.digest(data))
                self.assertEqual({row['sha256'] for row in receipt['inputs_before']}, {evidence.digest(data), evidence.digest(external.read_bytes())})
                self.assertEqual(receipt['inputs_before'], receipt['inputs_after'])
                digests.append(receipt['stdin']['sha256'])
            self.assertNotEqual(*digests)

    def test_external_input_mutation_prevents_verification_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / 'input.txt'; source.write_text('before')
            out = root / 'run'
            code = 'from pathlib import Path; import sys; Path(sys.argv[1]).write_text("after")'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/evidence.py'), '--out', str(out),
                                     '--input', str(source), '--', sys.executable, '-c', code, str(source)], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0)
            receipt = json.loads((out / 'receipt.json').read_text())
            self.assertEqual(receipt['execution_outcome'], 'INPUT_CHANGED')
            self.assertEqual(receipt['verification_status'], 'FAIL')
            self.assertNotEqual(receipt['inputs_before'], receipt['inputs_after'])

    def test_html_escape(self):
        demo = module('demo_reference')
        text = demo.render([('<script>alert(1)</script>', {'rows': [['<img src=x onerror=alert(1)>']], 'implementation': 'python-reference'})])
        self.assertNotIn('<script>', text); self.assertNotIn('<img ', text)
        self.assertIn('&lt;script&gt;', text); self.assertIn('default-src', text)

if __name__ == '__main__': unittest.main()
