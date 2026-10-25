"""Independent literal stream expectations; no privileged subprocess or VM execution."""
import ast
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_boot as boot


class MarkerChildObservation(unittest.TestCase):
    def scope(self, run):
        source = ast.parse((ROOT / 'tests/system/canonical_handoff_permissions.py').read_text(encoding='utf-8'))
        selected = [node for node in source.body if isinstance(node, ast.FunctionDef)
            and node.name in {'emit_marker_child_observation', 'run_marker_child'}]
        self.assertEqual(len(selected), 2)
        program = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
        scope = {'base64': base64, 'hashlib': hashlib, 'json': json, 'boot': boot,
            'subprocess': SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired)}
        exec(compile(program, '<actual marker child observation functions>', 'exec'), scope)
        return scope

    def observe(self, run):
        scope = self.scope(run); captured = io.StringIO(); error = None; result = None
        command = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
            '/usr/bin/python3', '-I', '-c', 'SYNTHETIC CONTROL; NEVER EXECUTED', '/synthetic/marker']
        with contextlib.redirect_stdout(captured):
            try: result = scope['run_marker_child'](command)
            except subprocess.TimeoutExpired as caught: error = caught
        rows = [json.loads(line) for line in captured.getvalue().splitlines()]
        self.assertEqual(len(rows), 1)
        row = rows[0]['canonical_marker_child_observation']
        self.assertEqual(row['command'], command)
        self.assertEqual(row['timeout_seconds'], 10)
        self.assertEqual(row['bootstrap_sha256'], hashlib.sha256(boot.BOOTSTRAP.encode()).hexdigest())
        self.assertIn('not yet validated', row['scope'])
        return result, error, row

    def check_stream(self, row, name, expected):
        self.assertEqual(base64.b64decode(row[name]['base64'], validate=True), expected)
        self.assertEqual(row[name]['sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(row[name]['bytes'], len(expected))
        self.assertEqual(row[name]['text_utf8_backslashreplace'], expected.decode('utf-8', errors='backslashreplace'))

    def test_nonzero_and_non_utf8_original_bytes_are_retained_before_the_gate_can_fail(self):
        stdout = b'MARKER CHILD STDOUT\n\xff\x00'; stderr = b'MARKER CHILD STDERR\n\xfe'
        def run(command, **options):
            self.assertEqual(options, {'cwd': '/', 'capture_output': True, 'timeout': 10, 'check': False})
            return subprocess.CompletedProcess(command, 17, stdout, stderr)
        result, error, row = self.observe(run)
        self.assertIsNone(error); self.assertEqual(result.returncode, 17)
        self.assertEqual(row['outcome'], 'EXECUTED'); self.assertEqual(row['returncode'], 17)
        self.check_stream(row, 'stdout', stdout); self.check_stream(row, 'stderr', stderr)

    def test_timeout_preserves_partial_bytes_and_reraises_the_same_timeout(self):
        stdout = b'PARTIAL STDOUT\n\xff'; stderr = b'PARTIAL STDERR\n\xfe'
        failure = subprocess.TimeoutExpired(['synthetic-only'], 10, output=stdout, stderr=stderr)
        def run(*args, **kwargs): raise failure
        result, error, row = self.observe(run)
        self.assertIsNone(result); self.assertIs(error, failure)
        self.assertEqual(row['outcome'], 'TIMEOUT'); self.assertIsNone(row['returncode'])
        self.check_stream(row, 'stdout', stdout); self.check_stream(row, 'stderr', stderr)

    def test_timeout_without_partial_streams_truthfully_retains_empty_bytes(self):
        failure = subprocess.TimeoutExpired(['synthetic-only'], 10)
        def run(*args, **kwargs): raise failure
        result, error, row = self.observe(run)
        self.assertIsNone(result); self.assertIs(error, failure)
        self.assertEqual(row['outcome'], 'TIMEOUT'); self.assertIsNone(row['returncode'])
        self.check_stream(row, 'stdout', b''); self.check_stream(row, 'stderr', b'')

    def test_success_is_an_observation_before_identity_and_permissions_validation(self):
        def run(command, **options): return subprocess.CompletedProcess(command, 0, b'{"synthetic":true}\n', b'')
        result, error, row = self.observe(run)
        self.assertIsNone(error); self.assertEqual(result.returncode, 0)
        self.assertEqual(row['outcome'], 'EXECUTED'); self.assertEqual(row['returncode'], 0)
        self.check_stream(row, 'stdout', b'{"synthetic":true}\n'); self.check_stream(row, 'stderr', b'')


if __name__ == '__main__': unittest.main()
