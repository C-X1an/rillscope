#!/usr/bin/env python3
"""Real disposable-copy PASS-FAIL-PASS controls for the Python reference only."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = [
    ('tenant_bypass', 'if raw[tenant_idx] == self.context["tenant"]:', 'if True:', 'test_tenant'),
    ('null_equality', 'if a is None or b is None:\n            return None', 'if a is None or b is None:\n            return a is b', 'test_null_filter'),
    ('join_deduplication', 'self.bounded_append(rows, a + b)', 'if a + b not in rows:\n                            self.bounded_append(rows, a + b)', 'test_identical_duplicate_join')]
results = []
for name, old, new, test in MUTATIONS:
    with tempfile.TemporaryDirectory(prefix='rillscope-mutation-') as directory:
        root = Path(directory)
        for sub in ('tools', 'tests'):
            shutil.copytree(ROOT / sub, root / sub, ignore=shutil.ignore_patterns('__pycache__'))
        source = root / 'tools/reference/engine.py'
        original = source.read_text()
        if original.count(old) != 1: raise SystemExit(f'mutation {name} target must occur exactly once')
        command = [sys.executable, '-B', '-m', 'unittest', 'tests.test_reference.ReferenceTests.' + test]
        outcomes = []
        for stage in ('baseline', 'mutated', 'restored'):
            source.write_text(original.replace(old, new) if stage == 'mutated' else original)
            process = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
            outcomes.append({'stage': stage, 'exit_code': process.returncode, 'stdout': process.stdout, 'stderr': process.stderr})
        valid = outcomes[0]['exit_code'] == 0 and outcomes[1]['exit_code'] == 1 and 'AssertionError' in outcomes[1]['stderr'] and outcomes[2]['exit_code'] == 0 and source.read_text() == original
        results.append({'mutation': name, 'test': test, 'implementation': 'python-reference',
                        'original_sha256': hashlib.sha256(original.encode()).hexdigest(),
                        'old': old, 'new': new, 'runs': outcomes, 'detected_and_restored': valid})
print(json.dumps({'mutations': results, 'all_detected': all(r['detected_and_restored'] for r in results)}, indent=2))
raise SystemExit(0 if all(r['detected_and_restored'] for r in results) else 1)
