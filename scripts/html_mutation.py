#!/usr/bin/env python3
"""Actual Rust-backed HTML escape PASS-FAIL-PASS control in a fresh committed clone."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from mutation import run

ROOT = Path(__file__).resolve().parents[1]
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists(): parser.error('control evidence directory must be new')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip():
        raise RuntimeError('commit the audited public source before the control')
    args.out.mkdir(parents=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory(prefix='rillscope-html-control-') as folder:
        clone = Path(folder) / 'repo'
        subprocess.run(['git', 'clone', '--no-local', '--config', 'core.autocrlf=false', str(ROOT), str(clone)], capture_output=True, check=True)
        if not clone.resolve().is_relative_to(Path(folder).resolve()): raise RuntimeError('clone boundary failure')
        env = os.environ.copy(); env['CARGO_TARGET_DIR'] = str(clone / 'target')
        built, build_receipt = run(['cargo', 'build', '--locked', '--bin', 'rillscope'], clone, args.out / 'build', env)
        if built.returncode: raise RuntimeError('fresh actual Rust binary did not build')
        command = [sys.executable, 'tests/acceptance_locked/test_demo.py', '-v', 'RustDemo.test_actual_text_output_and_supplied_labels_are_escaped_offline']
        path = clone / 'scripts/demo.py'; original = path.read_bytes(); text = original.decode()
        anchor = 'html.escape(label)'
        if text.count(anchor) != 1: raise RuntimeError('escape mutation anchor is not unique')
        baseline, before = run(command, clone, args.out / 'baseline', env)
        if baseline.returncode or b'Ran 1 test' not in baseline.stdout + baseline.stderr:
            raise RuntimeError('selected actual baseline did not run and pass')
        path.write_text(text.replace(anchor, 'label'), encoding='utf-8', newline='\n')
        mutant_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        mutant, broken = run(command, clone, args.out / 'mutant', env)
        path.write_bytes(original)
        restored, after = run(command, clone, args.out / 'restored', env)
        detected = mutant.returncode != 0 and b'Ran 1 test' in mutant.stdout + mutant.stderr and b'AssertionError' in mutant.stdout + mutant.stderr
        healthy = restored.returncode == 0 and path.read_bytes() == original
        summary = {'control': 'offline_html_escape', 'source_commit': commit, 'path': 'scripts/demo.py',
                   'original_sha256': hashlib.sha256(original).hexdigest(), 'mutant_sha256': mutant_sha,
                   'restored_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'build': build_receipt,
                   'baseline': before, 'mutant': broken, 'restored': after,
                   'status': 'PASS' if detected and healthy else 'FAIL', 'actual_rust_result_tested': True}
        (args.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps({'control': summary['control'], 'sequence': [baseline.returncode, mutant.returncode, restored.returncode], 'status': summary['status']}))
        return int(summary['status'] != 'PASS')

if __name__ == '__main__': raise SystemExit(main())
