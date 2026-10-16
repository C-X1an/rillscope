#!/usr/bin/env python3
"""Actual final-cancellation behavioral PASS-FAIL-PASS in an owned clone."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out',type=Path,required=True); args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or shutil.which('gdb') is None:
        print(json.dumps({'status':'BLOCKED','reason':'actual Linux x86_64 and permitted existing GDB required'})); return 77
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / '.local-runs'):
        raise ValueError('new owned control output required')
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT).strip():
        raise ValueError('commit the public candidate before cloning its behavioral control')
    commit = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    out.mkdir(parents=True); clone = out / 'checkout'
    subprocess.run(['git','clone','--no-local','--config','core.autocrlf=false',str(ROOT),str(clone)],check=True,capture_output=True)
    if not clone.resolve().is_relative_to(out): raise ValueError('control clone escaped owned output')
    source = clone / 'src/main.rs'; original = source.read_bytes()
    anchor = 'if flag.load(Ordering::Acquire) {\n                        Err(E::Cancelled.into())'
    text = original.decode()
    if text.count(anchor) != 1: raise ValueError('final conversion mutation must identify exactly one operation')
    mutant = text.replace(anchor,anchor.replace('Err(E::Cancelled.into())','Ok(bytes)')).encode()
    (out / 'source.before.rs').write_bytes(original); (out / 'source.mutant.rs').write_bytes(mutant)
    env = os.environ.copy(); env['CARGO_TARGET_DIR'] = 'target'
    rows = []
    def execute(label,command):
        destination = out / 'commands' / label
        completed = subprocess.run([sys.executable,'scripts/evidence.py','--out',str(destination),'--timeout','600',
                                    '--',*command],cwd=clone,env=env,capture_output=True,timeout=620)
        receipt = json.loads((destination / 'receipt.json').read_bytes())
        row = {'label':label,'exit_code':completed.returncode,'status':receipt['verification_status'],
               'source_sha256':receipt['source_before']['sha256'],
               'stdout_sha256':receipt['stdout']['sha256'],'stderr_sha256':receipt['stderr']['sha256']}
        rows.append(row); return row
    def experiment(label):
        build = execute(label+'-build',[sys.executable,'scripts/product_build.py'])
        if build['status'] != 'PASS': raise RuntimeError('actual control build failed: '+label)
        return execute(label,[sys.executable,'tests/system/publication_decision.py',
                              '--out','.local-runs/'+label,'--before-sigint-only'])
    try:
        baseline = experiment('baseline')
        if baseline['status'] != 'PASS': raise RuntimeError('actual baseline did not pass before mutation')
        source.write_bytes(mutant)
        broken = experiment('mutant')
        case = clone / '.local-runs/mutant/before-commit-sigint'
        observed = json.loads((case / 'debugger-observation.json').read_bytes())
        payload = (case / 'stdout.bin').read_bytes(); response = json.loads(payload)
        diagnostics = (out / 'commands/mutant/stderr.txt').read_text()
        detected = (broken['status'] == 'FAIL' and broken['exit_code'] != 0
                    and 'actual terminal exit differs: expected 4, observed 0' in diagnostics
                    and observed['inferior_exit_code'] == 0 and observed['handler_return_syscall_observed'] is True
                    and observed['stdout_bytes_at_decision_stop'] == observed['stdout_bytes_at_handler_return'] == 0
                    and response.get('status') == 'ok' and response.get('rows') == [[7]]
                    and payload.count(b'\n') == 1 and payload.endswith(b'\n') and not (case / 'stderr.bin').read_bytes())
        source.write_bytes(original)
        restored = experiment('restored')
        healthy = restored['status'] == 'PASS' and source.read_bytes() == original
        summary = {'status':'PASS' if detected and healthy else 'FAIL',
                   'campaign':'actual-final-cancellation-behavioral-control','source_commit':commit,
                   'sequence':[baseline['status'],broken['status'],restored['status']],
                   'source_original_sha256':hashlib.sha256(original).hexdigest(),
                   'source_mutant_sha256':hashlib.sha256(mutant).hexdigest(),
                   'source_restored_sha256':sha(source),'original_repository_source_unchanged':(ROOT / 'src/main.rs').read_bytes() == original,
                   'mutant_returned_authorized_success_after_handled_predecision_signal':detected,
                   'commands':rows,
                   'scope':'actual source mutation in an isolated clone; final conversion bypassed while source anchors remain; no AC-018 interpretation approval'}
        (out / 'summary.json').write_text(json.dumps(summary,indent=2)+'\n'); print(json.dumps(summary,indent=2))
        return 0 if summary['status'] == 'PASS' and summary['original_repository_source_unchanged'] else 1
    finally:
        source.write_bytes(original)


if __name__ == '__main__': raise SystemExit(main())
