#!/usr/bin/env python3
"""Reproduce report-binding corruption using genuine artifacts and virtual reads.

Original files are never changed. This validates a verifier; it executes no
query or browser review and cannot establish product correctness by itself.
"""
import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--checker-root',type=Path,default=ROOT,help='explicit historical checkout for before-fix reproduction')
    parser.add_argument('--mutation',choices=('report','results'),default='report')
    for name in ('fresh-checkout','demo-dir','demo-receipt','browser-record'):
        parser.add_argument('--'+name,type=Path,required=True)
    args = parser.parse_args(); checker = args.checker_root.resolve()
    sys.path[:0] = [str(checker / 'scripts'),str(checker / 'benchmarks')]
    import verify_demo_evidence
    fresh, demo, receipt, browser = (getattr(args,name).resolve() for name in
                                     ('fresh_checkout','demo_dir','demo_receipt','browser_record'))
    report, manifest = demo / 'report.html', demo / 'manifest.json'
    original_read = Path.read_bytes
    target = report if args.mutation == 'report' else demo / 'results.json'
    changed = target.read_bytes() + b'\n<!-- virtual post-capture corruption control -->\n'
    if args.mutation == 'results':
        cases = json.loads(target.read_bytes())
        next(row for row in cases['cases'] if row['id'] == 'allowed')['result']['implementation'] = 'python-reference'
        changed = json.dumps(cases).encode()
    changed_sha = hashlib.sha256(changed).hexdigest()
    metadata = json.loads(manifest.read_bytes()); metadata[args.mutation+'_sha256'] = changed_sha
    overlays = {target:changed,manifest:json.dumps(metadata).encode()}
    if args.mutation == 'report':
        manual = json.loads(browser.read_bytes()); manual['report_sha256'] = changed_sha
        overlays[browser] = json.dumps(manual).encode()
    argv = ['verify_demo_evidence','--fresh-checkout',str(fresh),'--demo-dir',str(demo),
            '--demo-receipt',str(receipt),'--browser-record',str(browser)]
    def invoke(mutant=False):
        def read(path): return overlays[path] if mutant and path in overlays else original_read(path)
        stream = io.StringIO()
        try:
            with patch.object(sys,'argv',argv),patch.object(Path,'read_bytes',read),contextlib.redirect_stdout(stream):
                verify_demo_evidence.main()
            return {'accepted':True,'observation':json.loads(stream.getvalue())}
        except ValueError as error:
            return {'accepted':False,'reason':str(error)}
    baseline, mutant, restored = invoke(),invoke(True),invoke()
    result = {'campaign':'actual-fresh-demo-validator-binding-control','original_files_mutated':False,
              'new_query_execution':False,'fresh_checkout_commit':baseline.get('observation',{}).get('fresh_checkout_commit'),
              'control':'post-capture-'+args.mutation+'-substitution',
              'original_report_sha256':sha(report),'mutated_artifact':target.name,'virtual_changed_artifact_sha256':changed_sha,
              'recorded_demo_receipt_sha256':sha(receipt),
              'checker_source_sha256':sha(checker / 'scripts/verify_demo_evidence.py'),
              'checker_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=checker,text=True).strip(),
              'baseline_accepted':baseline['accepted'],'mutant_accepted':mutant['accepted'],
              'restored_accepted':restored['accepted'],'mutant_reason':mutant.get('reason'),
              'scope':'genuine recorded artifacts with virtual report/manifest/manual-record mutation; no modified original evidence or invented execution'}
    result['status'] = 'PASS' if baseline['accepted'] and not mutant['accepted'] and restored['accepted'] else 'FAIL'
    print(json.dumps(result,indent=2)); return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
