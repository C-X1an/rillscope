"""Independent-review counterexamples; metadata fixtures are not measurements."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evidence_coverage import coverage, required_sources, wording_hashes


class Review427(unittest.TestCase):
    def test_successful_parent_stops_detached_output_worker_before_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'synthetic-input'
            source.write_text('stable synthetic input')
            ready = root / 'ready'
            worker = ('import time; from pathlib import Path; Path(' + repr(str(ready))
                      + ').write_text("ready"); time.sleep(1.5); Path(' + repr(str(source))
                      + ').write_text("worker survived the evidence boundary")')
            parent = ('import subprocess,sys,time; from pathlib import Path; '
                      'subprocess.Popen([sys.executable,"-c",' + repr(worker)
                      + '],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); '
                      'deadline=time.monotonic()+5\n'
                      'while not Path(' + repr(str(ready)) + ').exists() and time.monotonic()<deadline: time.sleep(.01)\n'
                      'assert Path(' + repr(str(ready)) + ').exists(); print("owned worker started")')
            out = root / 'receipt'
            run = subprocess.run([sys.executable, str(ROOT / 'scripts/evidence.py'), '--out', str(out),
                                  '--input', str(source), '--timeout', '10', '--', sys.executable, '-c', parent],
                                 capture_output=True, cwd=ROOT, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            receipt = json.loads((out / 'receipt.json').read_bytes())
            self.assertEqual(receipt['verification_status'], 'PASS')
            time.sleep(2)
            self.assertEqual(source.read_text(), 'stable synthetic input', 'owned worker survived a PASS receipt')
            self.assertEqual(receipt['process_cleanup']['status'], 'PASS')

    def test_report_criterion_binds_renderer_adapter_and_actual_tests(self):
        self.assertLessEqual({'scripts/demo.py', 'tools/fixed_scope.py',
                              'tests/acceptance_locked/test_demo.py',
                              'tests/acceptance_locked/product_helpers.py'}, required_sources('AC-029', ROOT))

    def test_public_html_claim_change_invalidates_wording_review(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / 'README.md').write_text('Experimental unit fixture.\n')
            report = root / 'docs/demo/report.html'
            report.parent.mkdir(parents=True)
            report.write_text('<p>Experimental unit fixture.</p>')
            item = {'review_kind':'independent-public-wording', 'review_status':'PASS',
                    'unsupported_maturity_claims':[], 'inspection_only':True,
                    'reviewed_wording_sha256':wording_hashes(root)}
            data = {'source_files':[], 'observations':[item]}
            self.assertIn('PUBLIC-WORDING', coverage(data, root))
            report.write_text('<p>Production ready; latency guaranteed without measurements.</p>')
            self.assertNotIn('PUBLIC-WORDING', coverage(data, root))

    def test_legacy_grid_metadata_cannot_qualify_current_release(self):
        observation = {'status':'PASS', 'profile':'full', 'observations_checked':43050,
                       'cases_checked':410, 'current_product_source_matches_capture':True,
                       'required_success_cases_checked':290, 'independent_semantic_comparisons':17400,
                       'evidence_schema_version':1, 'build_provenance_status':'NOT RECORDED',
                       'current_release_evidence_qualified':False}
        self.assertNotIn('FULL-GRID-VALIDATION', coverage({'source_files':[], 'observations':[observation]}))


if __name__ == '__main__':
    unittest.main()
