"""Independent 72f review regressions; metadata fixtures are not product runs."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / 'scripts'))
import release_audit
import verify_demo_evidence
from evidence_coverage import required_sources


class Review72(unittest.TestCase):
    def test_demo_receipt_binds_report_path_hash_and_unique_generator(self):
        # Unit stdout metadata only, never an executed demo or browser record.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); demo = root / '.local-runs/demo-unit'; demo.mkdir(parents=True)
            report = demo / 'report.html'; report.write_bytes(b'unit rendered bytes')
            results = demo / 'results.json'; results.write_bytes(b'unit results bytes')
            manifest = demo / 'manifest.json'; manifest.write_bytes(b'unit manifest bytes')
            stdout = root / 'stdout.txt'; receipt_path = root / 'receipt.json'
            receipt = {'cwd':str(root),'stdout':{'file':'stdout.txt'}}
            observed = {'implementation':'rust','cases':3,'oracle_match':True,
                        'report':'.local-runs/demo-unit/report.html','report_sha256':hashlib.sha256(report.read_bytes()).hexdigest(),
                        'results_sha256':hashlib.sha256(results.read_bytes()).hexdigest(),
                        'manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest()}
            def bind(value):
                stdout.write_text(json.dumps(value)+'\n')
                return verify_demo_evidence.bind_generator_observation(receipt_path,receipt,root,demo)
            self.assertEqual(bind(observed),observed)
            for change in ({'report_sha256':'0'*64},{'results_sha256':'0'*64},{'manifest_sha256':'0'*64},
                           {'report':'.local-runs/another/report.html'},
                           {'oracle_match':False},{'cases':2}):
                with self.subTest(change=change),self.assertRaises(ValueError): bind(dict(observed,**change))
            stdout.write_text((json.dumps(observed)+'\n')*2)
            with self.assertRaises(ValueError): verify_demo_evidence.bind_generator_observation(receipt_path,receipt,root,demo)
            self.assertEqual(bind(observed),observed)
            receipt['cwd'] = str(root / 'different-checkout')
            with self.assertRaises(ValueError): bind(observed)

    def test_unrelated_current_receipt_cannot_freshen_old_checkout_verification(self):
        # Synthetic auditor metadata only. No fresh checkout or make invocation
        # is claimed by this fixture; its expected association is independent.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / 'spec').mkdir(); (root / 'spec/acceptance.json').write_bytes((ROOT / 'spec/acceptance.json').read_bytes())
            for name in ('src/example.rs','Makefile','Cargo.toml','Cargo.lock','ACCEPTANCE_SPEC.md',
                         'rust-toolchain.toml','deny.toml','verification/spec-lock.json','scripts/clean_verify.py'):
                path = root / name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text('current unit fixture\n')
            current = [[name,hashlib.sha256((root / name).read_bytes()).hexdigest()]
                       for name in sorted(required_sources('AC-024',root))]
            observation = {'mode':'fresh-committed-Rust-checkout','status':'PASS','source_stable':True,
                           'cargo_target_dir_enforced_inside_fresh_clone':True,
                           'commands':[{'target':target,'status':'PASS'} for target in ('bootstrap','verify','demo')]}
            base = {'status':'PASS','exit_code':0,'source_before_sha256':'a'*64,'source_after_sha256':'a'*64,
                    'raw_stdout_sha256':'b'*64,'raw_stderr_sha256':'c'*64,'source_files':current}
            fresh = dict(base,observations=[observation]); trivial = dict(base,observations=[])
            identifiers = [row['id'] for row in json.loads((root / 'spec/acceptance.json').read_bytes())['criteria']]
            index = {'criteria':{identifier:{'status':'NOT RUN','runs':[],'scope':'unit metadata only'} for identifier in identifiers},
                     'artifacts':{}}
            index['criteria']['AC-024'] = {'status':'PASS','runs':['fresh','trivial'],'scope':'unit metadata only'}
            table = []
            for identifier,row in index['criteria'].items():
                links = ', '.join('['+name+'](verification/'+name+'.json)' for name in row['runs']) or row['scope']
                table.append('| C-'+identifier[3:]+': fixture | unit | fixture | '+links+' | '+row['status']+' |')
            (root / 'CLAIMS_EVIDENCE.md').write_text('\n'.join(table)+'\n')
            def check(fresh_data, second_data=None):
                for name,data in (('fresh',fresh_data),('trivial',trivial if second_data is None else second_data)):
                    path = root / 'verification' / (name+'.json'); path.write_text(json.dumps(data))
                    index['artifacts'][name] = {'path':path.relative_to(root).as_posix(),
                                               'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
                with patch.object(release_audit,'ROOT',root): return release_audit.audit(index)
            self.assertEqual(check(fresh)['stale_required_sources'],[])
            old = copy.deepcopy(fresh)
            next(pair for pair in old['source_files'] if pair[0] == 'Makefile')[1] = '0'*64
            other = copy.deepcopy(fresh)
            next(pair for pair in other['source_files'] if pair[0] == 'scripts/clean_verify.py')[1] = '0'*64
            mixed = check(old,other)
            self.assertIn('AC-024: no single qualifying run matches the complete required source set',mixed['stale_required_sources'],
                          'two historical fresh runs supplied complementary current hashes')
            self.assertEqual(check(fresh,fresh)['stale_required_sources'],[])
            self.assertIn('AC-024: Makefile',check(old)['stale_required_sources'],
                          'unrelated current command supplied freshness for an old checkout run')
            self.assertEqual(check(fresh)['stale_required_sources'],[])


if __name__ == '__main__': unittest.main()
