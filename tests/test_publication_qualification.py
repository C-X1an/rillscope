"""Metadata rejection checks, not fabricated execution or independent review."""
import hashlib
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from evidence_coverage import applied_publication_clarification, coverage
from evidence_coverage import required_sources
import release_audit


class PublicationQualification(unittest.TestCase):
    def test_current_boundary_receipt_cannot_freshen_stale_ordinary_caps(self):
        # Synthetic audit/coverage-interface fixtures, not executed product runs.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root/'spec').mkdir(); (root/'src').mkdir()
            public = Path(__file__).resolve().parents[1]
            (root/'spec/acceptance.json').write_bytes((public/'spec/acceptance.json').read_bytes())
            (root/'src/example.rs').write_text('current unit source\n')
            fixture_sources = required_sources('AC-018',root) | {
                'scripts/evidence.py','scripts/verify_ci_observations.py'}
            for name in fixture_sources:
                path = root/name; path.parent.mkdir(parents=True,exist_ok=True)
                if not path.exists(): path.write_text('current unit fixture\n')
            current = [[name,hashlib.sha256((root/name).read_bytes()).hexdigest()]
                       for name in sorted(fixture_sources)]
            base = {'status':'PASS','exit_code':0,'source_before_sha256':'a'*64,'source_after_sha256':'a'*64,
                    'raw_stdout_sha256':'b'*64,'raw_stderr_sha256':'c'*64,'source_files':current}
            caps = dict(base,unit_subjects=['AC-018','OUTPUT-CAPS'])
            final = dict(base,unit_subjects=['AC-018','FINAL-CANCELLATION'])
            identifiers = [row['id'] for row in json.loads((root/'spec/acceptance.json').read_bytes())['criteria']]
            index = {'criteria':{identifier:{'status':'NOT RUN','runs':[],'scope':'unit metadata only'} for identifier in identifiers},
                     'artifacts':{}}
            index['criteria']['AC-018'] = {'status':'PASS','runs':['caps','final'],'scope':'unit metadata only'}
            table = []
            for identifier,row in index['criteria'].items():
                links = ', '.join('['+name+'](verification/'+name+'.json)' for name in row['runs']) or row['scope']
                table.append('| C-'+identifier[3:]+': fixture | unit | fixture | '+links+' | '+row['status']+' |')
            (root/'CLAIMS_EVIDENCE.md').write_text('\n'.join(table)+'\n')
            def check(caps_record,final_record):
                for name,data in (('caps',caps_record),('final',final_record)):
                    path = root/'verification'/(name+'.json'); path.write_text(json.dumps(data))
                    index['artifacts'][name] = {'path':path.relative_to(root).as_posix(),
                                               'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
                with patch.object(release_audit,'ROOT',root),patch.object(release_audit,'coverage',
                        lambda data,unused:set(data['unit_subjects'])):
                    return release_audit.audit(index)
            self.assertEqual(check(caps,final)['stale_required_sources'],[])
            stale_caps = copy.deepcopy(caps)
            next(row for row in stale_caps['source_files'] if row[0] == 'tests/acceptance_locked/test_product.py')[1] = '0'*64
            expected = 'AC-018: no single current OUTPUT-CAPS run matches its complete dependency set'
            self.assertIn(expected,check(stale_caps,final)['stale_required_sources'])
            self.assertEqual(check(caps,final)['stale_required_sources'],[])
            # These helpers establish the executable binding of the ordinary
            # cap observations; a current final-boundary run cannot refresh them.
            for helper in ('scripts/product_build.py','benchmarks/build.py','scripts/evidence.py'):
                with self.subTest(stale_ordinary_executable_helper=helper):
                    stale_caps = copy.deepcopy(caps)
                    next(row for row in stale_caps['source_files'] if row[0] == helper)[1] = '0'*64
                    self.assertIn(expected,check(stale_caps,final)['stale_required_sources'])
                    self.assertEqual(check(caps,final)['stale_required_sources'],[])
            for helper in ('scripts/verify_publication_evidence.py','scripts/evidence.py',
                           'scripts/verify_ci_observations.py'):
                with self.subTest(stale_final_validation_helper=helper):
                    stale_final = copy.deepcopy(final)
                    next(row for row in stale_final['source_files'] if row[0] == helper)[1] = '0'*64
                    self.assertIn('AC-018: no single current FINAL-CANCELLATION run matches its complete dependency set',
                                  check(caps,stale_final)['stale_required_sources'])
                    self.assertEqual(check(caps,final)['stale_required_sources'],[])

    def test_ordinary_cancel_and_caps_do_not_supply_final_boundary(self):
        value = {'python_test_names':['test_ac018_actual_cli_cancel_before_publication','test_ac018_actual_cli_row_and_byte_caps'],
                 'source_files':[[name,'0'*64] for name in ('src/main.rs','tests/acceptance_locked/product_helpers.py',
                                                         'tests/acceptance_locked/test_product.py')]}
        with tempfile.TemporaryDirectory() as directory:
            found = coverage(value,Path(directory))
        self.assertIn('OUTPUT-CAPS',found)
        self.assertNotIn('FINAL-CANCELLATION',found)

    def test_draft_missing_and_changed_clarification_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'spec').mkdir(); (root/'verification').mkdir()
            doc = root/'TEST_SPEC_EXCEPTION_AC-018.md'; doc.write_bytes(b'test metadata fixture\n')
            lock = root/'verification/spec-lock.json'; lock.write_bytes(b'{}\n')
            observed = {'remote_repository':'C-X1an/rillscope','remote_commit':'a'*40,'remote_run_id':1,
                        'remote_job_id':2,'remote_artifact_id':3,'remote_artifact_sha256':'b'*64,
                        'instruction_disassembly_sha256':{'case':'c'*64}}
            self.assertFalse(applied_publication_clarification(observed,root))
            record = {**observed,'criterion':'AC-018','status':'DRAFT',
                      'decision':'final-success-path-atomic-cancellation-decision',
                      'clarification_path':doc.name,'clarification_sha256':hashlib.sha256(doc.read_bytes()).hexdigest(),
                      'contract_lock_sha256':hashlib.sha256(lock.read_bytes()).hexdigest(),
                      'independent_assessment':{'status':'RECOMMENDED','independent_runtime_execution':False,
                                               'instruction_disassembly_sha256':observed['instruction_disassembly_sha256']}}
            destination = root/'spec/ac018-clarification.json'
            destination.write_text(json.dumps(record))
            self.assertFalse(applied_publication_clarification(observed,root))
            record['status'] = 'APPLIED'; destination.write_text(json.dumps(record))
            self.assertTrue(applied_publication_clarification(observed,root))
            doc.write_bytes(b'changed assertion\n')
            self.assertFalse(applied_publication_clarification(observed,root))

    def test_independent_instruction_and_artifact_association_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'spec').mkdir(); (root/'verification').mkdir()
            doc = root/'TEST_SPEC_EXCEPTION_AC-018.md'; doc.write_bytes(b'test fixture\n')
            lock = root/'verification/spec-lock.json'; lock.write_bytes(b'{}\n')
            observed = {'remote_repository':'C-X1an/rillscope','remote_commit':'a'*40,'remote_run_id':1,
                        'remote_job_id':2,'remote_artifact_id':3,'remote_artifact_sha256':'b'*64,
                        'instruction_disassembly_sha256':{'case':'c'*64}}
            record = {**observed,'criterion':'AC-018','status':'APPLIED',
                      'decision':'final-success-path-atomic-cancellation-decision','clarification_path':doc.name,
                      'clarification_sha256':hashlib.sha256(doc.read_bytes()).hexdigest(),
                      'contract_lock_sha256':hashlib.sha256(lock.read_bytes()).hexdigest(),
                      'independent_assessment':{'status':'RECOMMENDED','independent_runtime_execution':False,
                                               'instruction_disassembly_sha256':{'case':'d'*64}}}
            (root/'spec/ac018-clarification.json').write_text(json.dumps(record))
            self.assertFalse(applied_publication_clarification(observed,root))
            record['independent_assessment']['instruction_disassembly_sha256'] = observed['instruction_disassembly_sha256']
            record['remote_job_id'] = 99
            (root/'spec/ac018-clarification.json').write_text(json.dumps(record))
            self.assertFalse(applied_publication_clarification(observed,root))
