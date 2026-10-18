"""Closed-plan, provenance and diagnostic-prerequisite metadata controls only."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import verify_sequence as sequence
from evidence_coverage import required_sources
from tests.test_clean_recipe import GATES,IDENTITY


class VerifySequence(unittest.TestCase):
    def test_reference_claims_bind_the_imported_retention_and_execution_helpers(self):
        root=Path(__file__).resolve().parents[1]
        for identifier in ('AC-021','AC-022','AC-023'):
            self.assertLessEqual({'scripts/archive_capture.py','scripts/verify_sequence.py'},required_sources(identifier,root))

    def fixture(self,root,rows):
        (root/'Makefile').write_text('VERIFY_GATES := '+' '.join(GATES)+'\n',encoding='utf-8')
        path=root/'.local-runs/verify-unit/ledger.json'; steps=[]
        for target,status in rows:
            directory=path.parent/'commands'/target; directory.mkdir(parents=True)
            for name in ('stdout.txt','stderr.txt'): (directory/name).write_bytes(b'unit metadata only\n')
            command=['make',target]+(['SHELL=sh'] if sequence.os.name=='nt' else [])
            data={'command':command,'exit_code':0 if status=='PASS' else 17,'verification_status':status,
                'execution_outcome':'EXECUTED','process_cleanup':{'status':'PASS'},
                'source_before':{'sha256':IDENTITY},'source_after_sha256':IDENTITY,
                **{key:{'file':key+'.txt','sha256':hashlib.sha256(b'unit metadata only\n').hexdigest()}
                   for key in ('stdout','stderr')}}
            receipt=directory/'receipt.json'; receipt.write_text(json.dumps(data),encoding='utf-8')
            steps.append({'target':target,'state':'COMPLETED','status':status,'exit_code':data['exit_code'],
                'receipt':directory.relative_to(root).as_posix(),'receipt_sha256':hashlib.sha256(receipt.read_bytes()).hexdigest()})
        value={'schema_version':1,'source_sha256':IDENTITY,'plan':list(GATES),'commands':steps,'status':'FAIL'}
        path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(value),encoding='utf-8')
        return path,value

    def test_actual_prefix_is_required_and_started_gate_is_never_repeated(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); path,value=self.fixture(root,[('contracts','PASS'),('build','PASS')])
            value['commands'].append({'target':'fmt','state':'STARTED'}); value['status']='RUNNING'
            path.write_text(json.dumps(value),encoding='utf-8')
            steps=sequence.load_ledger(root,path,IDENTITY)
            runnable,blocked=sequence.diagnostic_plan(list(GATES),steps,cleanup_passed=True)
            self.assertNotIn('fmt',runnable); self.assertIn('benchmark',runnable); self.assertEqual(blocked,[])
            value['commands'][-1]['target']='benchmark'; path.write_text(json.dumps(value),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'prefix'): sequence.load_ledger(root,path,IDENTITY)

    def test_unverified_or_changed_raw_receipt_cannot_prove_an_attempt_completed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); path,value=self.fixture(root,[('contracts','PASS')])
            with self.assertRaises(ValueError): sequence.load_ledger(root,path,'b'*64)
            (path.parent/'commands/contracts/stdout.txt').write_bytes(b'changed\n')
            with self.assertRaises(ValueError): sequence.load_ledger(root,path,IDENTITY)
            value['status']='PASS'; path.write_text(json.dumps(value),encoding='utf-8')
            with self.assertRaises(ValueError): sequence.load_ledger(root,path,IDENTITY)

    def test_cleanup_contract_and_build_failures_block_dependent_diagnostics(self):
        steps=[{'target':'contracts','state':'COMPLETED','status':'PASS'},
               {'target':'build','state':'COMPLETED','status':'FAIL'}]
        runnable,blocked=sequence.diagnostic_plan(list(GATES),steps,cleanup_passed=True)
        self.assertEqual(set(runnable),{'fmt','lint','check','test','verify-reference','security-online'})
        self.assertTrue(all(row['reason']=='product build prerequisite did not pass' for row in blocked))
        runnable,blocked=sequence.diagnostic_plan(list(GATES),steps,cleanup_passed=False)
        self.assertEqual(runnable,[]); self.assertEqual(len(blocked),len(GATES)-2)
        runnable,_=sequence.diagnostic_plan(list(GATES),[dict(steps[0],status='FAIL')],cleanup_passed=True)
        self.assertEqual(runnable,[])

    def test_incomplete_duplicate_and_reduced_make_plans_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            for plan in (GATES[:-1],(*GATES,'benchmark'),tuple(name for name in GATES if name!='verify-reference')):
                (root/'Makefile').write_text('VERIFY_GATES := '+' '.join(plan)+'\n',encoding='utf-8')
                with self.assertRaises(ValueError): sequence.read_plan(root)
            for value in ('nan','inf','-1','0','299','86401'):
                with self.assertRaises(ValueError): sequence.budget(value)


if __name__=='__main__': unittest.main()
