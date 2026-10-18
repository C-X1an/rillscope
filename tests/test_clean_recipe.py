"""Fresh-recipe orchestration metadata controls; these do not run the product."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import clean_verify

GATES=('contracts','build','fmt','lint','check','test','verify-reference','integration',
       'acceptance','security','security-online','property','fuzz','mutation','benchmark',
       'benchmark-sort-null','publication-check','demo')
IDENTITY='a'*64


class CleanRecipe(unittest.TestCase):
    def invoke(self, failure=None):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); calls=[]
            (root/'Makefile').write_bytes((Path(clean_verify.__file__).resolve().parents[1]/'Makefile').read_bytes())
            def receipt(path,command,status):
                path.mkdir(parents=True,exist_ok=True)
                for name in ('stdout.txt','stderr.txt'): (path/name).write_bytes(b'')
                data={'command':command,'exit_code':0 if status=='PASS' else 17,
                    'verification_status':status,'execution_outcome':'EXECUTED',
                    'source_before':{'sha256':IDENTITY},'source_after_sha256':IDENTITY,
                    'process_cleanup':{'status':'PASS'},
                    **{key:{'file':key+'.txt','sha256':hashlib.sha256(b'').hexdigest()}
                       for key in ('stdout','stderr')}}
                (path/'receipt.json').write_text(json.dumps(data),encoding='utf-8')
                return data
            def run(command,**kwargs):
                if command[:2]==['git','clone']:
                    self.clone_attempt=(command,kwargs)
                    checkout=Path(command[-1]); checkout.mkdir(parents=True)
                    (checkout/'Makefile').write_bytes((root/'Makefile').read_bytes())
                    return types.SimpleNamespace(returncode=0)
                if '--out' not in command: raise AssertionError('unexpected unit command: '+repr(command))
                destination=Path(command[command.index('--out')+1])
                child=command[command.index('--')+1:]
                if child[:2]==['git','clone']:
                    self.clone_attempt=(command,kwargs)
                    checkout=Path(child[-1]); checkout.mkdir(parents=True)
                    (checkout/'Makefile').write_bytes((root/'Makefile').read_bytes())
                    data=receipt(destination,child,'PASS')
                    return types.SimpleNamespace(returncode=data['exit_code'])
                self.assertEqual(child[0],'make')
                target=child[1]; calls.append((target,command))
                status='FAIL' if target==failure or target=='verify' and failure in GATES else 'PASS'
                data=receipt(destination,child,status)
                if target=='verify' and 'RILLSCOPE_VERIFY_LEDGER' in kwargs['env']:
                    # Unit records model the actual per-gate ledger contract.
                    ledger=Path(kwargs['env']['RILLSCOPE_VERIFY_LEDGER']); steps=[]
                    for gate in GATES:
                        gate_path=ledger.parent/'commands'/gate
                        gate_command=['make',gate]+(['SHELL=sh'] if clean_verify.os.name=='nt' else [])
                        gate_data=receipt(gate_path,gate_command,'FAIL' if gate==failure else 'PASS')
                        steps.append({'target':gate,'state':'COMPLETED','status':gate_data['verification_status'],
                            'exit_code':gate_data['exit_code'],'receipt':gate_path.relative_to(Path(kwargs['cwd'])).as_posix(),
                            'receipt_sha256':hashlib.sha256((gate_path/'receipt.json').read_bytes()).hexdigest()})
                        if gate==failure: break
                    ledger.parent.mkdir(parents=True,exist_ok=True)
                    ledger.write_text(json.dumps({'schema_version':1,'source_sha256':IDENTITY,
                        'plan':list(GATES),'commands':steps,'status':status}),encoding='utf-8')
                return types.SimpleNamespace(returncode=data['exit_code'])
            with patch.object(clean_verify,'ROOT',root), \
                    patch.object(clean_verify,'git',side_effect=lambda *args,**kwargs: '' if args[0]=='status' else 'b'*40), \
                    patch.object(clean_verify,'source_identity',return_value={'sha256':IDENTITY}), \
                    patch.object(clean_verify.shutil,'which',return_value='unit-tool'), \
                    patch.object(clean_verify.subprocess,'run',side_effect=run), \
                    patch.object(sys,'argv',['clean_verify.py']), \
                    patch.dict(clean_verify.os.environ,{},clear=True), \
                    contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                code=clean_verify.main()
            reports=list((root/'.local-runs').glob('clean-*/results.json'))
            return code,calls,json.loads(reports[0].read_bytes()) if reports else None

    def test_success_runs_one_canonical_recipe_and_no_supplemental_grid(self):
        code,calls,report=self.invoke()
        self.assertEqual((code,report['status']),(0,'PASS'))
        self.assertEqual([target for target,_ in calls],['bootstrap','verify','demo'])

    def test_verify_budget_covers_observed_collection_and_validation_with_headroom(self):
        _,calls,_=self.invoke()
        command=next(command for target,command in calls if target=='verify')
        self.assertGreaterEqual(float(command[command.index('--timeout')+1]),24000,
            '17660s collection +3805s validation leave no room for the remaining recipe at10800s')

    def test_failed_benchmark_is_retained_without_rerunning_attempted_gates(self):
        code,calls,report=self.invoke('benchmark')
        self.assertNotEqual(code,0)
        self.assertEqual(report['status'],'FAIL')
        self.assertEqual([target for target,_ in calls],
            ['bootstrap','verify','benchmark-sort-null','publication-check','demo'])

    def test_failed_bootstrap_does_not_launch_canonical_verify_or_product_diagnostics(self):
        code,calls,report=self.invoke('bootstrap')
        self.assertNotEqual(code,0)
        self.assertEqual(report['status'],'FAIL')
        self.assertEqual([target for target,_ in calls],['bootstrap'])

    def test_later_unattempted_benchmark_gets_the_full_remaining_diagnostic_budget(self):
        code,calls,report=self.invoke('fmt')
        self.assertNotEqual(code,0); self.assertEqual(report['status'],'FAIL')
        self.assertEqual([target for target,_ in calls].count('benchmark'),1)
        command=next(command for target,command in calls if target=='benchmark')
        self.assertGreaterEqual(float(command[command.index('--timeout')+1]),24000)

    def test_clone_has_an_owned_capture_and_a_bounded_timeout(self):
        self.invoke()
        command,_=self.clone_attempt
        self.assertIn('--out',command,'clone must retain an actual owned-process receipt')
        self.assertGreater(float(command[command.index('--timeout')+1]),0)
        self.assertLessEqual(float(command[command.index('--timeout')+1]),300)

    def test_git_identity_queries_have_a_bounded_timeout(self):
        with patch.object(clean_verify.subprocess,'check_output',return_value='unit\n') as query:
            self.assertEqual(clean_verify.git('rev-parse','HEAD'),'unit')
        self.assertIn('timeout',query.call_args.kwargs)
        self.assertGreater(query.call_args.kwargs['timeout'],0)
        self.assertLessEqual(query.call_args.kwargs['timeout'],30)


if __name__=='__main__': unittest.main()
