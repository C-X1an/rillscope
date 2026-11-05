"""Synthetic CLI identity controls using real disposable Git commit graphs.

API/artifact records and the raw validator are unit fixtures. These tests make
no CI-origin, execution, cancellation, or independent-review evidence claim.
"""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import verify_publication_evidence as checker


class PublicationPRIdentity(unittest.TestCase):
    def setUp(self):
        local = ROOT/'.local-runs'
        local.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='publication-identity-',dir=local)
        self.folder = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.source = self.folder/'source'; self.source.mkdir()
        self.git('init','--quiet')
        (self.source/'marker.txt').write_bytes(b'base unit fixture\n')
        self.git('add','--','marker.txt'); base_tree = self.git('write-tree')
        self.base = self.commit(base_tree,[],b'base\n')
        (self.source/'marker.txt').write_bytes(b'head unit fixture\n')
        self.git('add','--','marker.txt'); self.tree = self.git('write-tree')
        self.head = self.commit(self.tree,[self.base],b'head\n')
        self.merge = self.commit(self.tree,[self.base,self.head],b'merge\n')
        self.unrelated = self.commit(self.tree,[],b'unrelated same tree\n')
        self.swapped = self.commit(self.tree,[self.head,self.base],b'swapped parents\n')
        self.extra_parent = self.commit(self.tree,[self.base,self.head,self.unrelated],b'extra parent\n')
        (self.source/'marker.txt').write_bytes(b'changed merge unit fixture\n')
        self.git('add','--','marker.txt')
        self.changed = self.commit(self.git('write-tree'),[self.base,self.head],b'changed tree\n')
        self.select(self.merge)
        self.zip = self.folder/'unit-artifact.zip'
        self.zip.write_bytes(b'synthetic artifact fixture; Records is mocked\n')
        repo = {'id':1421903136,'full_name':'C-X1an/rillscope'}
        endpoint = {'id':repo['id'],'name':'rillscope','url':'https://api.github.com/repos/C-X1an/rillscope'}
        self.job = {'id':2,'run_id':1,'name':'publication-boundary','status':'completed',
            'conclusion':'success','labels':['ubuntu-24.04']}
        self.run = {'id':1,'head_sha':self.head,'event':'pull_request','repository':repo,
            'conclusion':'success','pull_requests':[{'number':1,
                'head':{'sha':self.head,'repo':copy.deepcopy(endpoint)},
                'base':{'sha':self.base,'repo':copy.deepcopy(endpoint)}}]}
        self.artifact = {'name':'publication-boundary-observations','workflow_run':{'id':1,'head_sha':self.head},
            'digest':'sha256:'+hashlib.sha256(self.zip.read_bytes()).hexdigest()}

    def git(self,*arguments,input=None):
        command = ['git','-c','core.autocrlf=false','-c','commit.gpgsign=false',
            '-c','user.name=RillScope unit fixture','-c','user.email=unit@rillscope.invalid',*arguments]
        result = subprocess.run(command,cwd=self.source,input=input,capture_output=True,check=True)
        return result.stdout.decode().strip()

    def commit(self,tree,parents,message):
        arguments = ['commit-tree',tree]
        for parent in parents: arguments.extend(['-p',parent])
        return self.git(*arguments,input=message)

    def select(self,commit):
        self.assertTrue(self.source.resolve().is_relative_to(self.folder))
        self.git('checkout','--quiet','--detach','--force',commit)

    def invoke(self):
        def public_api(suffix):
            return copy.deepcopy({'/actions/jobs/2':self.job,'/actions/runs/1':self.run,
                '/actions/artifacts/3':self.artifact}[suffix])
        def recorded_validator(records,source,commit):
            # Retain the real validator's exact clean-HEAD precondition. Its
            # behavioral record assertions are exercised by separate tests.
            if source != self.source or commit != self.git('rev-parse','HEAD') or self.git('status','--porcelain'):
                raise ValueError('exact clean recorded-source checkout required')
            return {'status':'PASS','campaign':'synthetic-cli-identity-unit-fixture'}
        stream = io.StringIO()
        records = Mock()
        argv = ['verify_publication_evidence.py','--commit',self.head,'--job-id','2',
            '--artifact-id','3','--zip',str(self.zip),'--source-checkout',str(self.source)]
        with patch.object(sys,'argv',argv),patch.object(checker,'public_api',side_effect=public_api),\
                patch.object(checker,'Records',return_value=records),\
                patch.object(checker,'verify_records',side_effect=recorded_validator) as validator,\
                contextlib.redirect_stdout(stream):
            code = checker.main()
        self.assertEqual(code,0)
        records.archive.close.assert_called_once_with()
        return json.loads(stream.getvalue()),validator

    def test_actual_merge_parent_order_and_identical_full_tree_accepts_both_identities(self):
        try:
            result, validator = self.invoke()
        except ValueError as error:
            self.fail('valid same-tree PR merge rejected: '+str(error))
        self.assertEqual(validator.call_args.args[2],self.merge)
        self.assertEqual(result['remote_commit'],self.head)
        self.assertEqual(result['workflow_head_commit'],self.head)
        self.assertEqual(result['recorded_checkout_commit'],self.merge)
        self.assertEqual(result['recorded_checkout_tree'],self.tree)
        self.assertEqual(result['recorded_checkout_parents'],[self.base,self.head])
        self.assertEqual(result['source_commit_binding'],'same-tree-pull-request-merge')

    def test_ordinary_exact_head_push_still_accepts(self):
        self.select(self.head)
        self.run['event'] = 'push'; self.run.pop('pull_requests')
        result, validator = self.invoke()
        self.assertEqual(validator.call_args.args[2],self.head)
        self.assertEqual(result['remote_commit'],self.head)

    def test_exact_head_pr_still_accepts(self):
        self.select(self.head)
        result, validator = self.invoke()
        self.assertEqual(validator.call_args.args[2],self.head)
        self.assertEqual(result['remote_commit'],self.head)

    def test_unrelated_changed_tree_or_wrong_parent_graph_rejects(self):
        for commit in (self.unrelated,self.changed,self.swapped,self.extra_parent):
            with self.subTest(commit=commit):
                self.select(commit)
                with self.assertRaises(ValueError): self.invoke()

    def test_dirty_merge_checkout_rejects(self):
        (self.source/'untracked.txt').write_bytes(b'dirty\n')
        with self.assertRaises(ValueError): self.invoke()

    def test_non_pr_workflow_cannot_bind_a_merge(self):
        for event in ('push','workflow_dispatch',None):
            with self.subTest(event=event):
                self.run['event'] = event
                with self.assertRaises(ValueError): self.invoke()

    def test_missing_duplicate_or_unrelated_pr_association_rejects(self):
        original = copy.deepcopy(self.run['pull_requests'][0])
        for associations in (None,[],[original,original],{},[dict(original,head={'sha':self.base,'repo':original['head']['repo']})]):
            with self.subTest(associations=associations):
                self.run['pull_requests'] = copy.deepcopy(associations)
                with self.assertRaises(ValueError): self.invoke()

    def test_wrong_base_or_malformed_sha_rejects(self):
        for base in (self.unrelated,'--help','a'*39,None):
            with self.subTest(base=base):
                self.run['pull_requests'][0]['base']['sha'] = base
                with self.assertRaises(ValueError): self.invoke()

    def test_cross_repository_missing_or_untyped_repository_identity_rejects(self):
        original = copy.deepcopy(self.run)
        for endpoint in ('head','base'):
            for field,value in [('id',1),('id',None),('id',True),('url','https://api.github.com/repos/other/rillscope'),('name','other')]:
                with self.subTest(endpoint=endpoint,field=field,value=value):
                    self.run = copy.deepcopy(original)
                    self.run['pull_requests'][0][endpoint]['repo'][field] = value
                    with self.assertRaises(ValueError): self.invoke()
        for value in (None,True,0,-1,'1421903136'):
            with self.subTest(workflow_repository_id=value):
                self.run = copy.deepcopy(original); self.run['repository']['id'] = value
                with self.assertRaises(ValueError): self.invoke()

    def test_wrong_workflow_or_artifact_head_rejects(self):
        self.run['head_sha'] = self.base
        with self.assertRaises(ValueError): self.invoke()
        self.run['head_sha'] = self.head
        self.artifact['workflow_run']['head_sha'] = self.base
        with self.assertRaises(ValueError): self.invoke()


if __name__ == '__main__':
    unittest.main()
