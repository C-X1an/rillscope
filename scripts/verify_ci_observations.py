#!/usr/bin/env python3
"""Bind captured public CI test observations to actual job state and Git blobs.

No local product tests are executed. Raw logs are operator inputs, never copied
to the curated output. Their origin remains author-attested; hashes do not turn
them into independent origin authentication. No credentials are read or sent.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'C-X1an/rillscope'
REMOTE_SOURCES = {
    'AC-016': {'scripts/export_policy.py','tests/security/test_export.py'},
    'AC-026': {'scripts/evidence.py','scripts/owned_process.py','tests/test_evidence.py',
               'tests/test_review_427.py','tests/test_review_e7.py'}}


def public_api(suffix):
    request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + suffix,
        headers={'Accept':'application/vnd.github+json','User-Agent':'RillScope-evidence-reader',
                 'X-GitHub-Api-Version':'2022-11-28'})
    with urllib.request.urlopen(request,timeout=30) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--commit',required=True)
    parser.add_argument('--job-id',type=int,required=True); parser.add_argument('--job-log',type=Path,required=True)
    parser.add_argument('--source-checkout',type=Path,required=True); args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}',args.commit) or args.job_id <= 0: raise ValueError('explicit commit/job identity required')
    source = args.source_checkout.resolve()
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip() != args.commit:
        raise ValueError('source checkout does not match the actual requested CI commit')
    if subprocess.check_output(['git','status','--porcelain'],cwd=source).strip(): raise ValueError('CI source checkout is dirty')
    job = public_api('/actions/jobs/' + str(args.job_id))
    workflow = public_api('/actions/runs/' + str(job['run_id']))
    if (job['id'] != args.job_id or job['status'] != 'completed' or job['conclusion'] != 'success'
            or workflow['head_sha'] != args.commit or workflow['repository']['full_name'] != REPOSITORY
            or job['name'] not in ('reference','rust-product') or 'ubuntu-24.04' not in job['labels']):
        raise ValueError('no matching completed successful Ubuntu test job')
    log = args.job_log.read_bytes()
    if len(log) > 8*1024*1024: raise ValueError('unexpected captured job log size')
    names = set()
    for line in log.decode('utf-8').splitlines():
        line = re.sub(r'^\d{4}-\d{2}-\d{2}T[^ ]+\s+','',line)
        line = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',line)
        match = re.fullmatch(r'(test_[A-Za-z0-9_]+) \([^\n]+\) \.\.\. ok',line)
        if match: names.add(match[1])
    if not names: raise ValueError('no actual named successful Python checks in the captured log')
    remote = {}
    for name in sorted(set.union(*REMOTE_SOURCES.values())):
        content = subprocess.run(['git','show',args.commit + ':' + name],cwd=source,capture_output=True)
        if content.returncode: continue
        if (source / name).read_bytes() != content.stdout: raise ValueError('source checkout/blob mismatch')
        remote[name] = hashlib.sha256(content.stdout).hexdigest()
    result = {'status':'PASS','campaign':'observed-public-linux-CI','remote_repository':REPOSITORY,
              'remote_commit':args.commit,'remote_run_id':job['run_id'],'remote_job_id':job['id'],
              'remote_job_name':job['name'],'remote_job_conclusion':job['conclusion'],
              'remote_workflow_conclusion':workflow['conclusion'],'remote_runner_labels':job['labels'],
              'remote_python_test_names':sorted(names),'remote_source_files':sorted(remote.items()),
              'remote_log_sha256':hashlib.sha256(log).hexdigest(),
              'remote_scope':'selected actual Ubuntu job; no local product execution, full-release or dedicated-reference-host claim; captured log origin is author-attested'}
    print(json.dumps(result,indent=2)); return 0


if __name__ == '__main__': raise SystemExit(main())
