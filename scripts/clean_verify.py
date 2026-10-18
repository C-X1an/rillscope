#!/usr/bin/env python3
"""Execute one fresh bootstrap/verify/demo recipe, retaining canonical failures."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from evidence import source_identity
from verify_sequence import (budget,checked_receipt,diagnostic_plan,gate_timeout,
    load_ledger,read_plan,write_json)

ROOT=Path(__file__).resolve().parents[1]
DEFAULT_BUDGET_SECONDS=43200
RESERVE_SECONDS=300


def git(*arguments,root=None,timeout=30):
    if not 0<timeout<=30: raise ValueError('Git query timeout must be within30seconds')
    # These are local identity/status queries; disable optional external fsmonitor.
    return subprocess.check_output(['git','-c','core.fsmonitor=false','-c','core.untrackedCache=false',*arguments],
        cwd=ROOT if root is None else root,text=True,timeout=timeout,stdin=subprocess.DEVNULL).strip()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--demo-only',action='store_true',help='fresh bootstrap/build/demo only; never qualifies AC024')
    parser.add_argument('--budget-seconds',type=budget,
        default=os.environ.get('RILLSCOPE_CLEAN_BUDGET_SECONDS',DEFAULT_BUDGET_SECONDS),
        help='whole fresh procedure wall budget, including diagnostics and cleanup reserve; default12hours')
    args=parser.parse_args()
    started=time.monotonic(); deadline=started+args.budget_seconds
    def query(*arguments,root=None):
        remaining=deadline-time.monotonic()
        if remaining<=0: raise subprocess.TimeoutExpired(['git',*arguments],args.budget_seconds)
        return git(*arguments,root=root,timeout=min(30,remaining))
    if os.environ.get('RILLSCOPE_CLEAN_SCOPE_FILE'):
        print('FAIL: obsolete nested-clean marker is not accepted',file=sys.stderr); return 1
    for tool in ('git','make','rustup','cargo'):
        if shutil.which(tool) is None:
            print('BLOCKED: required tool unavailable: '+tool,file=sys.stderr); return 77
    local=ROOT/'.local-runs';local.mkdir(parents=True,exist_ok=True)
    # Keep the exact owned checkout18characters shorter than the timestamped
    # layout: the pinned Windows GNU linker failed on its272character output.
    out=Path(tempfile.mkdtemp(prefix='clean-',dir=local))
    clone=out/'c'; identity=source_identity(ROOT)['sha256']
    env=os.environ.copy(); env['CARGO_TARGET_DIR']='target'; env['GIT_TERMINAL_PROMPT']='0'
    ledger=clone/'.local-runs/verify-ledger/ledger.json'
    env['RILLSCOPE_VERIFY_LEDGER']=str(ledger)
    report={'mode':'fresh-committed-Rust-demo-checkout' if args.demo_only else 'fresh-committed-Rust-checkout',
        'status':'RUNNING','commit':None,'source_sha256':identity,'source_stable':False,
        'same_os_and_toolchain_installation':True,'target_directory_was_fresh':False,
        'checkout':clone.relative_to(ROOT).as_posix(),
        'cargo_target_dir_enforced_inside_fresh_clone':True,'budget_seconds':args.budget_seconds,
        'preparation':[],'commands':[],'diagnostic_commands':[],'not_run':[],
        'scope':'canonical fresh commands govern status; diagnostic success never repairs their failure'}
    def persist(): write_json(out/'results.json',report)
    persist()
    def execute(target,role):
        remaining=deadline-time.monotonic()-RESERVE_SECONDS
        timeout=remaining if target=='verify' else min(1800 if target in {'bootstrap','build'} else 900,remaining)
        if role=='diagnostic': timeout=gate_timeout(target,remaining)
        if timeout<=0 or target=='verify' and timeout<360:
            report['not_run'].append({'target':target,'role':role,'reason':'whole procedure budget exhausted'})
            persist(); return None
        if target=='verify': env['RILLSCOPE_VERIFY_BUDGET_SECONDS']=str(max(300,timeout-60))
        command=['make',target]+(['SHELL=sh'] if os.name=='nt' else [])
        directory=out/'commands'/target if role=='canonical' else out/'diagnostics'/target
        attempted={'target':target,'role':role,'state':'STARTED'}
        destination=report['commands'] if role=='canonical' else report['diagnostic_commands']
        destination.append(attempted); persist()
        result=subprocess.run([sys.executable,str(clone/'scripts/evidence.py'),'--out',str(directory),
            '--timeout',str(timeout),'--',*command],cwd=clone,env=env,timeout=timeout+60)
        data=checked_receipt(ROOT,directory,identity,command)
        attempted.update(state='COMPLETED',exit_code=result.returncode,status=data['verification_status'],
            source_before=data['source_before']['sha256'],source_after=data['source_after_sha256'],
            receipt=directory.relative_to(ROOT).as_posix())
        if result.returncode!=data['exit_code']: raise ValueError('actual canonical process/receipt exit differs')
        persist(); return data
    failure=False; confirmed=False
    targets=['bootstrap','build','demo'] if args.demo_only else ['bootstrap','verify','demo']
    verify_data=None
    try:
        if query('status','--porcelain'): raise ValueError('commit all public source changes before clean verification')
        commit=query('rev-parse','HEAD'); report['commit']=commit
        command=['git','clone','--no-local','--config','core.autocrlf=false',str(ROOT),str(clone)]
        directory=out/'preparation/clone'
        preparation={'operation':'clone','state':'STARTED'}; report['preparation'].append(preparation); persist()
        timeout=min(300,deadline-time.monotonic()-RESERVE_SECONDS)
        if timeout<=0: raise ValueError('whole procedure budget exhausted before clone')
        result=subprocess.run([sys.executable,str(ROOT/'scripts/evidence.py'),'--out',str(directory),
            '--timeout',str(timeout),'--',*command],cwd=ROOT,env=env,timeout=timeout+60)
        data=checked_receipt(ROOT,directory,identity,command)
        preparation.update(state='COMPLETED',status=data['verification_status'],exit_code=result.returncode,
            receipt=directory.relative_to(ROOT).as_posix())
        persist()
        if result.returncode!=data['exit_code'] or data['verification_status']!='PASS':
            raise ValueError('owned fresh clone did not pass; original receipt retained')
        if query('rev-parse','HEAD',root=clone)!=commit or source_identity(clone)['sha256']!=identity:
            raise ValueError('fresh clone differs from committed source')
        if (clone/'target').exists(): raise ValueError('fresh clone already has build output')
        confirmed=True; report['target_directory_was_fresh']=True; persist()
        for index,target in enumerate(targets):
            data=execute(target,'canonical')
            if target=='verify': verify_data=data
            if data is None or data['verification_status']!='PASS':
                failure=True
                report['not_run'].extend({'target':other,'role':'canonical',
                    'reason':'preceding canonical command did not pass'} for other in targets[index+1:])
                break
        if (failure and verify_data is not None and not args.demo_only
                and source_identity(clone)['sha256']==identity):
            steps=load_ledger(clone,ledger,identity)
            runnable,blocked=diagnostic_plan(read_plan(clone),steps,
                cleanup_passed=verify_data['process_cleanup']['status']=='PASS')
            report['not_run'].extend(dict(row,role='diagnostic') for row in blocked)
            for index,target in enumerate(runnable):
                data=execute(target,'diagnostic')
                if data is None or data['process_cleanup']['status']!='PASS' or data['source_after_sha256']!=identity:
                    report['not_run'].extend({'target':other,'role':'diagnostic',
                        'reason':'diagnostic budget, cleanup or source stability prevents further work'} for other in runnable[index+1:])
                    break
    except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        failure=True; report['problem']=type(error).__name__+': '+str(error)
    stable=False
    try:
        stable=confirmed and source_identity(clone)['sha256']==identity and not query('status','--porcelain',root=clone)
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        failure=True; report['final_identity_problem']=type(error).__name__+': '+str(error)
    passed=(not failure and stable and len(report['commands'])==3
        and all(item.get('status')=='PASS' for item in report['commands']))
    report.update(status='PASS' if passed else 'FAIL',source_stable=stable,
        elapsed_seconds=time.monotonic()-started,finished_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    persist(); print(json.dumps(report,indent=2))
    return 0 if passed else 1


if __name__=='__main__': raise SystemExit(main())
