#!/usr/bin/env python3
"""Execute the Makefile's closed verification plan and retain each actual attempt."""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from evidence import source_identity, verify_receipt

ROOT=Path(__file__).resolve().parents[1]
REQUIRED=frozenset(('contracts','build','fmt','lint','check','test','verify-reference',
    'integration','acceptance','security','security-online','property','fuzz','mutation',
    'benchmark','benchmark-sort-null','publication-check','demo'))
PRODUCT=frozenset(('integration','acceptance','security','property','fuzz','mutation',
    'benchmark','benchmark-sort-null','publication-check','demo'))
RESERVE_SECONDS=180
DEFAULT_BUDGET_SECONDS=42600
MAX_BUDGET_SECONDS=86400


def owned_path(root,path):
    root=root.resolve(); path=Path(os.path.abspath(path))
    if not path.is_relative_to(root/'.local-runs'): raise ValueError('owned .local-runs path required')
    for part in (path,*path.parents):
        if part.is_symlink() or (hasattr(part,'is_junction') and part.is_junction()):
            raise ValueError('verification paths cannot traverse links')
        if part==root: break
    return path


def write_json(path,data):
    encoded=(json.dumps(data,indent=2)+'\n').encode('utf-8')
    path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix='ledger-',suffix='.tmp',dir=path.parent,delete=False) as target:
        target.write(encoded); target.flush(); os.fsync(target.fileno()); temporary=target.name
    os.replace(temporary,path)


def read_plan(root):
    lines=[line for line in (root/'Makefile').read_text(encoding='utf-8').splitlines()
           if line.startswith('VERIFY_GATES := ')]
    if len(lines)!=1: raise ValueError('one authoritative verification plan required')
    gates=lines[0].removeprefix('VERIFY_GATES := ').split()
    if (len(gates)!=len(REQUIRED) or set(gates)!=REQUIRED or gates[:2]!=['contracts','build']
            or gates[-1]!='demo' or any(re.fullmatch('[a-z-]+',name) is None for name in gates)):
        raise ValueError('verification plan omits/repeats a required gate or changes prerequisite order')
    return gates


def checked_receipt(root,directory,identity,command=None):
    directory=owned_path(root,directory); path=directory/'receipt.json'
    if path.stat().st_size>8*1024**2: raise ValueError('command receipt exceeds metadata bound')
    data=json.loads(path.read_bytes())
    if (not verify_receipt(path) or data['source_before']['sha256']!=identity
            or data['verification_status'] not in {'PASS','FAIL','BLOCKED'}
            or (command is not None and data['command']!=command)):
        raise ValueError('actual command receipt/source/command differs')
    if type(data['exit_code']) is not int: raise ValueError('actual exit code must be an integer')
    if data['verification_status']=='PASS' and (data['exit_code']!=0 or data['source_after_sha256']!=identity
            or data['execution_outcome']!='EXECUTED' or data['process_cleanup']['status']!='PASS'):
        raise ValueError('command PASS lacks successful execution/cleanup')
    return data


def load_ledger(root,path,identity):
    path=owned_path(root,path)
    if path.stat().st_size>1024**2: raise ValueError('verification ledger exceeds bound')
    value=json.loads(path.read_bytes()); plan=read_plan(root)
    if (value['schema_version']!=1 or value['source_sha256']!=identity or value['plan']!=plan
            or value['status'] not in {'RUNNING','PASS','FAIL'} or len(value['commands'])>len(plan)):
        raise ValueError('verification ledger identity/plan differs')
    steps=value['commands']
    for index,step in enumerate(steps):
        if step['target']!=plan[index]: raise ValueError('actual attempt order is not a plan prefix')
        if step['state']=='STARTED' and index==len(steps)-1: continue
        if step['state']!='COMPLETED': raise ValueError('unknown or nonterminal unfinished attempt')
        directory=owned_path(root,root/step['receipt'])
        if hashlib.sha256((directory/'receipt.json').read_bytes()).hexdigest()!=step['receipt_sha256']:
            raise ValueError('actual gate receipt identity changed')
        command=['make',step['target']]+(['SHELL=sh'] if os.name=='nt' else [])
        data=checked_receipt(root,directory,identity,command)
        if step['status']!=data['verification_status'] or step['exit_code']!=data['exit_code']:
            raise ValueError('ledger differs from actual gate receipt')
        if index<len(steps)-1 and step['status']!='PASS': raise ValueError('sequence continued after failure')
    if value['status']=='PASS' and (len(steps)!=len(plan)
            or any(step['state']!='COMPLETED' or step['status']!='PASS' for step in steps)):
        raise ValueError('ledger PASS lacks all completed gates')
    return steps


def diagnostic_plan(plan,steps,*,cleanup_passed):
    attempted={step['target'] for step in steps}
    passed={step['target'] for step in steps if step['state']=='COMPLETED' and step['status']=='PASS'}
    runnable=[]; blocked=[]
    for target in plan:
        if target in attempted: continue
        reason=None
        if not cleanup_passed: reason='canonical verification cleanup did not pass'
        elif 'contracts' not in passed: reason='contract prerequisite did not pass'
        elif target in PRODUCT and 'build' not in passed: reason='product build prerequisite did not pass'
        (blocked if reason else runnable).append({'target':target,'reason':reason} if reason else target)
    return runnable,blocked


def budget(value):
    result=float(value)
    if not math.isfinite(result) or not 300<=result<=MAX_BUDGET_SECONDS:
        raise ValueError('verification budget must be finite and between300 and86400 seconds')
    return result


def gate_timeout(target,remaining):
    limit={'benchmark':32400,'benchmark-sort-null':7200,'build':1800,
           'property':1800,'fuzz':1800,'mutation':1800,'security-online':1800}.get(target,900)
    return min(limit,remaining-RESERVE_SECONDS)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('gates',nargs='+'); args=parser.parse_args()
    plan=read_plan(ROOT)
    if args.gates!=plan: raise ValueError('execute the exact authoritative Makefile plan')
    if os.environ.get('RILLSCOPE_CLEAN_SCOPE_FILE'):
        raise ValueError('obsolete nested-clean shortcut is not accepted')
    total=budget(os.environ.get('RILLSCOPE_VERIFY_BUDGET_SECONDS',DEFAULT_BUDGET_SECONDS))
    path=owned_path(ROOT,Path(os.environ.get('RILLSCOPE_VERIFY_LEDGER',
        str(ROOT/'.local-runs'/('verify-'+str(time.time_ns()))/'ledger.json'))))
    if path.exists(): raise ValueError('verification ledger must be new')
    identity=source_identity(ROOT)['sha256']; deadline=time.monotonic()+total
    record={'schema_version':1,'source_sha256':identity,'plan':plan,'commands':[],
        'status':'RUNNING','budget_seconds':total,'started_utc':dt.datetime.now(dt.timezone.utc).isoformat()}
    write_json(path,record)
    code=1
    try:
        for target in plan:
            timeout=gate_timeout(target,deadline-time.monotonic())
            if timeout<=0: raise ValueError('verification budget exhausted before next gate')
            directory=path.parent/'commands'/target
            command=['make',target]+(['SHELL=sh'] if os.name=='nt' else [])
            step={'target':target,'state':'STARTED','started_utc':dt.datetime.now(dt.timezone.utc).isoformat()}
            record['commands'].append(step); write_json(path,record)
            result=subprocess.run([sys.executable,str(ROOT/'scripts/evidence.py'),'--out',str(directory),
                '--timeout',str(timeout),'--',*command],cwd=ROOT)
            data=checked_receipt(ROOT,directory,identity,command)
            step.update(state='COMPLETED',status=data['verification_status'],exit_code=data['exit_code'],
                receipt=directory.relative_to(ROOT).as_posix(),
                receipt_sha256=hashlib.sha256((directory/'receipt.json').read_bytes()).hexdigest())
            write_json(path,record)
            if result.returncode!=data['exit_code']: raise ValueError('actual gate process/receipt exit differs')
            if step['status']!='PASS':
                code=result.returncode or 1; break
        else: code=0
    except (OSError,ValueError,KeyError) as error:
        record['problem']=type(error).__name__+': '+str(error)
        code=1
    record.update(status='PASS' if code==0 else 'FAIL',finished_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    write_json(path,record)
    print(json.dumps({'status':record['status'],'ledger':str(path),'attempted_gates':len(record['commands']),
        'scope':'actual sequential gate attempts; a verification plan alone is not execution evidence'}))
    return code


if __name__=='__main__': raise SystemExit(main())
