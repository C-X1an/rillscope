"""Actual Linux helper lifecycle controls; no VM or reference certification.

The default harness owns every test process and needs no elevated permission.
The same command can run under the trial's already authorized root identity to
exercise privileged descendant cleanup. It never signals unrelated processes.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from inspect_reference_guest import TrialCommands,TrialInterrupted,interrupted,require
from owned_process import LinuxOwnedChildren


def worker(out,mode):
    out.mkdir()
    ownership=LinuxOwnedChildren()
    for number in (signal.SIGTERM,signal.SIGINT): signal.signal(number,interrupted)
    error=None
    try:
        if mode=='success': command=[sys.executable,'-c','print("actual helper output")'];timeout=5
        else:
            # The actual tool starts a new session-changing child and records
            # both PIDs. These are real owned processes, not mocked Popen calls.
            program='import json,os,pathlib,subprocess,sys,time; child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],start_new_session=True); pathlib.Path(sys.argv[1]).write_text(json.dumps([os.getpid(),child.pid])); print("actual helper started",flush=True); time.sleep(60)'
            command=[sys.executable,'-c',program,str(out/'owned-pids.json')]
            timeout=.5 if mode=='timeout' else 60
        TrialCommands(out,ownership)('controlled-helper',command,timeout=timeout)
    except (OSError,ValueError,subprocess.SubprocessError,TrialInterrupted) as caught:
        error=type(caught).__name__
    finally:
        for number in (signal.SIGTERM,signal.SIGINT): signal.signal(number,signal.SIG_IGN)
        cleanup=ownership.finish(None)
        (out/'worker.json').write_text(json.dumps({'error':error,'cleanup':cleanup})+'\n')
    return 0 if cleanup['status']=='PASS' else 1


def harness(out):
    out.mkdir(parents=True,exist_ok=False)
    ownership=LinuxOwnedChildren();processes=[];rows=[]
    try:
        sentinel=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],stdin=subprocess.DEVNULL)
        processes.append(sentinel)
        for mode in ('success','timeout','interruption'):
            directory=out/mode
            with (out/(mode+'.stdout')).open('xb') as stdout,(out/(mode+'.stderr')).open('xb') as stderr:
                child=subprocess.Popen([sys.executable,__file__,'--worker',mode,'--out',str(directory)],
                    stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
                processes.append(child)
                if mode=='interruption':
                    deadline=time.monotonic()+15
                    while not (directory/'owned-pids.json').exists() and child.poll() is None and time.monotonic()<deadline:
                        time.sleep(.02)
                    require((directory/'owned-pids.json').exists(),'actual helper did not start before interruption')
                    child.send_signal(signal.SIGTERM)
                require(child.wait(timeout=20)==0,'actual worker failed')
            state=json.loads((directory/'worker.json').read_bytes())
            wrapper=json.loads((directory/'commands/controlled-helper/receipt.json').read_bytes())
            require(state['cleanup']['status']=='PASS','worker cleanup failed')
            if mode=='success':
                require(state['error'] is None and wrapper['verification_status']=='PASS','successful helper was rejected')
                require((directory/'commands/controlled-helper/stdout.txt').read_bytes()==b'actual helper output\n','actual helper output differs')
            else:
                require(wrapper['verification_status']=='FAIL','failed helper falsely verified')
                require(state['error']==('TrialInterrupted' if mode=='interruption' else 'TimeoutExpired'),'wrong actual failure mode')
                pids=json.loads((directory/'owned-pids.json').read_bytes())
                require(len(pids)==2 and all(type(pid) is int and pid>0 for pid in pids),'actual owned PIDs missing')
                require(all(not Path('/proc',str(pid)).exists() for pid in pids),'owned session-changing helper survived')
                require((directory/'commands/controlled-helper/stdout.txt').read_bytes()==b'actual helper started\n',
                        'actual interrupted helper output missing')
                require((directory/'commands/controlled-helper/stderr.txt').read_bytes()==b'','actual helper stderr differs')
            require(sentinel.poll() is None,'worker cleanup killed the separate harness sentinel')
            rows.append({'case':mode,'status':'PASS','wrapper_status':wrapper['verification_status'],
                         'worker_cleanup':state['cleanup'],'separate_sentinel_survived':True})
    finally:
        cleanup=ownership.terminate(None)
        for child in processes:
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: cleanup.update(status='FAIL',error='control child still alive')
        restored=ownership.close()
        if restored['status']!='PASS': cleanup['status']='FAIL'
        (out/'cleanup.json').write_text(json.dumps(cleanup,indent=2)+'\n')
    require(cleanup['status']=='PASS','harness cleanup failed')
    result={'status':'PASS','cases':rows,'euid':os.geteuid(),'reference_qualified':False,
            'scope':'actual helper cleanup controls only; no VM boot/resource/reference evidence'}
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
    return 0


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--worker',choices=('success','timeout','interruption'))
    args=parser.parse_args()
    if not sys.platform.startswith('linux'):
        print(json.dumps({'status':'BLOCKED','reason':'actual Linux subreaper/pidfd controls required'}));return 77
    return worker(args.out.absolute(),args.worker) if args.worker else harness(args.out.absolute())


if __name__=='__main__': raise SystemExit(main())
