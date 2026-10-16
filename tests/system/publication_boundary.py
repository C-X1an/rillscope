#!/usr/bin/env python3
"""Observe Linux stdout boundaries; the observations do not settle AC-018 wording.

strace -D keeps the tracee a direct child: https://man7.org/linux/man-pages/man1/strace.1.html
No debugger policy, account, privileges, signal handling or product source is changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT / 'scripts'))
from product_build import bound_binary, BINARY
from owned_process import terminate_posix_group


def observe(out, close_reader):
    import fcntl
    out.mkdir()
    literal = 'S' * 4096
    catalog = {'version':1,'snapshot':'synthetic-publication-boundary','tables':{'t':{
        'columns':[{'name':'tenant','type':'text','nullable':False}], 'rows':[['alpha'] for _ in range(128)]}}}
    context = {'version':1,'tenant':'alpha','policy_revision':'synthetic-boundary-r1',
               'tables':{'t':{'tenant_column':'tenant','columns':['tenant']}}}
    query = {'version':1,'plan':{'op':'project','input':{'op':'scan','table':'t','alias':'s'},
             'columns':[{'name':'x','expr':{'lit':literal}}]}}
    for name,value in (('catalog',catalog),('context',context),('query',query)):
        (out / (name + '.json')).write_text(json.dumps(value))
    trace = out / 'trace.log'
    command = [shutil.which('strace'),'-D','-qq','-ttt','-e','trace=write,rt_sigreturn','-e','signal=SIGINT',
               '-o',str(trace),str(BINARY),'run','--catalog',str(out / 'catalog.json'),
               '--context',str(out / 'context.json'),'--query',str(out / 'query.json')]
    read_fd,write_fd = os.pipe()
    fcntl.fcntl(write_fd,fcntl.F_SETPIPE_SZ,4096)
    capacity = fcntl.fcntl(write_fd,fcntl.F_GETPIPE_SZ)
    os.set_blocking(read_fd,False)
    env = {key:os.environ[key] for key in ('PATH','HOME','LANG','LC_ALL','TMPDIR') if key in os.environ}
    child = None; payload = bytearray(); stderr = b''; sent = None; handled = False; reader_closed = False
    try:
        child = subprocess.Popen(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=write_fd,
                                 stderr=subprocess.PIPE,start_new_session=True)
        os.close(write_fd); write_fd = -1
        if not select.select([read_fd],[],[],10)[0]: raise RuntimeError('no live response prefix')
        payload.extend(os.read(read_fd,256))
        prefix_bytes = len(payload)
        prefix_at = time.perf_counter_ns()
        if not payload or child.poll() is not None: raise RuntimeError('publication did not block with a visible prefix')
        if Path('/proc/' + str(child.pid) + '/exe').resolve() != BINARY.resolve():
            raise RuntimeError('strace did not retain the owned Rust tracee PID')
        if close_reader:
            os.close(read_fd); reader_closed = True
        else:
            previous_trace = trace.stat().st_size
            sent = time.perf_counter_ns(); child.send_signal(signal.SIGINT)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                tail = trace.read_text()[previous_trace:]
                position = tail.find('SIGINT')
                if position >= 0 and 'rt_sigreturn' in tail[position:]:
                    handled = True; break
                time.sleep(.01)
            if not handled: raise RuntimeError('SIGINT delivery and handler return not observed in owned trace')
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if not select.select([read_fd],[],[],.25)[0]: continue
                block = os.read(read_fd,65536)
                if not block: break
                payload.extend(block)
                if len(payload) > 1048577: raise RuntimeError('response exceeds locked byte cap')
            else: raise RuntimeError('stdout did not finish after draining')
        _,stderr = child.communicate(timeout=5)
        (out / 'stdout.bin').write_bytes(payload); (out / 'stderr.bin').write_bytes(stderr)
        if stderr: raise RuntimeError('unexpected tracer/product stderr')
        if close_reader:
            if child.returncode != 6: raise RuntimeError('closed output channel did not return transport failure')
            terminal = 'TRUNCATED OUTPUT AFTER READER CLOSED'
        else:
            value = json.loads(payload)
            if (child.returncode != 0 or value.get('status') != 'ok' or value.get('implementation') != 'rust'
                    or value.get('rows') != [[literal] for _ in range(128)]):
                raise RuntimeError('post-publication signal outcome differs from predicted complete success')
            terminal = 'COMPLETE SUCCESS AFTER SIGNAL FOLLOWING VISIBLE PREFIX'
        result = {'experiment_status':'RECORDED','pipe_capacity_bytes':capacity,'visible_prefix_bytes':prefix_bytes,
                  'prefix_observed_ns':prefix_at,'signal_sent_ns':sent,'signal_handler_return_traced':handled,
                  'exit_code':child.returncode,'retained_stdout_bytes':len(payload),
                  'stdout_sha256':hashlib.sha256(payload).hexdigest(),'trace_sha256':hashlib.sha256(trace.read_bytes()).hexdigest(),
                  'observed_terminal':terminal,
                  'qualification':'observation after publication began; not an AC-018 PASS or latency target'}
        (out / 'result.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    except Exception as error:
        (out / 'failure.json').write_text(json.dumps({'status':'FAIL','error':type(error).__name__,
                                                    'reason':str(error)},indent=2)+'\n')
        raise
    finally:
        if write_fd >= 0: os.close(write_fd)
        if not reader_closed: os.close(read_fd)
        if child is not None:
            terminate_posix_group(child.pid)
            if child.poll() is None: child.kill()
            child.wait(timeout=5)
        (out / 'stdout.bin').write_bytes(payload)
        (out / 'stderr.bin').write_bytes(stderr)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out',type=Path,required=True); args = parser.parse_args()
    if platform.system() != 'Linux' or shutil.which('strace') is None:
        print(json.dumps({'status':'BLOCKED','reason':'actual Linux and permitted existing strace required'})); return 77
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / '.local-runs') or out.exists(): raise ValueError('new owned experiment output required')
    build = bound_binary(); out.mkdir(parents=True)
    results = [observe(out / 'signal-after-prefix',False),observe(out / 'reader-closed-after-prefix',True)]
    summary = {'experiment_status':'RECORDED','binary_sha256':build['bins']['rillscope']['sha256'],
               'source_sha256':build['source']['sha256'],'results':results,
               'scope':'actual traced transport observations; publication contract interpretation remains open'}
    (out / 'summary.json').write_text(json.dumps(summary,indent=2)+'\n'); print(json.dumps(summary,indent=2)); return 0


if __name__ == '__main__': raise SystemExit(main())
