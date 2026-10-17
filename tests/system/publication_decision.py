#!/usr/bin/env python3
"""Exercise both sides of the CLI's final decision in an unchanged Linux build.

GDB delivers a real SIGINT at a source-bound stop and observes the handler's
rt_sigreturn syscall. No flag/memory patch, product hook, privilege change or
network access is used. This records terminal commitment, not atomic transport.
Signal command: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Signaling.html
Run arguments: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Arguments.html
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from evidence import run_owned
from product_build import bound_binary, BINARY


DRIVER = r'''
import gdb
import json
from pathlib import Path
import re
import shlex

config = json.loads(CONFIG_JSON)
out = Path(config['out'])
stdout = out / 'stdout.bin'
stderr = out / 'stderr.bin'
exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('set disable-randomization off')
gdb.execute('set debuginfod enabled off')
gdb.execute('handle SIGINT nostop print pass')
gdb.execute('handle SIGTERM nostop print pass')
point = gdb.Breakpoint(config['source'] + ':' + str(config['line']), internal=True)
# Redirection is itself a run argument. Supply the complete inferior argument
# list here: a run command with arguments replaces those saved by --args.
gdb.execute('run ' + shlex.join(config['inferior_args']) + ' > ' + shlex.quote(str(stdout)) + ' 2> ' + shlex.quote(str(stderr)))
if point.hit_count != 1:
    raise RuntimeError('required final-decision breakpoint was not hit once')
sal = gdb.newest_frame().find_sal()
if sal.line != config['line'] or Path(sal.symtab.fullname()).resolve() != Path(config['source']).resolve():
    raise RuntimeError('debug stop does not match the bound source decision line')
if stdout.stat().st_size != 0 or stderr.stat().st_size != 0:
    raise RuntimeError('product emitted bytes before the controlled decision stop')
record = {'case':config['case'], 'stopped_source_line':sal.line,
          'stdout_bytes_at_decision_stop':stdout.stat().st_size,
          'instruction_window':gdb.execute('x/16i $pc', to_string=True),
          'signal_method':None, 'handler_return_syscall_observed':False}
(out / 'decision-function-disassembly.txt').write_text(gdb.execute('disassemble /r',to_string=True))
point.delete()
if config['signal']:
    before = set(gdb.breakpoints() or [])
    gdb.execute('catch syscall rt_sigreturn')
    added = set(gdb.breakpoints() or []) - before
    if len(added) != 1:
        raise RuntimeError('cannot identify the owned signal-return catchpoint')
    catch = added.pop()
    signal_output = gdb.execute('signal ' + config['signal'], to_string=True)
    (out / 'signal-stop.txt').write_text(signal_output)
    if catch.hit_count != 1 or not re.search(r'Catchpoint\s+\d+\s+\(call to syscall [\'\"]?rt_sigreturn', signal_output):
        raise RuntimeError('actual signal handler return was not observed')
    if stdout.stat().st_size != 0 or stderr.stat().st_size != 0:
        raise RuntimeError('output escaped before the controlled handler returned')
    record.update(signal_method='GDB signal ' + config['signal'] + ' to the owned stopped inferior',
                  handler_return_syscall_observed=True,
                  stdout_bytes_at_handler_return=stdout.stat().st_size)
    catch.delete()
gdb.execute('continue')
if len(exits) != 1:
    raise RuntimeError('unexpected actual inferior exit status: ' + repr(exits))
record['inferior_exit_code'] = exits[0]
(out / 'debugger-observation.json').write_text(json.dumps(record, indent=2) + '\n')
gdb.execute('quit 0')
'''


def decision_line(anchor):
    lines = (ROOT / 'src/main.rs').read_text(encoding='utf-8').splitlines()
    matches = [number for number, line in enumerate(lines, 1) if line.strip() == anchor]
    if len(matches) != 1:
        raise ValueError('the final decision source anchor is not unique')
    return matches[0]


def observe(out, case, line, deliver_signal, expected_exit):
    out.mkdir()
    catalog = {'version':1, 'snapshot':'synthetic-publication-decision', 'tables':{'t':{
        'columns':[{'name':'tenant','type':'text','nullable':False},
                   {'name':'id','type':'i64','nullable':False}], 'rows':[['alpha',7],['other',99]]}}}
    context = {'version':1, 'tenant':'alpha', 'policy_revision':'synthetic-decision-r1',
               'tables':{'t':{'tenant_column':'tenant','columns':['id']}}}
    query = {'version':1, 'plan':{'op':'project', 'input':{'op':'scan','table':'t','alias':'s'},
                                'columns':[{'name':'id','expr':{'col':'s.id'}}]}}
    for name, value in (('catalog',catalog), ('context',context), ('query',query)):
        (out / (name + '.json')).write_text(json.dumps(value) + '\n')
    inferior_args = ['run', '--catalog', str(out / 'catalog.json'),
                     '--context', str(out / 'context.json'), '--query', str(out / 'query.json')]
    config = {'out':str(out), 'case':case, 'source':str(ROOT / 'src/main.rs'),
              'line':line, 'signal':deliver_signal, 'expected_exit':expected_exit,'inferior_args':inferior_args}
    driver = out / 'control.py'
    driver.write_text(DRIVER.replace('CONFIG_JSON', repr(json.dumps(config))), encoding='utf-8')
    if any(value in str(driver) for value in ('\r','\n')):
        raise ValueError('debugger command-file path contains a line break')
    args = [str(BINARY), *inferior_args]
    command = [shutil.which('gdb'), '--nx', '--batch', '-iex', 'set auto-load off',
               '-ex', 'source ' + str(driver), '--args', *args]
    # Disable network debuginfo lookup and preserve ordinary ASLR. Tracing must be
    # allowed already; no ptrace, seccomp or administrator policy is modified.
    env_keys = ('PATH','HOME','LANG','LC_ALL','TMPDIR')
    env = {key:os.environ[key] for key in env_keys if key in os.environ}
    env['DEBUGINFOD_URLS'] = ''
    # run_owned has process-group cleanup on success and failure. Its subprocess
    # environment is inherited, so temporarily provide only this explicit set.
    previous = os.environ.copy()
    try:
        os.environ.clear(); os.environ.update(env)
        code, stdout, stderr, outcome, cleanup = run_owned(command, cwd=ROOT, timeout=60, stdin_data=None)
    finally:
        os.environ.clear(); os.environ.update(previous)
    (out / 'gdb.stdout.txt').write_bytes(stdout)
    (out / 'gdb.stderr.txt').write_bytes(stderr)
    (out / 'process.json').write_text(json.dumps({'exit_code':code,'outcome':outcome,'cleanup':cleanup}, indent=2)+'\n')
    if code != 0 or outcome != 'EXECUTED':
        raise RuntimeError('debugger experiment did not complete; preserve raw diagnostics')
    observation_path = out / 'debugger-observation.json'
    if not observation_path.is_file():
        raise RuntimeError('GDB produced no boundary observation; inspect retained gdb.stdout.txt/gdb.stderr.txt')
    observed = json.loads(observation_path.read_bytes())
    payload = (out / 'stdout.bin').read_bytes()
    if (out / 'stderr.bin').read_bytes():
        raise RuntimeError('unexpected product stderr')
    response = json.loads(payload)
    if observed['inferior_exit_code'] != expected_exit:
        raise RuntimeError('actual terminal exit differs: expected ' + str(expected_exit) + ', observed ' + str(observed['inferior_exit_code']))
    if payload.count(b'\n') != 1 or not payload.endswith(b'\n') or response.get('implementation') != 'rust':
        raise RuntimeError('product did not emit exactly one Rust terminal object')
    if expected_exit == 4:
        if response.get('status') != 'error' or response.get('error',{}).get('code') != 'E_CANCELLED' or 'rows' in response:
            raise RuntimeError('signal before final commitment did not return only E_CANCELLED')
    elif response.get('status') != 'ok' or response.get('rows') != [[7]]:
        raise RuntimeError('committed success differs from the independent expected authorized row')
    result = {**observed, 'status':'PASS', 'response_status':response['status'],
              'retained_stdout_bytes':len(payload), 'stdout_sha256':hashlib.sha256(payload).hexdigest(),
              'qualification':'explicit final atomic decision boundary; no transport atomicity or latency target'}
    (out / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--before-sigint-only',action='store_true',help='bounded behavioral mutation control; default runs both signals on both sides')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or shutil.which('gdb') is None:
        print(json.dumps({'status':'BLOCKED','reason':'actual Linux x86_64 and permitted existing GDB required'})); return 77
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / '.local-runs') or out.exists():
        raise ValueError('new owned experiment output required')
    build = bound_binary(); out.mkdir(parents=True)
    try:
        before = decision_line('if flag.load(Ordering::Acquire) {')
        after = decision_line('let (bytes, code) = match outcome {')
        results = [observe(out / 'no-signal', 'no-signal', before, None, 0)]
        for name in (('SIGINT',) if args.before_sigint_only else ('SIGINT','SIGTERM')):
            case = 'before-commit-' + name.lower()
            results.append(observe(out / case,case,before,name,4))
            if not args.before_sigint_only:
                case = 'after-commit-before-write-' + name.lower()
                results.append(observe(out / case,case,after,name,0))
        summary = {'status':'PASS', 'campaign':'actual-final-publication-decision',
                   'binary_sha256':build['bins']['rillscope']['sha256'], 'source_sha256':build['source']['sha256'],
                   'gdb_version':subprocess.check_output([shutil.which('gdb'),'--version'],text=True,timeout=10).splitlines()[0],
                   'gdb_sha256':hashlib.sha256(Path(shutil.which('gdb')).read_bytes()).hexdigest(),
                   'selected_case_scope':'no-signal and before-SIGINT control only' if args.before_sigint_only else 'no-signal and both sides for SIGINT/SIGTERM',
                   'results':results, 'contract_qualification':'NOT ESTABLISHED: AC-018 clarification disposition and independent assessment required',
                   'scope':'unchanged Rust build; actual signals before/after terminal commitment; experiment observations only, no AC-018 compliance or latency claim'}
        (out / 'summary.json').write_text(json.dumps(summary,indent=2)+'\n'); print(json.dumps(summary,indent=2)); return 0
    except Exception as error:
        (out / 'failure.json').write_text(json.dumps({'status':'FAIL','reason':str(error),'error':type(error).__name__},indent=2)+'\n')
        raise


if __name__ == '__main__': raise SystemExit(main())
