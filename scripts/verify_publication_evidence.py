#!/usr/bin/env python3
"""Recheck actual synthetic CI boundary records; execute no product queries.

The public API associates the artifact digest with a completed job/run. Recorded
debugger instructions still require human/independent inspection; this checker
does not infer a cancellation contract from an observed successful response.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import zipfile

from evidence import source_identity
from verify_ci_observations import REPOSITORY, public_api

ROOT = Path(__file__).resolve().parents[1]
CASES = {'no-signal':0, 'before-commit-sigint':4, 'before-commit-sigterm':4,
         'after-commit-before-write-sigint':0, 'after-commit-before-write-sigterm':0}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Records:
    def __init__(self, path):
        self.archive = zipfile.ZipFile(path)
        entries = self.archive.infolist()
        require(0 < len(entries) <= 5000, 'artifact member count exceeds bound')
        self.names = set()
        folded, size = set(), 0
        for entry in entries:
            name = entry.filename
            relative = PurePosixPath(name)
            require(not relative.is_absolute() and relative.parts and '..' not in relative.parts
                    and '\\' not in name and ':' not in name and '\x00' not in name,
                    'invalid artifact member path')
            require(name.casefold() not in folded, 'duplicate artifact member')
            folded.add(name.casefold())
            mode = stat.S_IFMT(entry.external_attr >> 16)
            require(mode in (0, stat.S_IFREG, stat.S_IFDIR), 'non-regular artifact member')
            require(not entry.flag_bits & 1 and entry.file_size <= 8*1024**2,
                    'encrypted or oversized artifact member')
            size += entry.file_size
            if not entry.is_dir():
                self.names.add(name)
        require(size <= 64*1024**2, 'uncompressed artifact exceeds bound')
        require(self.archive.testzip() is None, 'artifact member CRC check failed')

    def read(self, name):
        require(name in self.names, 'required artifact member missing: ' + name)
        return self.archive.read(name)

    def value(self, name):
        return json.loads(self.read(name))

    def one(self, prefix, suffix):
        names = [name for name in self.names if name.startswith(prefix) and name.endswith(suffix)]
        require(len(names) == 1, 'expected one artifact member for ' + prefix + suffix)
        return names[0]


def source_check(build, expected, records, prefix):
    require(build['status'] == 'PASS' and build['exit_code'] == 0 and build['problems'] == []
            and type(build['fresh_target_directory']) is bool and build['profile'] == 'dev' and build['schema_version'] == 2,
            'source-bound successful build missing')
    require(build['source'] == expected and build['source_after_sha256'] == expected['sha256'],
            'recorded build differs from frozen source')
    require(build['cargo_lock_sha256'] == dict(expected['files'])['Cargo.lock']
            and build['compiler_selection'] == 'explicit pinned sysroot executable passed as RUSTC'
            and build['compiler_configuration'] == {'RUSTUP_TOOLCHAIN':'1.99.0', 'RUSTC_WRAPPER':'',
                                                   'RUSTC_WORKSPACE_WRAPPER':'', 'CARGO_ENCODED_RUSTFLAGS':''}
            and build['compiler'].startswith('rustc 1.99.0 ')
            and 'host: x86_64-unknown-linux-gnu\n' in build['compiler'], 'compiler/lock binding differs')
    require(records.read(prefix+'/compiler.stdout').decode() == build['compiler'], 'compiler probe text differs')
    require(set(build['bins']) == {'rillscope','rillscope-measure'}, 'recorded Cargo binary set differs')
    artifacts = {}
    for line in records.read(prefix+'/cargo.stdout').splitlines():
        value = json.loads(line)
        if value.get('reason') == 'compiler-artifact' and value.get('executable'):
            artifacts[value['target']['name']] = value
    for name, binary in build['bins'].items():
        profile = {'opt_level':'0','debuginfo':2,'debug_assertions':True,'overflow_checks':True,'test':False}
        require(binary['actual_profile'] == profile and artifacts[name]['profile'] == profile
                and re.fullmatch('[0-9a-f]{64}',binary['sha256'])
                and artifacts[name]['executable'].endswith('/'+binary['path']), 'actual dev build profile differs')
    for stream in ('stdout', 'stderr'):
        require(digest(records.read(prefix + '/cargo.' + stream)) == build['raw_' + stream + '_sha256'],
                'raw build output digest mismatch')
        require(digest(records.read(prefix + '/compiler.' + stream)) == build['raw_compiler_' + stream + '_sha256'],
                'raw compiler probe digest mismatch')


def driver_template(source):
    tree = ast.parse((source/'tests/system/publication_decision.py').read_text(encoding='utf-8'))
    values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
              and any(isinstance(target,ast.Name) and target.id == 'DRIVER' for target in node.targets)]
    require(len(values) == 1 and isinstance(values[0],str), 'recorded driver template missing')
    return values[0]


def check_case(records, prefix, name, expected_exit, template, source_text, configured_exit=None):
    base = prefix + '/' + name
    observed = records.value(base + '/debugger-observation.json')
    process = records.value(base + '/process.json')
    driver = records.read(base+'/control.py').decode()
    config_values = [node.value.args[0].value for node in ast.parse(driver).body
                     if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id == 'config' for target in node.targets)
                     and isinstance(node.value,ast.Call) and len(node.value.args) == 1
                     and isinstance(node.value.args[0],ast.Constant)]
    require(len(config_values) == 1, 'retained driver configuration missing')
    config = json.loads(config_values[0])
    expected_signal = None if name == 'no-signal' else ('SIGTERM' if name.endswith('sigterm') else 'SIGINT')
    anchor = 'let (bytes, code) = match outcome {' if name.startswith('after-') else 'if flag.load(Ordering::Acquire) {'
    lines = [number for number,line in enumerate(source_text.splitlines(),1) if line.strip() == anchor]
    require(len(lines) == 1 and observed['stopped_source_line'] == config['line'] == lines[0]
            and config['case'] == name and config['signal'] == expected_signal
            and config['expected_exit'] == (expected_exit if configured_exit is None else configured_exit),
            'case signal/source configuration differs')
    require(driver == template.replace('CONFIG_JSON',repr(json.dumps(config))), 'retained driver differs from captured source')
    require(PurePosixPath(config['out']).name == name and config['source'].endswith('/src/main.rs')
            and config['inferior_args'] == ['run','--catalog',config['out']+'/catalog.json',
                '--context',config['out']+'/context.json','--query',config['out']+'/query.json'], 'inferior argument binding differs')
    require(observed['signal_method'] == (None if expected_signal is None else
            'GDB signal '+expected_signal+' to the owned stopped inferior'), 'actual signal identity differs')
    require(records.value(base+'/catalog.json') == {'version':1,'snapshot':'synthetic-publication-decision',
            'tables':{'t':{'columns':[{'name':'tenant','type':'text','nullable':False},
                                     {'name':'id','type':'i64','nullable':False}], 'rows':[['alpha',7],['other',99]]}}}
            and records.value(base+'/context.json') == {'version':1,'tenant':'alpha',
            'policy_revision':'synthetic-decision-r1','tables':{'t':{'tenant_column':'tenant','columns':['id']}}}
            and records.value(base+'/query.json') == {'version':1,'plan':{'op':'project',
            'input':{'op':'scan','table':'t','alias':'s'},'columns':[{'name':'id','expr':{'col':'s.id'}}]}},
            'captured synthetic inputs differ from independent case expectation')
    require(process['exit_code'] == 0 and process['outcome'] == 'EXECUTED'
            and process['cleanup']['status'] == 'PASS', 'debugger did not complete with cleanup')
    require(observed['case'] == name and observed['stdout_bytes_at_decision_stop'] == 0
            and type(observed['inferior_exit_code']) is int and observed['inferior_exit_code'] == expected_exit,
            'terminal decision/exit differs from expected behavior')
    require(observed['instruction_window'].startswith('=> ') and len(records.read(base + '/decision-function-disassembly.txt')) > 100,
            'actual instruction diagnostics missing')
    if name != 'no-signal':
        stop = records.value(base + '/signal-stop.json')
        require(observed['handler_return_syscall_observed'] is True
                and observed['handler_return_stop'] == stop and observed['stdout_bytes_at_handler_return'] == 0,
                'handled signal/empty output observation missing')
        require(type(stop['orig_rax']) is int and stop['orig_rax'] == 15 and stop['catchpoint_hit_count'] == 1
                and len(stop['stops']) == 1, 'actual signal return syscall missing')
        event = stop['stops'][0]
        require(event['details'].get('reason') == 'syscall-entry'
                and event['details'].get('syscall-name') == 'rt_sigreturn'
                and event['details'].get('syscall-number') == '15'
                and event['breakpoint_numbers'] == [stop['catchpoint_number']], 'signal return stop differs')
    payload = records.read(base + '/stdout.bin')
    require(payload.endswith(b'\n') and payload.count(b'\n') == 1
            and records.read(base + '/stderr.bin') == b'', 'terminal response framing differs')
    value = json.loads(payload)
    require(value.get('version') == 1 and value.get('implementation') == 'rust', 'non-Rust response')
    if expected_exit == 4:
        require(value == {'version':1,'status':'error','error':{'code':'E_CANCELLED','phase':'execute',
                'message':'query cancelled'},'implementation':'rust'}, 'predecision response is not one cancellation object')
    else:
        require(value.get('status') == 'ok' and value.get('rows') == [[7]]
                and value.get('schema') == [{'name':'id','type':'i64','nullable':False}]
                and 'error' not in value, 'success differs from independent authorized expectation')
    return observed, digest(payload)


def verify_records(records, source, commit):
    require(subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip() == commit
            and not subprocess.check_output(['git','status','--porcelain'],cwd=source).strip(),
            'exact clean recorded-source checkout required')
    expected = source_identity(source)
    template = driver_template(source)
    source_text = (source/'src/main.rs').read_text(encoding='utf-8')
    build_names = [name for name in records.names if re.fullmatch(r'build/[^/]+/build.json',name)]
    require(build_names, 'recorded product build missing')
    builds = []
    for name in sorted(build_names):
        build = records.value(name)
        source_check(build,expected,records,name.rsplit('/',1)[0])
        builds.append(build)
    product = lambda name: name.startswith('src/') or name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml')
    require({name:sha for name,sha in expected['files'] if product(name)} ==
            {name:sha for name,sha in source_identity(ROOT)['files'] if product(name)},
            'current Rust product differs from recorded build')
    decision_name = records.one('publication-decision-', '/summary.json')
    decision_prefix = decision_name.rsplit('/',1)[0]
    summary = records.value(decision_name)
    require(summary['status'] == 'PASS' and summary['campaign'] == 'actual-final-publication-decision'
            and summary['source_sha256'] == expected['sha256']
            and summary['binary_sha256'] in {build['bins']['rillscope']['sha256'] for build in builds},
            'decision summary/build binding differs')
    require({row['case'] for row in summary['results']} == set(CASES) and len(summary['results']) == len(CASES),
            'both sides of both signals and no-signal control required')
    hashes, instructions = {}, {}
    for name, code in CASES.items():
        observed, hashes[name] = check_case(records,decision_prefix,name,code,template,source_text)
        selected = next(row for row in summary['results'] if row['case'] == name)
        require(all(selected.get(key) == value for key,value in observed.items())
                and selected['status'] == 'PASS' and selected['stdout_sha256'] == hashes[name],
                'decision summary differs from raw observation')
        instructions[name] = digest(records.read(decision_prefix+'/'+name+'/decision-function-disassembly.txt'))
    control_names = [name for name in records.names if re.fullmatch(r'publication-control-[^/]+/summary.json',name)]
    require(len(control_names) == 1, 'expected one top-level behavioral control summary')
    control_name = control_names[0]
    control_prefix = control_name.rsplit('/',1)[0]
    control = records.value(control_name)
    require(control['status'] == 'PASS' and control['source_commit'] == commit
            and control['sequence'] == ['PASS','FAIL','PASS']
            and control['original_repository_source_unchanged'] is True
            and control['mutant_returned_authorized_success_after_handled_predecision_signal'] is True,
            'actual behavioral PASS-FAIL-PASS control missing')
    original = records.read(control_prefix+'/source.before.rs')
    mutant = records.read(control_prefix+'/source.mutant.rs')
    anchor = b'if flag.load(Ordering::Acquire) {\n                        Err(E::Cancelled.into())'
    require(original == (source/'src/main.rs').read_bytes() and original.count(anchor) == 1
            and mutant == original.replace(anchor,anchor.replace(b'Err(E::Cancelled.into())',b'Ok(bytes)')),
            'mutation changes more than final cancellation conversion')
    require(control['source_original_sha256'] == control['source_restored_sha256'] == digest(original)
            and control['source_mutant_sha256'] == digest(mutant), 'control source identities differ')
    changed_files = [[name,digest(mutant) if name == 'src/main.rs' else sha] for name,sha in expected['files']]
    changed = {'files':changed_files,'sha256':digest(json.dumps(changed_files,separators=(',',':')).encode())}
    expected_labels = ['baseline-build','baseline','mutant-build','mutant','restored-build','restored']
    require([row['label'] for row in control['commands']] == expected_labels, 'control command sequence differs')
    for row in control['commands']:
        base = control_prefix+'/commands/'+row['label']
        receipt = records.value(base+'/receipt.json')
        status = 'FAIL' if row['label'] == 'mutant' else 'PASS'
        expected_source = changed if row['label'].startswith('mutant') else expected
        require(row['status'] == receipt['verification_status'] == status
                and row['exit_code'] == receipt['exit_code'] == (1 if status == 'FAIL' else 0)
                and receipt['source_before'] == expected_source
                and row['source_sha256'] == receipt['source_after_sha256'] == expected_source['sha256'],
                'control command expected source lineage differs')
        for stream in ('stdout','stderr'):
            require(row[stream+'_sha256'] == receipt[stream]['sha256'] == digest(records.read(base+'/'+stream+'.txt')),
                    'control raw output digest differs')
    stage_builds = {}
    for label in ('baseline','mutant','restored'):
        output = records.value(control_prefix+'/commands/'+label+'-build/stdout.txt')
        expected_source = changed if label == 'mutant' else expected
        build_name = control_prefix+'/checkout/'+output['build_receipt']
        build = records.value(build_name)
        source_check(build,expected_source,records,build_name.rsplit('/',1)[0])
        require(output['status'] == 'PASS' and output['source_sha256'] == expected_source['sha256']
                and output['binary_sha256'] == build['bins']['rillscope']['sha256'], 'control build/result association differs')
        stage_builds[label] = build
        scope = control_prefix+'/checkout/.local-runs/'+label
        if label != 'mutant':
            stage = records.value(scope+'/summary.json')
            require(stage['status'] == 'PASS' and stage['source_sha256'] == expected_source['sha256']
                    and stage['binary_sha256'] == output['binary_sha256']
                    and [case['case'] for case in stage['results']] == ['no-signal','before-commit-sigint'],
                    'control experiment/build association differs')
        check_case(records,scope,'no-signal',0,template,source_text)
        check_case(records,scope,'before-commit-sigint',0 if label == 'mutant' else 4,
                   template,source_text,configured_exit=4)
    require(stage_builds['baseline']['bins']['rillscope']['sha256'] == stage_builds['restored']['bins']['rillscope']['sha256'],
            'restored control binary identity differs')
    require(b'actual terminal exit differs: expected 4, observed 0' in records.read(control_prefix+'/commands/mutant/stderr.txt'),
            'mutant failed for a different reason')
    return {'status':'PASS','campaign':'recorded-final-cancellation-validation','cases':len(CASES),
            'signals':['SIGINT','SIGTERM'],'binary_sha256':summary['binary_sha256'],
            'source_sha256':expected['sha256'],'current_product_source_matches_capture':True,
            'behavioral_control_sequence':control['sequence'],'terminal_stdout_sha256':hashes,
            'instruction_disassembly_sha256':instructions,
            'recorded_dev_fresh_target_flags':[build['fresh_target_directory'] for build in builds],
            'contract_qualification':'recorded observations only; explicit clarification and independent instruction assessment remain separate',
            'scope':'all bounded artifact members/selected source and raw responses checked; no new product execution or reference-host target'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--commit',required=True); parser.add_argument('--job-id',type=int,required=True)
    parser.add_argument('--artifact-id',type=int,required=True); parser.add_argument('--zip',type=Path,required=True)
    parser.add_argument('--source-checkout',type=Path,required=True); args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}',args.commit) and args.job_id > 0 and args.artifact_id > 0,
            'explicit recorded commit/job/artifact required')
    require(args.zip.stat().st_size <= 16*1024**2,'compressed artifact exceeds bound')
    job = public_api('/actions/jobs/'+str(args.job_id))
    run = public_api('/actions/runs/'+str(job['run_id']))
    artifact = public_api('/actions/artifacts/'+str(args.artifact_id))
    require(job['status'] == 'completed' and job['conclusion'] == 'success'
            and job['name'] == 'publication-boundary' and 'ubuntu-24.04' in job['labels']
            and run['head_sha'] == args.commit and run['repository']['full_name'] == REPOSITORY
            and artifact['name'] == 'publication-boundary-observations'
            and artifact['workflow_run']['id'] == job['run_id']
            and artifact['workflow_run']['head_sha'] == args.commit, 'actual public job/artifact association differs')
    archive_sha = digest(args.zip.read_bytes())
    require(artifact['digest'] == 'sha256:'+archive_sha, 'download differs from actual public artifact digest')
    records = Records(args.zip)
    try:
        result = verify_records(records,args.source_checkout.resolve(),args.commit)
    finally:
        records.archive.close()
    result.update(remote_repository=REPOSITORY,remote_commit=args.commit,remote_run_id=job['run_id'],
                  remote_job_id=job['id'],remote_job_name=job['name'],remote_job_conclusion=job['conclusion'],
                  remote_workflow_conclusion=run['conclusion'],remote_runner_labels=job['labels'],
                  remote_artifact_id=args.artifact_id,remote_artifact_sha256=archive_sha)
    print(json.dumps(result,indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
