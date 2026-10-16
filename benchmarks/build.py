#!/usr/bin/env python3
"""Capture every build attempt and bind actual Cargo artifacts to source."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evidence import source_identity


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_product(out, *, profile='release'):
    out = out.resolve()
    if not out.is_relative_to(ROOT / '.local-runs'): raise ValueError('build evidence must remain in owned .local-runs')
    out.mkdir(parents=True, exist_ok=False)
    receipt = {'schema_version': 2, 'status': 'FAIL', 'exit_code': None, 'profile': profile,
               'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'stage': 'source identity',
               'source': None, 'source_after_sha256': None, 'bins': {}, 'problems': [],
               'fresh_target_directory': profile == 'release'}
    stdout, stderr, compiler_stdout, compiler_stderr = b'', b'', b'', b''
    try:
        if profile not in ('release', 'dev'): raise ValueError('unsupported build profile')
        receipt['source'] = source_identity(ROOT)
        receipt['cargo_lock_sha256'] = sha(ROOT / 'Cargo.lock')
        target = (ROOT / '.local-runs/t' / hashlib.sha256(out.relative_to(ROOT).as_posix().encode()).hexdigest()[:12]) if profile == 'release' else ROOT / 'target'
        receipt['target_directory'] = target.relative_to(ROOT).as_posix()
        if profile == 'release' and target.exists(): raise ValueError('preserve existing build target; choose a new evidence directory')
        env = os.environ.copy()
        for key in list(env):
            if (key.startswith('CARGO_PROFILE_') or key.endswith('_RUSTFLAGS')
                    or key in ('RUSTFLAGS', 'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                               'RUSTC_BOOTSTRAP', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTC')):
                env.pop(key)
        env['RUSTUP_TOOLCHAIN'] = '1.99.0'
        env['CARGO_TARGET_DIR'] = target.relative_to(ROOT).as_posix()
        receipt.update(stage='compiler discovery', command=['rustc', '--print', 'sysroot'])
        probe = subprocess.run(['rustc', '--print', 'sysroot'], cwd=ROOT, env=env, capture_output=True, check=True)
        compiler_path = Path(os.fsdecode(probe.stdout).strip()) / 'bin' / ('rustc.exe' if os.name == 'nt' else 'rustc')
        env.update(RUSTC=str(compiler_path), RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='', CARGO_ENCODED_RUSTFLAGS='')
        receipt['command'] = ['<selected-rustc>', '--version', '--verbose']
        actual = subprocess.run([str(compiler_path), '--version', '--verbose'], cwd=ROOT, env=env, capture_output=True, check=True)
        compiler_stdout, compiler_stderr = actual.stdout, actual.stderr
        compiler = actual.stdout.decode('utf-8')
        if not compiler.startswith('rustc 1.99.0 '): raise ValueError('actual compiler differs from pinned 1.99.0')
        receipt.update(compiler=compiler, rustc_executable_sha256=sha(compiler_path),
                       compiler_selection='explicit pinned sysroot executable passed as RUSTC',
                       compiler_configuration={'RUSTUP_TOOLCHAIN':'1.99.0', 'RUSTC_WRAPPER':'',
                                               'RUSTC_WORKSPACE_WRAPPER':'', 'CARGO_ENCODED_RUSTFLAGS':''})
        command = ['cargo', 'build', '--bins', '--locked', '--message-format=json-render-diagnostics', '--verbose']
        if profile == 'release': command.append('--release')
        receipt.update(command=command, stage='cargo build')
        process = subprocess.run(command, cwd=ROOT, env=env, capture_output=True)
        stdout, stderr = process.stdout, process.stderr
        receipt.update(exit_code=process.returncode, stage='artifact validation')
        for line in stdout.splitlines():
            value = json.loads(line)
            if value.get('reason') != 'compiler-artifact' or not value.get('executable'): continue
            if Path(value['manifest_path']).resolve() != ROOT / 'Cargo.toml': continue
            actual_profile = value['profile']
            opt, debug = ('3', False) if profile == 'release' else ('0', True)
            if actual_profile['opt_level'] != opt or actual_profile['debug_assertions'] is not debug or actual_profile['test']:
                raise ValueError('Cargo artifact differs from required build profile')
            executable = Path(value['executable']).resolve()
            if not executable.is_relative_to(target): raise ValueError('artifact escaped owned target')
            receipt['bins'][value['target']['name']] = {'path': executable.relative_to(ROOT).as_posix(),
                'sha256': sha(executable), 'actual_profile': actual_profile}
        receipt['source_after_sha256'] = source_identity(ROOT)['sha256']
        if process.returncode: raise ValueError('Cargo build failed')
        if receipt['source_after_sha256'] != receipt['source']['sha256']: raise ValueError('source changed during build')
        if set(receipt['bins']) != {'rillscope', 'rillscope-measure'}: raise ValueError('required actual Cargo artifacts missing')
        receipt.update(status='PASS', stage='complete')
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        receipt['problems'].append(type(error).__name__ + ': ' + str(error))
        if isinstance(error, subprocess.CalledProcessError):
            compiler_stdout, compiler_stderr = error.stdout or b'', error.stderr or b''
        try: receipt['source_after_sha256'] = source_identity(ROOT)['sha256']
        except (OSError, ValueError): pass
    for name, data in [('cargo.stdout', stdout), ('cargo.stderr', stderr),
                       ('compiler.stdout', compiler_stdout), ('compiler.stderr', compiler_stderr)]:
        (out / name).write_bytes(data)
    receipt.update(raw_stdout_sha256=sha(out / 'cargo.stdout'), raw_stderr_sha256=sha(out / 'cargo.stderr'),
                   raw_compiler_stdout_sha256=sha(out / 'compiler.stdout'), raw_compiler_stderr_sha256=sha(out / 'compiler.stderr'),
                   finished_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    (out / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    if receipt['status'] != 'PASS': raise ValueError('build attempt failed; structured receipt and raw evidence retained')
    return receipt


def build_release(out): return build_product(out, profile='release')


def verify_build(receipt_path, binary, *, name, root=ROOT, profile='release'):
    root = Path(root).resolve()
    receipt = json.loads(Path(receipt_path).read_bytes())
    if receipt.get('schema_version') != 2 or receipt.get('fresh_target_directory') is not (profile == 'release'):
        raise ValueError('unsupported or wrong freshness build receipt')
    if receipt.get('status') != 'PASS' or receipt.get('exit_code') != 0 or receipt.get('profile') != profile:
        raise ValueError('no passing actual required build receipt')
    if receipt['source']['sha256'] != source_identity(root)['sha256'] or receipt['source_after_sha256'] != receipt['source']['sha256']:
        raise ValueError('executable source differs from current source')
    if receipt['cargo_lock_sha256'] != sha(root / 'Cargo.lock'): raise ValueError('dependency lock differs from build')
    artifact = receipt['bins'][name]
    expected = (root / artifact['path']).resolve()
    target = (root / receipt['target_directory']).resolve()
    owned = root / ('.local-runs' if profile == 'release' else 'target')
    if not target.is_relative_to(owned) or not expected.is_relative_to(target) or Path(binary).resolve() != expected or sha(expected) != artifact['sha256']:
        raise ValueError('executable is not the source-bound required artifact')
    actual_profile = artifact['actual_profile']
    opt, debug = ('3', False) if profile == 'release' else ('0', True)
    if actual_profile['opt_level'] != opt or actual_profile['debug_assertions'] is not debug or actual_profile['test']:
        raise ValueError('wrong actual build profile')
    if (receipt.get('compiler_selection') != 'explicit pinned sysroot executable passed as RUSTC'
            or not receipt.get('compiler', '').startswith('rustc 1.99.0 ')
            or receipt.get('compiler_configuration') != {'RUSTUP_TOOLCHAIN':'1.99.0', 'RUSTC_WRAPPER':'',
                'RUSTC_WORKSPACE_WRAPPER':'', 'CARGO_ENCODED_RUSTFLAGS':''}):
        raise ValueError('actual compiler/configuration binding missing')
    for stream in ('stdout', 'stderr'):
        if sha(Path(receipt_path).parent / ('cargo.' + stream)) != receipt['raw_' + stream + '_sha256']:
            raise ValueError('raw build output digest mismatch')
        if sha(Path(receipt_path).parent / ('compiler.' + stream)) != receipt['raw_compiler_' + stream + '_sha256']:
            raise ValueError('raw compiler probe output digest mismatch')
    if (Path(receipt_path).parent / 'compiler.stdout').read_text(encoding='utf-8') != receipt['compiler']:
        raise ValueError('recorded compiler differs from actual probe bytes')
    return receipt


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = build_release(args.out)
    print(json.dumps({'status': result['status'], 'bins': result['bins'], 'source_sha256': result['source']['sha256']}))
    return 0


if __name__ == '__main__': raise SystemExit(main())
