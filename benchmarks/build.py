#!/usr/bin/env python3
"""Build into a new target directory and bind actual Cargo artifacts to source."""
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


def build_release(out):
    out = out.resolve()
    if not out.is_relative_to(ROOT / '.local-runs'): raise ValueError('build evidence must remain in owned .local-runs')
    out.mkdir(parents=True, exist_ok=False)
    before = source_identity(ROOT)
    target = ROOT / '.local-runs/t' / hashlib.sha256(out.relative_to(ROOT).as_posix().encode()).hexdigest()[:12]
    if target.exists(): raise ValueError('preserve existing build target; select a new build evidence directory')
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('CARGO_PROFILE_') or key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP', 'CARGO_BUILD_TARGET'):
            env.pop(key)
    # Short relative paths also work with the pinned Windows GNU linker; no OS policy changes.
    env['CARGO_TARGET_DIR'] = target.relative_to(ROOT).as_posix()
    compiler = subprocess.check_output(['rustc', '--version', '--verbose'], cwd=ROOT, env=env, text=True)
    if not compiler.startswith('rustc 1.99.0 '): raise ValueError('actual compiler differs from pinned 1.99.0')
    command = ['cargo', 'build', '--release', '--locked', '--message-format=json-render-diagnostics']
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    process = subprocess.run(command, cwd=ROOT, env=env, capture_output=True)
    (out / 'cargo.stdout').write_bytes(process.stdout); (out / 'cargo.stderr').write_bytes(process.stderr)
    bins = {}
    for line in process.stdout.splitlines():
        value = json.loads(line)
        if value.get('reason') != 'compiler-artifact' or not value.get('executable'): continue
        if Path(value['manifest_path']).resolve() != ROOT / 'Cargo.toml': continue
        profile = value['profile']
        if profile['opt_level'] != '3' or profile['debug_assertions'] or profile['test']:
            raise ValueError('Cargo artifact is not the required optimized release profile')
        executable = Path(value['executable']).resolve()
        if not executable.is_relative_to(target): raise ValueError('artifact escaped fresh target')
        bins[value['target']['name']] = {'path': executable.relative_to(ROOT).as_posix(),
                                         'sha256': sha(executable), 'actual_profile': profile}
    stable = before['sha256'] == source_identity(ROOT)['sha256']
    passed = process.returncode == 0 and stable and set(bins) == {'rillscope', 'rillscope-measure'}
    receipt = {'schema_version': 1, 'status': 'PASS' if passed else 'FAIL', 'exit_code': process.returncode,
               'command': command, 'started_utc': started, 'finished_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
               'source': before, 'source_after_sha256': source_identity(ROOT)['sha256'],
               'cargo_lock_sha256': sha(ROOT / 'Cargo.lock'), 'compiler': compiler, 'profile': 'release',
               'fresh_target_directory': True, 'target_directory': target.relative_to(ROOT).as_posix(), 'bins': bins,
               'raw_stdout_sha256': sha(out / 'cargo.stdout'), 'raw_stderr_sha256': sha(out / 'cargo.stderr')}
    (out / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    if not passed: raise ValueError('release build failed or source/artifact identity changed; raw evidence retained')
    return receipt


def verify_build(receipt_path, binary, *, name, root=ROOT):
    root = Path(root).resolve()
    receipt = json.loads(Path(receipt_path).read_bytes())
    if receipt.get('schema_version') != 1 or receipt.get('fresh_target_directory') is not True:
        raise ValueError('unsupported or non-fresh build receipt')
    if receipt.get('status') != 'PASS' or receipt.get('exit_code') != 0 or receipt.get('profile') != 'release':
        raise ValueError('no passing actual release build receipt')
    if receipt['source']['sha256'] != source_identity(root)['sha256'] or receipt['source_after_sha256'] != receipt['source']['sha256']:
        raise ValueError('release executable source differs from current source')
    if receipt['cargo_lock_sha256'] != sha(root / 'Cargo.lock'): raise ValueError('dependency lock differs from build')
    artifact = receipt['bins'][name]
    expected = (root / artifact['path']).resolve()
    target = (root / receipt['target_directory']).resolve()
    if not target.is_relative_to(root / '.local-runs') or not expected.is_relative_to(target) or Path(binary).resolve() != expected or sha(expected) != artifact['sha256']:
        raise ValueError('executable is not the source-bound release artifact')
    profile = artifact['actual_profile']
    if profile['opt_level'] != '3' or profile['debug_assertions'] or profile['test']: raise ValueError('wrong actual build profile')
    for stream in ('stdout', 'stderr'):
        if sha(Path(receipt_path).parent / ('cargo.' + stream)) != receipt['raw_' + stream + '_sha256']:
            raise ValueError('raw build output digest mismatch')
    return receipt


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True); args = parser.parse_args()
    result = build_release(args.out)
    print(json.dumps({'status': result['status'], 'bins': result['bins'], 'source_sha256': result['source']['sha256']}))
    return 0


if __name__ == '__main__': raise SystemExit(main())
