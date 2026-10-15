#!/usr/bin/env python3
"""Run the real product from a new committed clone, retaining all failures."""
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from evidence import source_identity

ROOT = Path(__file__).resolve().parents[1]


def git(*arguments, root=ROOT):
    return subprocess.check_output(['git', *arguments], cwd=root, text=True).strip()


def nested_check(marker):
    value = json.loads(marker.read_bytes())
    identity = source_identity(ROOT)
    if (marker.parent != ROOT / '.local-runs' or Path(value['fresh_clone_root']) != ROOT
            or value['commit'] != git('rev-parse', 'HEAD') or value['source_sha256'] != identity['sha256']
            or git('status', '--porcelain')):
        raise ValueError('fresh-clone identity changed or caller marker is invalid')
    executable = ROOT / 'target/debug' / ('rillscope.exe' if os.name == 'nt' else 'rillscope')
    if not executable.is_file(): raise ValueError('fresh clone has no built product binary')
    result = subprocess.run([str(executable), '--version'], capture_output=True, check=True)
    if result.stdout != b'rillscope 0.1.0-dev\n' or result.stderr:
        raise ValueError('fresh product version framing differs')
    print(json.dumps({'mode': 'already-in-owned-fresh-clone', 'status': 'PASS',
                      'commit': value['commit'], 'source_sha256': identity['sha256'],
                      'scope': 'fresh clone source/build identity; outer make verify still governs release status'}))
    return 0


def main():
    marker_value = os.environ.get('RILLSCOPE_CLEAN_SCOPE_FILE')
    if marker_value:
        try: return nested_check(Path(marker_value).resolve())
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            print('FAIL: nested fresh-clone check: ' + type(error).__name__, file=sys.stderr); return 1
    if git('status', '--porcelain'):
        print('FAIL: commit all public source changes before clean verification', file=sys.stderr); return 1
    for tool in ('git', 'make', 'rustup', 'cargo'):
        if shutil.which(tool) is None:
            print('BLOCKED: required tool unavailable: ' + tool, file=sys.stderr); return 77
    out = ROOT / '.local-runs' / ('clean-' + str(time.time_ns()))
    out.mkdir(parents=True)
    clone = out / 'checkout'
    commit = git('rev-parse', 'HEAD')
    identity = source_identity(ROOT)
    subprocess.run(['git', 'clone', '--no-local', '--config', 'core.autocrlf=false', str(ROOT), str(clone)], check=True)
    if git('rev-parse', 'HEAD', root=clone) != commit or source_identity(clone)['sha256'] != identity['sha256']:
        raise ValueError('fresh clone differs from committed source')
    (clone / '.local-runs').mkdir()
    marker = clone / '.local-runs/clean-scope.json'
    marker.write_text(json.dumps({'fresh_clone_root': str(clone), 'commit': commit,
                                 'source_sha256': identity['sha256']}) + '\n')
    env = os.environ.copy(); env['RILLSCOPE_CLEAN_SCOPE_FILE'] = str(marker)
    target_directory = clone / 'target'
    if target_directory.exists(): raise ValueError('fresh clone already has build output')
    env['CARGO_TARGET_DIR'] = 'target'  # Every command below has cwd=clone; avoid GNU absolute-path limits.
    targets = ['bootstrap', 'verify', 'demo']
    # A failed make verify stops its dependency sequence. Retain that failure and
    # execute subsequent independent gates explicitly; never relabel the aggregate.
    supplemental = ['verify-reference', 'security', 'property', 'fuzz', 'mutation', 'benchmark', 'security-online']
    results = []
    for target in targets + supplemental:
        command = ['make', target]
        if os.name == 'nt': command.append('SHELL=sh')
        receipt = out / 'commands' / target
        run = subprocess.run([sys.executable, str(clone / 'scripts/evidence.py'), '--out', str(receipt), '--timeout', '10800', '--', *command], cwd=clone, env=env)
        recorded = json.loads((receipt / 'receipt.json').read_bytes())
        results.append({'target': target, 'exit_code': run.returncode, 'status': recorded['verification_status'],
                        'source_before': recorded['source_before']['sha256'], 'source_after': recorded['source_after_sha256']})
    stable = source_identity(clone)['sha256'] == identity['sha256'] and not git('status', '--porcelain', root=clone)
    passed = stable and all(item['status'] == 'PASS' for item in results)
    report = {'mode': 'fresh-committed-Rust-checkout', 'status': 'PASS' if passed else 'FAIL',
              'commit': commit, 'source_sha256': identity['sha256'], 'source_stable': stable,
              'same_os_and_toolchain_installation': True, 'target_directory_was_fresh': True,
              'cargo_target_dir_enforced_inside_fresh_clone': True,
              'commands': results, 'finished_utc': dt.datetime.now(dt.timezone.utc).isoformat()}
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
