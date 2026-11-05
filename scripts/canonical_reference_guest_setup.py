"""Install pinned native tools only inside the distinct newly owned guest."""
import hashlib
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_allocation as allocation
import canonical_reference_device as device
from canonical_reference_guest_owner import HOME, nonroot
from canonical_reference_reservation import durable_mkdir, fsync_directory
from canonical_reference_seed import (INPUT_RELATIVE, INSTALLER_RELATIVE, INSTALLER_SHA256,
    INSTALLER_LIMIT, RUSTUP_VERSION, seed_files, validate_seed)
from inspect_reference_guest import TrialCommands, interrupted
from kvm_pilot_common import write_json
from owned_process import LinuxOwnedChildren
import reference_allocation as original
import canonical_reference_git_trust as git_trust
import base64
from canonical_reference_git_control import guest_output
import canonical_reference_native_apt as native_apt

BASE = ROOT / '.local-runs/canonical-setup'
TOOL_TARGET = HOME / '.native-tool-build'
PACKAGES = ('build-essential', 'ca-certificates', 'curl', 'pkg-config', 'libssl-dev',
    'git', 'make', 'gdb', 'strace', 'time', 'util-linux')


def check_rust_versions(rustup_raw, rustc_raw, cargo_raw, audit_raw, deny_raw):
    """Use actual tool output; no hardware/configuration-based success."""
    values = (rustup_raw, rustc_raw, cargo_raw, audit_raw, deny_raw)
    allocation.require(all(type(raw) is bytes and 0 < len(raw) <= 16384 for raw in values),
        'bounded actual native version outputs required')
    text = [raw.decode('utf-8') for raw in values]
    allocation.require(text[0].splitlines() and text[2].splitlines(), 'actual native tool version line required')
    allocation.require(text[0].splitlines()[0].split()[:2] == ['rustup', RUSTUP_VERSION],
        'actual native rustup version differs from pinned installer')
    rust = {}
    for line in text[1].splitlines():
        key, separator, value = line.partition(': ')
        if separator:
            allocation.require(key not in rust, 'duplicate native compiler version field')
            rust[key] = value
    allocation.require(rust.get('release') == '1.99.0' and rust.get('host') == 'x86_64-unknown-linux-gnu'
        and text[2].splitlines()[0].split()[:2] == ['cargo', '1.99.0']
        and text[3].strip().split() in (['cargo-audit', '0.22.2'], ['cargo-audit-audit', '0.22.2'])
        and text[4].strip().split() == ['cargo-deny', '0.20.2'],
        'actual pinned native compiler/Cargo/audit/deny versions differ')
    return {'rustup': text[0].splitlines()[0], 'rustc': rust, 'cargo': text[2].splitlines()[0],
        'cargo_audit': text[3].strip(), 'cargo_deny': text[4].strip()}


def retire_tool_target():
    """Remove only this stopped, regenerable external-tool compilation cache."""
    device.guard(0)
    allocation.require(TOOL_TARGET.parent == HOME and TOOL_TARGET.name == '.native-tool-build'
        and TOOL_TARGET.resolve() == TOOL_TARGET and TOOL_TARGET.is_relative_to(ROOT / '.local-runs'),
        'exact newly prepared guest tool cache required')
    if not TOOL_TARGET.exists(): return {'status': 'ABSENT', 'bytes': 0, 'files': 0}
    allocation.require(TOOL_TARGET.is_dir() and not TOOL_TARGET.is_symlink(), 'regular owned tool cache required')
    pending = [TOOL_TARGET]; size = count = 0
    while pending:
        for path in pending.pop().iterdir():
            count += 1
            allocation.require(count <= 100000 and not path.is_symlink(), 'bounded link-free tool cache required')
            info = path.lstat()
            allocation.require(info.st_uid == 65534, 'unexpected owner in new external-tool target')
            if stat.S_ISDIR(info.st_mode): pending.append(path)
            else:
                allocation.require(stat.S_ISREG(info.st_mode), 'tool cache requires regular files/directories')
                size += info.st_size
                allocation.require(size <= 16 * 1024**3, 'external-tool cache exceeds retirement bound')
    # These are the already checked absolute paths. This code cannot run on the
    # host controller or Windows, and no active installer/build owns the cache.
    shutil.rmtree(TOOL_TARGET)
    fsync_directory(HOME)
    return {'status': 'RETIRED', 'bytes': size, 'entries': count,
        'role': 'stopped third-party cargo-audit/cargo-deny build cache; installed tools and all raw receipts retained',
        'reproduction': ['cargo install cargo-audit --version 0.22.2 --locked',
            'cargo install cargo-deny --version 0.20.2 --locked']}


def setup(seed):
    device.guard(0)
    validate_seed(seed)
    allocation.require(seed_files(ROOT) == seed['files'] and not (ROOT / 'target').exists()
        and not HOME.exists() and not BASE.exists(), 'one unchanged source-only native setup required')
    # The root cloud bootstrap mounted only the owned work disk and wrote the
    # new marker. Neither an old marker nor root on an arbitrary host qualifies.
    import pwd
    account = pwd.getpwnam('nobody')
    allocation.require(account.pw_uid == account.pw_gid == 65534, 'existing guest nonroot identity differs')
    installer = ROOT / INSTALLER_RELATIVE
    allocation.require(0 < installer.stat().st_size <= INSTALLER_LIMIT
        and hashlib.sha256(installer.read_bytes()).hexdigest() == INSTALLER_SHA256,
        'actual pinned installer bytes differ before native execution')
    durable_mkdir(BASE, mode=0o700)
    started = time.monotonic_ns(); started_utc = time.time_ns(); deadline = started + seed['setup_seconds'] * 10**9
    record = {'schema_version': 1, 'method': allocation.METHOD, 'status': 'FAIL',
        'commit': seed['commit'], 'source_sha256': seed['source_sha256'],
        'started_monotonic_ns': started, 'started_utc_ns': started_utc, 'deadline_monotonic_ns': deadline,
        'boot_id': original.observed_boot_id(), 'first_party_build_transported': False,
        'canonical': 'NOT RUN', 'reference_qualified': False,
        'scope': 'Actual native prerequisites in the one owned ephemeral guest; no dedication, canonical or benchmark verdict.'}
    write_json(BASE / 'setup-result.json', record)
    ownership = LinuxOwnedChildren(); direct = TrialCommands(BASE, ownership)
    for selected in (signal.SIGTERM, signal.SIGINT): signal.signal(selected, interrupted)
    os.environ.update(DEBIAN_FRONTEND='noninteractive', PYTHONDONTWRITEBYTECODE='1',
        GIT_OPTIONAL_LOCKS='0', CARGO_INCREMENTAL='0')
    def checked(name, command, timeout=60):
        remaining = (deadline - time.monotonic_ns()) / 10**9
        allocation.require(remaining > 0, 'original native guest setup deadline exhausted')
        inputs = (ROOT / INPUT_RELATIVE,)
        if name in ('apt-update', 'apt-install'):
            _, sources, _ = native_apt.locations(ROOT)
            inputs += (Path(str(sources)), Path(native_apt.KEYRING))
        if 'git_trust_before' in record: inputs += (Path(git_trust.trust_path(ROOT)),)
        return direct(name, command, timeout=min(timeout, remaining), inputs=inputs)
    try:
        policy = native_apt.publish(ROOT)
        record['apt_acquisition'] = {'policy': policy, 'checks': []}
        write_json(BASE / 'setup-result.json', record)
        update, install = native_apt.commands(ROOT, PACKAGES)
        before = native_apt.observe(policy)
        checked('apt-update', update, 300)
        after = native_apt.observe(policy)
        record['apt_acquisition']['checks'].append({'stage': 'apt-update', 'before': before, 'after': after})
        write_json(BASE / 'setup-result.json', record)
        before = native_apt.observe(policy)
        checked('apt-install', install, 600)
        after = native_apt.observe(policy)
        record['apt_acquisition']['checks'].append({'stage': 'apt-install', 'before': before, 'after': after})
        write_json(BASE / 'setup-result.json', record)
        native_apt.validate_acquisition(record['apt_acquisition'], root=str(ROOT))
        checked('stop-package-services', ['/usr/bin/systemctl', 'stop', 'apt-daily.timer',
            'apt-daily-upgrade.timer', 'apt-daily.service', 'apt-daily-upgrade.service',
            'unattended-upgrades.service'], 30)
        checked('installed-packages', ['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\n',
            *PACKAGES, 'libc6', 'python3', 'libsqlite3-0'], 15)
        console = checked('serial-getty', ['/usr/bin/systemctl', 'show', '--property=LoadState',
            '--property=ActiveState', 'serial-getty@ttyS0.service'], 15)
        allocation.require(set(console.decode().splitlines()) == {'LoadState=masked', 'ActiveState=inactive'},
            'actual owned guest serial getty must be masked and inactive')
        allocation.require(original.repository_identity() == {'commit': seed['commit'],
            'source_sha256': seed['source_sha256']}, 'actual clean native source differs after system setup')
        git_raw = checked('guest-git-ownership', ['/usr/bin/python3',
            str(ROOT / 'tests/system/canonical_handoff_permissions.py'), '--guest-git-only'], 30)
        record['git_ownership_control'] = guest_output(git_raw, prefix_sha256=hashlib.sha256(
            (ROOT / 'scripts/canonical_reference_guest_owner.py').read_bytes()).hexdigest())
        record['git_trust_before'] = git_trust.install(ROOT)
        write_json(BASE / 'git-trust-observation.json', record['git_trust_before'])
        (BASE / 'git-trust-config.raw').write_bytes(base64.b64decode(record['git_trust_before']['base64'], validate=True))
        for path in (HOME, HOME / '.cargo', HOME / '.rustup'):
            durable_mkdir(path, mode=0o755); os.chown(path, 65534, 65534)
        fsync_directory(HOME.parent)
        checked('rustup-init', nonroot([str(installer), '-y', '--no-modify-path',
            '--profile', 'minimal', '--default-toolchain', 'none']), 300)
        checked('disable-rustup-self-update', nonroot(['rustup', 'set', 'auto-self-update', 'disable']), 15)
        checked('native-bootstrap', nonroot(['make', 'bootstrap']), 1440)
        # Use a newly owned, separately retired cache for third-party tools.
        # The first-party seed target and eventual fresh target stay absent.
        for label, tool, version in [('audit', 'cargo-audit', '0.22.2'), ('deny', 'cargo-deny', '0.20.2')]:
            command = nonroot(['/usr/bin/env', 'CARGO_TARGET_DIR=' + str(TOOL_TARGET),
                'cargo', 'install', tool, '--version', version, '--locked'])
            checked('install-' + label, command, 1440)
        rustup = checked('rustup-version', nonroot(['rustup', '--version']), 15)
        rustc = checked('rustc-version', nonroot(['rustc', '-vV']), 15)
        cargo = checked('cargo-version', nonroot(['cargo', '--version']), 15)
        audit = checked('audit-version', nonroot(['cargo', 'audit', '--version']), 15)
        deny = checked('deny-version', nonroot(['cargo', 'deny', '--version']), 15)
        record['versions'] = check_rust_versions(rustup, rustc, cargo, audit, deny)
        checked('gnu-time', ['/usr/bin/time', '-f', 'RILLTIME %U %S %M', '--',
            '/usr/bin/python3', '-c', 'print("native canonical GNU-time probe")'], 15)
        allocation.require(not (ROOT / 'target').exists()
            and not any((ROOT / '.local-runs').glob('clean-*'))
            and original.repository_identity() == {'commit': seed['commit'], 'source_sha256': seed['source_sha256']},
            'native prerequisite setup must not build or run first-party source')
        record['environment'] = original.environment()
        record['git_trust_after'] = git_trust.observe(ROOT)
        allocation.require(record['git_trust_after'] == record['git_trust_before'],
            'native setup changed protected child Git trust')
        record['status'] = 'PREPARED NATIVE TOOLS ONLY'
    except (Exception, KeyboardInterrupt) as error:
        record.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048])
    finally:
        for selected in (signal.SIGTERM, signal.SIGINT): signal.signal(selected, signal.SIG_IGN)
        record['cleanup'] = ownership.finish(None)
        if record['cleanup']['status'] != 'PASS': record['status'] = 'FAIL'
        # Never retire a cache while a command's cleanup is incomplete.
        if record['cleanup']['status'] == 'PASS':
            try: record['tool_target_retirement'] = retire_tool_target()
            except Exception as error:
                record.update(status='FAIL', retirement_error=type(error).__name__ + ': ' + str(error)[:2048])
        finished = time.monotonic_ns(); finished_utc = time.time_ns()
        record.update(finished_monotonic_ns=finished, finished_utc_ns=finished_utc,
            elapsed_seconds=(finished - started) / 10**9)
        if record['finished_monotonic_ns'] >= deadline: record['status'] = 'FAIL'
        write_json(BASE / 'setup-result.json', record); fsync_directory(BASE)
    return record
