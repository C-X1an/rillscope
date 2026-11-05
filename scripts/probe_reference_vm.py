#!/usr/bin/env python3
"""Inspect an existing Linux KVM interface; do not provision or qualify a VM."""
import argparse
import json
import os
from pathlib import Path
import platform
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from run import environment


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / '.local-runs'):
        raise ValueError('probe evidence must remain in owned .local-runs')
    out.mkdir(parents=True, exist_ok=False)
    actual = environment()
    reasons = []
    kvm = {'api_version': None, 'existing_device_opened': False}
    if platform.system() != 'Linux':
        reasons.append('actual runtime is not Linux')
    else:
        import fcntl
        try:
            # KVM_GET_API_VERSION = _IO(0xae, 0x00), Linux stable KVM ABI.
            # This read-only query creates no VM and changes no permissions.
            with Path('/dev/kvm').open('r+b', buffering=0) as handle:
                if not stat.S_ISCHR(os.fstat(handle.fileno()).st_mode):
                    raise ValueError('existing KVM interface is not a character device')
                kvm['existing_device_opened'] = True
                kvm['api_version'] = fcntl.ioctl(handle.fileno(), 0xae00, 0)
            if kvm['api_version'] != 12:
                reasons.append('existing KVM API version is not supported')
        except (OSError, ValueError) as error:
            kvm.update(error=type(error).__name__, errno=getattr(error, 'errno', None))
            reasons.append('existing KVM interface unavailable with current process permissions')
    if actual.get('machine', '').lower() not in ('x86_64', 'amd64'):
        reasons.append('actual host is not x86_64')
    if actual.get('resource_inspection_status') != 'MEASURED' or actual.get('effective_cpu_capacity', 0) < 4:
        reasons.append('four effective host CPUs have not been observed')
    available = actual.get('available_memory_bytes')
    if type(available) is not int or available < 10 * 1024**3:
        reasons.append('host headroom for an eight-GiB guest is unmeasured or insufficient')
    memory_limit = actual.get('cgroup_memory_limit_bytes')
    if memory_limit is not None and memory_limit < 12 * 1024**3:
        reasons.append('effective host memory limit leaves insufficient guest headroom')
    result = {'status': 'BLOCKED' if reasons else 'AVAILABLE', 'actual_environment': actual,
              'process_effective_user_id': os.geteuid() if hasattr(os, 'geteuid') else None,
              'kvm': kvm, 'reasons': reasons, 'reference_qualified': False,
              'scope': 'existing host capability observation only; no guest, allocation, benchmark or reference qualification',
              'provider_limitation': 'GitHub nested VMs are experimental and not officially supported',
              'api_reference': 'https://docs.kernel.org/virt/kvm/api.html#kvm-get-api-version'}
    (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 77 if reasons else 0


if __name__ == '__main__':
    raise SystemExit(main())
