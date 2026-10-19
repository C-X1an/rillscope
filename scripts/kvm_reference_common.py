"""Closed declarations for one complete collection; no qualification by prose."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from workloads import descriptors, sort_null_descriptors
from feasibility_profile import exact
from envelopes import unique_object
from kvm_pilot_common import require

METHOD = 'rillscope-full-capture-v1'
STAGES = ('grid', 'cancel', 'sort-null')
SEEDS = [20261014, 20261015, 20261016, 20261017, 20261018]
MANIFEST_LIMIT = 4 * 1024**2


def invalid_number(_value): raise ValueError('nonfinite JSON constant is forbidden')


def strict_json(data):
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_number)


def identity(commit, source_sha256):
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit)
            and isinstance(source_sha256, str) and re.fullmatch('[0-9a-f]{64}', source_sha256),
            'exact expected commit and source digest required')


def source_map(value, expected):
    require(type(value) is dict and set(value) == {'files', 'sha256'}
            and value['sha256'] == expected and type(value['files']) is list
            and 0 < len(value['files']) <= 4096, 'capture source identity differs')
    names = []
    for row in value['files']:
        require(type(row) is list and len(row) == 2 and all(isinstance(part, str) for part in row),
                'invalid capture source map row')
        name, digest = row; path = PurePosixPath(name)
        require(name and not path.is_absolute() and name == path.as_posix() and '..' not in path.parts
                and '\\' not in name and ':' not in name and re.fullmatch('[0-9a-f]{64}', digest),
                'invalid capture source path or digest')
        names.append(name)
    require(names == sorted(set(names)), 'capture source paths repeat or are unordered')
    actual = hashlib.sha256(json.dumps(value['files'], separators=(',', ':')).encode()).hexdigest()
    require(actual == expected, 'capture source map digest differs')


def validate_scope(manifest, stage, *, commit, source_sha256):
    """Check declared method only; raw outcomes still require the full offline verifier."""
    identity(commit, source_sha256)
    require(stage in STAGES and type(manifest) is dict, 'closed reference stage/manifest required')
    source_map(manifest.get('source'), source_sha256)
    expected = {'warmups': 5, 'repetitions': 30, 'seeds': SEEDS}
    if stage == 'cancel':
        expected.update(schema_version=2, system='Linux')
    else:
        chosen = descriptors() if stage == 'grid' else sort_null_descriptors()
        require(len(chosen) == (82 if stage == 'grid' else 8), 'complete reference scope implementation differs')
        expected.update(schema_version=3, commit=commit, dirty=False,
            profile='full' if stage == 'grid' else 'sort-null-supplement', chosen_workloads=chosen,
            expected_cases=410 if stage == 'grid' else 40,
            expected_observations=43050 if stage == 'grid' else 4200)
    require(all(exact(manifest.get(key), value) for key, value in expected.items()),
            'declared full/reference scope differs')
    return {'stage': stage, 'declared_scope_checked': True, 'all_record_validation': 'NOT RUN',
            'reference_qualified': False}
