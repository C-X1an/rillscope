"""Check retained native executable/build associations without executing bytes."""
import hashlib
from pathlib import PurePosixPath
import re

import archive_capture
from canonical_reference_allocation import METHOD, require, hex_value
from canonical_reference_binaries import native_prefix, MAX_BINARY, MAX_BYTES, MAX_METADATA, BUILD_FILES
from canonical_reference_retained_fresh import relative, bounded_hash, read_bounded_file
from kvm_reference_common import strict_json

ROLES = ('functional', 'full-grid', 'full-cancel', 'sort-null')
CONFIGURATION = {'RUSTUP_TOOLCHAIN': '1.99.0', 'RUSTC_WRAPPER': '',
    'RUSTC_WORKSPACE_WRAPPER': '', 'CARGO_ENCODED_RUSTFLAGS': ''}


def validate_binaries(root, *, commit, source, fresh, validator_root):
    root = archive_capture.owned(root); record_path = root / 'binaries-result.json'
    record_raw = read_bounded_file(record_path, MAX_METADATA)
    initial_record_sha256 = hashlib.sha256(record_raw).hexdigest()
    record = strict_json(record_raw)
    require(type(record) is dict and type(record.get('schema_version')) is int and record['schema_version'] == 1
        and record.get('method') == METHOD and record.get('status') == 'RETAINED ORIGINAL BYTES'
        and record.get('commit') == commit and record.get('source_sha256') == source['sha256']
        and record.get('upstream_fresh_status') == 'PASS' and record.get('errors') == []
        and record.get('reference_qualified') is False
        and type(record.get('finished_monotonic_ns')) is int and type(record.get('cutoff_monotonic_ns')) is int
        and 0 < record['finished_monotonic_ns'] < record['cutoff_monotonic_ns'],
        'complete original native binary retention record required')
    require(fresh.get('status') == 'CHECKED RECORDED FRESH' and fresh.get('commit') == commit
        and fresh.get('source_sha256') == source['sha256'], 'previous exact fresh validation required')
    clone = relative(fresh['fresh_checkout']); metadata = {}; objects = {}; all_rows = []; source_names = set()
    for key, maximum, limit in [('metadata', 32, MAX_METADATA), ('objects', 4, MAX_BINARY)]:
        rows = record.get(key)
        require(type(rows) is list and 0 < len(rows) <= maximum, 'bounded native object/metadata list required')
        for row in rows:
            require(type(row) is dict and set(row) == {'source', 'file', 'bytes', 'sha256'}
                and type(row['bytes']) is int and 0 <= row['bytes'] <= limit and hex_value(row['sha256'], 64),
                'closed original native byte identity required')
            original, file = relative(row['source']), relative(row['file'])
            require(original.is_relative_to(clone.parent) and len(file.parts) == 1
                and (re.fullmatch(r'metadata-[0-9]+', row['file']) if key == 'metadata'
                    else row['file'] == 'object-' + row['sha256'])
                and row['file'] not in metadata and row['file'] not in objects,
                'native retained byte path is duplicated or unrelated')
            path = archive_capture.owned(root / row['file'])
            require(bounded_hash(path, limit) == (row['sha256'], row['bytes']), 'native retained byte digest differs')
            if key == 'metadata':
                require(row['source'] not in source_names, 'original native metadata source repeated')
                source_names.add(row['source']); metadata[row['file']] = row
            else:
                with path.open('rb') as stream: native_prefix(stream.read(64))
                objects[row['file']] = row
            all_rows.append((row, limit))
    require(type(record.get('bytes')) is int and record['bytes'] == sum(row['bytes'] for row, _ in all_rows)
        and record['bytes'] <= MAX_BYTES, 'native retained aggregate byte count differs')
    originals = {row['source']: row for row in metadata.values()}
    result_name = (clone.parent / 'results.json').as_posix()
    require(result_name in originals and originals[result_name]['sha256'] == fresh['fresh_result_sha256'],
        'native custody and fresh validation used different original result bytes')
    def document(row):
        value = strict_json(read_bounded_file(root / row['file'], row['bytes'], row['sha256']))
        require(type(value) is dict, 'original native metadata object required'); return value
    rows = record.get('associations')
    require(type(rows) is list and len(rows) == 4 and all(type(row) is dict for row in rows)
        and [row.get('role') for row in rows] == list(ROLES), 'all four original native executable roles required')
    used_metadata = {originals[result_name]['file']}; used_objects = set(); build_sources = {}; bindings = []
    lock_sha256 = hashlib.sha256((validator_root / 'Cargo.lock').read_bytes()).hexdigest()
    for role, association in zip(ROLES, rows):
        name, profile = ('rillscope', 'dev') if role == 'functional' else (
            ('rillscope', 'release') if role == 'full-cancel' else ('rillscope-measure', 'release'))
        require(association.get('status') == 'RETAINED ORIGINAL BYTES'
            and association.get('binary_name') == name and association.get('profile') == profile
            and association.get('object') in objects and association.get('sha256') == objects[association['object']]['sha256'],
            'original native role/object identity differs')
        proofs = association.get('metadata')
        require(type(proofs) is list and len(proofs) == 6 and len(set(proofs)) == 6
            and all(type(item) is str and item in metadata for item in proofs),
            'six original build/raw/pointer-or-manifest proofs required')
        selected = [metadata[file] for file in proofs]; receipt_path = relative(selected[0]['source'])
        require(receipt_path.is_relative_to(clone) and receipt_path.name == 'build.json'
            and [relative(row['source']).name for row in selected[:5]] == list(BUILD_FILES)
            and all(relative(row['source']).parent == receipt_path.parent for row in selected[:5]),
            'original build proof/raw paths differ')
        build = document(selected[0]); target = relative(build['target_directory'])
        require(type(build.get('schema_version')) is int and build['schema_version'] == 2
            and build.get('status') == 'PASS' and type(build.get('exit_code')) is int and build['exit_code'] == 0
            and build.get('profile') == profile and build.get('problems') == []
            and build.get('fresh_target_directory') is (profile == 'release')
            and build.get('source') == source and build.get('source_after_sha256') == source['sha256']
            and build.get('cargo_lock_sha256') == lock_sha256
            and type(build.get('bins')) is dict and set(build['bins']) == {'rillscope', 'rillscope-measure'},
            'original required native build/source/lock/profile differs')
        require(target.is_relative_to(PurePosixPath('.local-runs')) if profile == 'release'
            else target == PurePosixPath('target'), 'original build target escaped fresh checkout ownership')
        require(build.get('command') == ['cargo', 'build', '--bins', '--locked',
            '--message-format=json-render-diagnostics', '--verbose'] + (['--release'] if profile == 'release' else [])
            and build.get('compiler_selection') == 'explicit pinned sysroot executable passed as RUSTC'
            and build.get('compiler_configuration') == CONFIGURATION and hex_value(build.get('rustc_executable_sha256'), 64)
            and type(build.get('compiler')) is str and build['compiler'].startswith('rustc 1.99.0 ')
            and 'host: x86_64-unknown-linux-gnu\n' in build['compiler'], 'pinned native compiler/build command differs')
        for proof, field in zip(selected[1:5], ['raw_stdout_sha256', 'raw_stderr_sha256',
            'raw_compiler_stdout_sha256', 'raw_compiler_stderr_sha256']):
            require(proof['sha256'] == build.get(field), 'native retained build raw stream differs')
        require(read_bounded_file(root / selected[3]['file'], selected[3]['bytes'], selected[3]['sha256']).decode('utf-8') == build['compiler'],
            'native compiler banner differs from retained original probe bytes')
        for bin_name, binary in build['bins'].items():
            actual_profile = binary['actual_profile']; binary_path = relative(binary['path'])
            require(binary_path.is_relative_to(target) and binary_path.name == bin_name
                and hex_value(binary.get('sha256'), 64) and type(actual_profile) is dict
                and actual_profile.get('opt_level') == ('3' if profile == 'release' else '0')
                and actual_profile.get('debug_assertions') is (profile == 'dev')
                and actual_profile.get('test') is False, 'native Cargo artifact path/profile differs')
        require(association.get('original_binary') == (clone / relative(build['bins'][name]['path'])).as_posix()
            and association['sha256'] == build['bins'][name]['sha256'], 'retained ELF differs from original measured build')
        linked = document(selected[-1]); linked_source = relative(selected[-1]['source'])
        build_relative = receipt_path.relative_to(clone)
        if role == 'functional':
            require(re.fullmatch(r'\.local-runs/build/dev-[0-9]+/build\.json', build_relative.as_posix())
                and linked_source == clone / 'target/debug/rillscope.build.json'
                and linked == {'receipt': build_relative.as_posix()}, 'original functional pointer differs')
        else:
            stage = 'cancel' if role == 'full-cancel' else 'grid'
            require(linked_source == receipt_path.parent.parent / stage / 'manifest.json'
                and linked.get('build_receipt_sha256') == selected[0]['sha256'] and linked.get('build') == build
                and linked.get('source') == source and linked.get('binary_sha256') == association['sha256']
                and (role == 'full-cancel' or linked.get('profile') == ('full' if role == 'full-grid' else 'sort-null-supplement')),
                'original native measured manifest differs')
            pattern = r'\.local-runs/bench/s-[0-9]+/build/build\.json' if role == 'sort-null' else r'\.local-runs/benchmark-[0-9]+/build/build\.json'
            require(re.fullmatch(pattern, build_relative.as_posix()), 'original measured experiment identity differs')
        build_sources[role] = receipt_path.as_posix(); used_metadata.update(proofs); used_objects.add(association['object'])
        bindings.append({'role': role, 'binary_name': name, 'sha256': association['sha256'],
            'build_receipt_sha256': selected[0]['sha256'], 'build_source': receipt_path.as_posix(),
            'linked_metadata_sha256': selected[-1]['sha256'], 'linked_source': linked_source.as_posix()})
    require(build_sources['full-grid'] == build_sources['full-cancel']
        and used_metadata == set(metadata) and used_objects == set(objects), 'extra unbound native bytes or split original experiment')
    require(bounded_hash(record_path, MAX_METADATA)[0] == initial_record_sha256, 'native custody record changed during checking')
    for row, limit in all_rows:
        require(bounded_hash(root / row['file'], limit) == (row['sha256'], row['bytes']), 'native custody bytes changed during checking')
    return {'status': 'CHECKED ORIGINAL NATIVE BYTES', 'commit': commit, 'source_sha256': source['sha256'],
        'fresh_result_sha256': fresh['fresh_result_sha256'], 'associations': bindings, 'objects_checked': len(objects),
        'metadata_checked': len(metadata), 'bytes_checked': record['bytes'], 'record_sha256': initial_record_sha256,
        'reference_qualified': False, 'executables_run': 0,
        'scope': 'Four original ELF64/build/raw/pointer/manifest associations replayed against exact checked fresh source. No captured executable was run; semantic, allocation and full-record validation are separate.'}
