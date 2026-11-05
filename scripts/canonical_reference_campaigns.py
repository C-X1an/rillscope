"""Inspect every original canonical campaign through bounded CAS read views.

This consumes the genuine retained native/fresh associations and both sides of
the original byte transfer. No old host-prebuilt payload is constructed.
"""
import hashlib
from pathlib import PurePosixPath
import re

import archive_capture
from canonical_reference_allocation import require, hex_value
from canonical_reference_retained_fresh import relative, bounded_hash, read_bounded_file
from capture_read_view import CaptureReadView
from cancellation import verify_cancellation
from feasibility_profile import exact
from kvm_reference_channel import header
from kvm_reference_common import METHOD as INNER_METHOD, STAGES, strict_json, validate_scope
from verify import verify
from verify_kvm_reference import filter_targets, cancel_target

COUNTS = {'grid': (410, 43050, 290, 17400), 'cancel': (5, 175, None, None), 'sort-null': (40, 4200, 40, 2400)}
ROLE = {'grid': 'full-grid', 'cancel': 'full-cancel', 'sort-null': 'sort-null'}


def check_manifest_binding(stage, binding, captured_sha256):
    require(stage in STAGES and type(binding) is dict and binding.get('role') == ROLE[stage]
        and hex_value(binding.get('linked_metadata_sha256'), 64) and hex_value(captured_sha256, 64),
        'typed original native manifest role/digest required')
    linked = relative(binding.get('linked_source'))
    experiment = r'bench/s-[0-9]+' if stage == 'sort-null' else r'benchmark-[0-9]+'
    inner_stage = 'cancel' if stage == 'cancel' else 'grid'
    pattern = r'\.local-runs/clean-[A-Za-z0-9_-]+/c/\.local-runs/' + experiment + '/' + inner_stage + r'/manifest\.json'
    require(re.fullmatch(pattern, linked.as_posix()) is not None,
        'original native manifest path differs from its measured role')
    require(captured_sha256 == binding['linked_metadata_sha256'],
        'captured manifest differs from exact original native manifest bytes')
    return linked


def check_complete(stage, verification, result):
    require(stage in STAGES and type(verification) is dict and type(result) is dict,
        'closed original campaign and verifier/result objects required')
    cases, observations, successes, comparisons = COUNTS[stage]
    require(verification.get('status') == 'PASS' and verification.get('errors') == []
        and type(verification.get('observations_checked')) is int
        and verification['observations_checked'] == observations,
        'all original observations must validate; partial/failed evidence cannot qualify')
    if stage == 'cancel':
        expected = {'status': 'PASS', 'observations': 175, 'measured_observations': 150,
            'invalid_observations': 0, 'source_binary_input_identity_stable': True}
    else:
        require(type(verification.get('cases_checked')) is int and verification['cases_checked'] == cases
            and type(verification.get('required_success_cases_checked')) is int
            and verification['required_success_cases_checked'] == successes
            and type(verification.get('independent_semantic_comparisons')) is int
            and verification['independent_semantic_comparisons'] >= comparisons,
            'all required seeded successful cases and independent comparisons required')
        expected = {'schema_version': 3, 'profile': 'full' if stage == 'grid' else 'sort-null-supplement',
            'completed_cases': cases, 'expected_cases': cases, 'complete_grid': stage == 'grid',
            'instrumentation_status': 'PASS', 'invalid_observations': 0, 'source_binary_inputs_stable': True}
    require(all(exact(result.get(key), value) for key, value in expected.items()),
        'original campaign result is incomplete, invalid or reduced')


def view_document(view, name, limit):
    require(name in view.files and view.files[name]['bytes'] <= limit, 'bounded original capture metadata missing')
    with (view.mount / name).open('rb') as stream: raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'original capture metadata exceeds bound')
    value = strict_json(raw); require(type(value) is dict, 'original capture metadata object required')
    return value


def validate_campaigns(artifact, metadata, native, *, commit, source, export_config_sha256, out):
    artifact, out = map(archive_capture.owned, (artifact, out))
    require(not out.exists() and out.parent.is_dir(), 'new separate all-record inspection output required')
    require(native.get('status') == 'CHECKED ORIGINAL NATIVE BYTES' and native.get('commit') == commit
        and native.get('source_sha256') == source['sha256'] and native.get('reference_qualified') is False,
        'exact original checked native association required before campaign inspection')
    bindings = native.get('associations')
    require(type(bindings) is list and len(bindings) == 4 and all(type(row) is dict for row in bindings)
        and [row.get('role') for row in bindings] == ['functional', 'full-grid', 'full-cancel', 'sort-null'],
        'all original native roles required before campaign inspection')
    captures = metadata.manifest.get('captures')
    require(type(captures) is list and len(captures) <= 32, 'bounded original retained capture list required')
    out.mkdir(); campaigns = []; results = {}; previous_finished = None
    for stage in STAGES:
        binding = next(row for row in bindings if row['role'] == ROLE[stage])
        source_stage = relative(binding['linked_source']).parent
        selected = [row for row in captures if type(row) is dict and row.get('source') == source_stage.as_posix()]
        require(len(selected) == 1, 'one exact original retained campaign required; never choose fallback/latest')
        retained = selected[0]
        require(type(retained.get('package')) is str and re.fullmatch(r'capture-[0-9]+', retained['package'])
            and type(retained.get('result')) is dict and retained['result'].get('status') == 'RECORDED',
            'original retained campaign package failed or missing')
        package = archive_capture.owned(metadata.root / retained['package'])
        retained_archive = package / 'capture.zip'
        archive_record = strict_json(read_bounded_file(package / 'archive-result.json', 65536))
        require(archive_record == retained['result'], 'retained campaign result differs from original package')
        host = archive_capture.owned(artifact / 'vm/artifact/channel/packages' / stage)
        archive = host / 'capture.zip'; digest, size = bounded_hash(archive, archive_capture.MAX_ARCHIVE)
        require(bounded_hash(retained_archive, archive_capture.MAX_ARCHIVE) == (digest, size)
            and archive_record.get('archive_sha256') == digest and archive_record.get('compressed_bytes') == size,
            'original host capture and retained guest bytes differ')
        transfer_raw = read_bounded_file(host / 'transfer.json', 65536); transfer = strict_json(transfer_raw)
        fields = {'schema_version', 'method', 'stage', 'bytes', 'sha256', 'commit', 'source_sha256', 'reference_qualified'}
        require(type(transfer) is dict and set(transfer) == fields | {'status', 'started', 'finished', 'metadata'},
            'closed original host transfer required')
        header({key: transfer[key] for key in fields}, commit=commit, source_sha256=source['sha256'])
        require(transfer['stage'] == stage and transfer['status'] == 'VERIFIED HOST BYTES'
            and transfer['sha256'] == digest and transfer['bytes'] == size, 'original host transfer differs from capture bytes')
        for endpoint in ('started', 'finished'):
            require(type(transfer[endpoint]) is dict and set(transfer[endpoint]) == {'utc_ns', 'monotonic_ns'}
                and all(type(value) is int and 0 < value < 2**63 for value in transfer[endpoint].values()),
                'original host transfer clocks missing or invalid')
        require(transfer['started']['monotonic_ns'] <= transfer['finished']['monotonic_ns']
            and transfer['started']['utc_ns'] <= transfer['finished']['utc_ns']
            and (previous_finished is None or previous_finished <= transfer['started']['monotonic_ns']),
            'original host campaign transfers overlap or reorder')
        previous_finished = transfer['finished']['monotonic_ns']
        export_source = source_stage.parent / ('capture-' + source_stage.name) / 'host-export-result.json'
        exported = metadata.document(export_source, 65536)
        require(exported.get('status') == 'HOST ACKNOWLEDGED' and exported.get('stage') == stage
            and exported.get('method') == INNER_METHOD and exported.get('reference_qualified') is False
            and exported.get('all_record_validation') == 'NOT RUN' and exported.get('commit') == commit
            and exported.get('source_sha256') == source['sha256'] and exported.get('archive_sha256') == digest
            and exported.get('config_sha256') == export_config_sha256,
            'original guest export differs from source-bound host bytes/configuration')
        ack = exported.get('host_transfer')
        require(type(ack) is dict and set(ack) == fields | {'status', 'elapsed_ns'}
            and ack['status'] == 'HOST ACKNOWLEDGED' and type(ack['elapsed_ns']) is int and ack['elapsed_ns'] >= 0
            and all(exact(ack[key], transfer[key]) for key in fields), 'original guest ACK/header differs')
        with CaptureReadView(archive, out / ('read-' + stage)) as view:
            manifest = view_document(view, 'manifest.json', 4 * 1024**2)
            check_manifest_binding(stage, binding, view.files['manifest.json']['sha256'])
            validate_scope(manifest, stage, commit=commit, source_sha256=source['sha256'])
            require(manifest.get('source') == source and manifest.get('binary_sha256') == binding['sha256']
                and manifest.get('build_receipt_sha256') == binding['build_receipt_sha256'],
                'actual captured campaign/native build association differs')
            require(transfer['metadata'] == view.metadata
                and all(exact(archive_record.get(key), value) for key, value in view.metadata.items()),
                'original transferred/retained CAS inventories differ')
            verification = verify_cancellation(view.mount) if stage == 'cancel' else verify(view.mount, True)
            result = view_document(view, 'results.json', archive_capture.MAX_FILE)
            check_complete(stage, verification, result)
            results[stage] = result
            checked = {'stage': stage, 'status': 'PASS', 'archive_sha256': digest, 'archive_bytes': size,
                'manifest_sha256': view.files['manifest.json']['sha256'], 'metadata': view.metadata,
                'original_export_sha256': metadata.rows[export_source.as_posix()]['sha256'],
                'original_transfer_sha256': hashlib.sha256(transfer_raw).hexdigest(),
                'verification': verification, 'CAS_reads': view.read_calls, 'expanded_raw_files_created': 0}
        require(bounded_hash(archive, archive_capture.MAX_ARCHIVE) == (digest, size)
            and bounded_hash(retained_archive, archive_capture.MAX_ARCHIVE) == (digest, size)
            and read_bounded_file(host / 'transfer.json', 65536) == transfer_raw,
            'original campaign bytes changed during all-record inspection')
        campaigns.append(checked)
    metadata.unchanged()
    return {'status': 'CHECKED ORIGINAL CAMPAIGNS', 'campaigns': campaigns,
        'observations_checked': 47425, 'minimum_independent_semantic_comparisons': 19800,
        'filter_project_observed_targets': filter_targets(results['grid']),
        'cancellation_observed_target': cancel_target(results['cancel']), 'reference_qualified': False,
        'scope': 'Every original full410/cancel/NULL40 raw record, declared scope and both retained transfer associations checked. No query execution, fabricated old-method payload, allocation authenticity, continuous-resource or independent qualification verdict.'}
