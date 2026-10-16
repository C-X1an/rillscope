"""Criterion-specific observed checks; unrelated exit-zero artifacts do not qualify."""
import re
import hashlib
import json
from pathlib import Path
from evidence import source_identity


def wording_hashes(root):
    result = {}
    for name, _ in source_identity(root)['files']:
        if not name.endswith('.md'): continue
        text = (root / name).read_text(encoding='utf-8')
        if name == 'CLAIMS_EVIDENCE.md':
            normalized = []
            for line in text.splitlines():
                cells = line.split('|')
                links_only = (len(cells) == 7 and re.fullmatch(r'\s*\[[a-z0-9-]+\]\([^)]+\)(?:,\s*\[[a-z0-9-]+\]\([^)]+\))*\s*',cells[4]))
                if line.startswith('| C-') and links_only:
                    cells[4] = ' <live-validated evidence links> '
                    if cells[5].strip() in {'PASS','FAIL','BLOCKED','NOT RUN','NOT YET MEASURED'}:
                        cells[5] = ' <live-validated status> '
                    line = '|'.join(cells)
                normalized.append(line)
            text = '\n'.join(normalized) + '\n'
        result[name] = hashlib.sha256(text.encode()).hexdigest()
    return result


def coverage(data, root=None):
    root = Path(__file__).resolve().parents[1] if root is None else root
    names = set(data.get('python_test_names', []))
    rust = set(data.get('rust_test_names', []))
    sources = {name for name, _ in data.get('source_files', [])}
    result = set()
    if any(name.endswith('reject_forged_provenance_grant_source_and_snapshot') for name in rust): result.add('AC-012')
    if any(name.endswith('reject_context_and_snapshot_substitution_before_verification') for name in rust): result.add('AC-017')
    # These named cases execute Client.call against the Rust CLI, not the Python reference.
    if {'src/main.rs', 'tests/acceptance_locked/product_helpers.py', 'tests/acceptance_locked/test_product.py'} <= sources:
        for name in names:
            for number in re.findall(r'ac(\d{3})', name): result.add('AC-' + number)
        if 'test_frontend_and_binding_denials_have_zero_actual_scans' in names: result.update(('AC-001', 'AC-003'))
        if 'test_cli_duplicate_unknown_flags_and_no_required_keys' in names: result.add('AC-028')
        if 'test_actual_text_output_and_supplied_labels_are_escaped_offline' in names: result.add('AC-029')
    if 'test_symbolic_link_is_rejected' in names and {'test_even_allowlisted_env_resume_marker_and_credentials_fail',
            'test_exact_allowlist_and_missing_files', 'test_real_staging_and_zip_have_exact_regular_allowlist'} <= names:
        result.add('AC-016')
    evidence_controls = {'test_real_success_receipt', 'test_real_failure_receipt', 'test_real_timeout_receipt',
                         'test_missing_executable_receipt', 'test_output_tampering',
                         'test_nonexecutable_launch_retains_failed_receipt', 'test_timeout_stops_owned_descendant_before_next_gate',
                         'test_timeout_stops_descendant_after_its_root_has_exited',
                         'test_external_input_mutation_prevents_verification_pass',
                         'test_external_stdin_and_file_inputs_have_actual_hashes'}
    if evidence_controls <= names and {'scripts/evidence.py', 'tests/test_evidence.py'} <= sources: result.add('AC-026')
    if not all(any(name.endswith(check) for name in rust) for check in (
            'batch_conversion_observes_mid_column_cancellation', 'repeated_text_join_probe_keys_reserve_every_copy')):
        # Existing narrow budget cases alone do not establish the now-known conversion guarantee.
        result.discard('AC-015')
    for observation in data.get('observations', []):
        if (observation.get('license_audit_status') == 'PASS' and observation.get('errors') == []
                and observation.get('first_party_license') == 'MIT' and observation.get('registry_packages', 0) > 0
                and observation.get('preserved_notice_files', 0) >= observation['registry_packages']
                and re.fullmatch('[0-9a-f]{64}', observation.get('lockfile_sha256', ''))
                and {'Cargo.lock', 'scripts/license_audit.py', 'licenses/dependency-inventory.json', 'THIRD_PARTY_NOTICES.md'} <= sources):
            result.add('LICENSE-NOTICES')
        if (observation.get('review_kind') == 'independent-public-wording' and observation.get('review_status') == 'PASS'
                and observation.get('unsupported_maturity_claims') == [] and observation.get('inspection_only') is True
                and observation.get('reviewed_wording_sha256') and observation['reviewed_wording_sha256'] == wording_hashes(root)):
            result.add('PUBLIC-WORDING')
        if observation.get('status') == 'PASS' and observation.get('failures') == 0 and observation.get('binary_sha256'):
            if observation.get('cases', 0) >= 1000 and 'tests/property/differential.py' in sources and 'cases_by_format' not in observation:
                result.add('AC-006')
            if observation.get('cases', 0) >= 2000 and observation.get('cases_by_format') == {'json': 1000, 'sql': 1000}:
                result.add('MALFORMED-CORPUS')
        if (observation.get('instrumentation_status') == 'PASS' and observation.get('profile') == 'full'
                and observation.get('complete_grid') is True and observation.get('completed_cases') == 410
                and observation.get('invalid_observations') == 0 and observation.get('independent_semantic_comparisons',0) > 0):
            result.add('FULL-GRID-CAPTURE')
        if (observation.get('status') == 'PASS' and observation.get('profile') == 'full' and observation.get('observations_checked') == 43050
                and observation.get('cases_checked') == 410 and observation.get('current_product_source_matches_capture') is True
                and observation.get('required_success_cases_checked') == 290 and observation.get('independent_semantic_comparisons',0) > 0):
            result.add('FULL-GRID-VALIDATION')
        if observation.get('audit_status') == 'PASS' and observation.get('errors') == [] and 'scripts/release_audit.py' in sources:
            result.add('AC-027')
        reference = observation.get('reference_host_preflight')
        if reference and reference.get('status') == 'READY' and observation.get('allocation_receipt_stable') is True and observation.get('status') == 'PASS':
            targets = observation.get('filter_project_target_by_seed', [])
            if len(targets) == 5 and all(row.get('target_status') in ('MET', 'MISSED') and row.get('execution_ns',{}).get('n') == 30
                    and row.get('end_to_end_ns',{}).get('n') == 30 and row.get('independent_semantic_comparisons') == 60 for row in targets): result.add('AC-022')
            if observation.get('cancellation_reference_target', {}).get('status') in ('MET', 'MISSED'): result.add('AC-023')
        if observation.get('mode') == 'fresh-committed-Rust-checkout' and observation.get('status') == 'PASS' and observation.get('source_stable') is True and observation.get('cargo_target_dir_enforced_inside_fresh_clone') is True:
            commands = {row['target']: row['status'] for row in observation.get('commands', [])}
            if all(commands.get(target) == 'PASS' for target in ('bootstrap', 'verify', 'demo')): result.add('AC-024')
    return result


def required_sources(identifier, root):
    if identifier in {'AC-016'}: return {'scripts/export_policy.py', 'tests/security/test_export.py'}
    if identifier == 'AC-026': return {'scripts/evidence.py','scripts/owned_process.py', 'tests/test_evidence.py'}
    if identifier == 'AC-027': return {'scripts/release_audit.py', 'scripts/evidence_coverage.py', 'CLAIMS_EVIDENCE.md'}
    if identifier == 'AC-030':
        inventory = json.loads((root / 'licenses/dependency-inventory.json').read_bytes())
        expected_notices = set()
        for package in inventory['packages']:
            for notice in package['notices']:
                path = Path(notice['path'])
                if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'licenses':
                    raise ValueError('non-public notice path')
                expected_notices.add(path.as_posix())
        return {'Cargo.lock','LICENSE','scripts/license_audit.py','THIRD_PARTY_NOTICES.md'} | set(wording_hashes(root)) | expected_notices | {
            path.relative_to(root).as_posix() for path in (root / 'licenses').rglob('*') if path.is_file()}
    core = {file.relative_to(root).as_posix() for file in (root / 'src').rglob('*.rs') if 'bin' not in file.parts and file.name != 'seed.rs'}
    core |= {'Cargo.toml', 'Cargo.lock', 'ACCEPTANCE_SPEC.md', 'spec/acceptance.json', 'verification/spec-lock.json'}
    if identifier in {'AC-021', 'AC-022', 'AC-023'}:
        core |= {file.relative_to(root).as_posix() for file in (root / 'benchmarks').glob('*.py')}
        core.add('src/bin/rillscope-measure.rs')
    return core
