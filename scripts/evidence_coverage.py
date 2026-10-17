"""Criterion-specific observed checks; unrelated exit-zero artifacts do not qualify."""
import re
import hashlib
import json
from pathlib import Path
from evidence import source_identity


def wording_hashes(root):
    result = {}
    # Published reports/images can make assertions too. Include generated public
    # artifacts while pruning only implementation caches and Git metadata.
    candidates, pending = [], [root]
    generators = {'scripts/demo.py','scripts/demo_reference.py','tools/fixed_scope.py'}
    while pending:
        for path in pending.pop().iterdir():
            if path.name in {'.git','.local-runs','target','__pycache__'}: continue
            if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()):
                raise ValueError('wording binding cannot follow a symbolic link')
            if path.is_dir(): pending.append(path)
            elif path.is_file(): candidates.append(path)
    for path in sorted(candidates):
        name = path.relative_to(root).as_posix()
        if path.suffix.lower() not in {'.md','.html','.htm','.svg','.png','.jpg','.jpeg','.webp'} and name not in generators: continue
        if path.suffix.lower() in {'.png','.jpg','.jpeg','.webp'}:
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            continue
        text = path.read_text(encoding='utf-8')
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


def applied_publication_clarification(observation, root):
    """A recorded experiment cannot approve an unapplied interpretation."""
    try:
        record = json.loads((root/'spec/ac018-clarification.json').read_bytes())
        review = record['independent_assessment']
        return (record['criterion'] == 'AC-018' and record['status'] == 'APPLIED'
                and record['decision'] == 'final-success-path-atomic-cancellation-decision'
                and record['clarification_path'] == 'TEST_SPEC_EXCEPTION_AC-018.md'
                and record['clarification_sha256'] == hashlib.sha256((root/record['clarification_path']).read_bytes()).hexdigest()
                and record['contract_lock_sha256'] == hashlib.sha256((root/'verification/spec-lock.json').read_bytes()).hexdigest()
                and review['status'] == 'RECOMMENDED' and review['independent_runtime_execution'] is False
                and review['instruction_disassembly_sha256'] == observation['instruction_disassembly_sha256']
                and all(record[key] == observation[key] for key in ('remote_repository','remote_commit','remote_run_id',
                    'remote_job_id','remote_artifact_id','remote_artifact_sha256')))
    except (OSError, ValueError, KeyError, TypeError):
        return False


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
        if {'test_ac018_actual_cli_cancel_before_publication','test_ac018_actual_cli_row_and_byte_caps'} <= names:
            result.add('OUTPUT-CAPS')
    if 'test_symbolic_link_is_rejected' in names and {'test_even_allowlisted_env_resume_marker_and_credentials_fail',
            'test_exact_allowlist_and_missing_files', 'test_real_staging_and_zip_have_exact_regular_allowlist'} <= names:
        result.add('AC-016')
    evidence_controls = {'test_real_success_receipt', 'test_real_failure_receipt', 'test_real_timeout_receipt',
                         'test_missing_executable_receipt', 'test_output_tampering',
                         'test_nonexecutable_launch_retains_failed_receipt', 'test_timeout_stops_owned_descendant_before_next_gate',
                         'test_timeout_stops_descendant_after_its_root_has_exited',
                         'test_successful_parent_stops_detached_output_worker_before_receipt',
                         'test_successful_parent_stops_new_session_worker_before_receipt',
                         'test_external_input_mutation_prevents_verification_pass',
                         'test_external_stdin_and_file_inputs_have_actual_hashes'}
    if evidence_controls <= names and {'scripts/evidence.py', 'tests/test_evidence.py'} <= sources: result.add('AC-026')
    if not all(any(name.endswith(check) for name in rust) for check in (
            'batch_conversion_observes_mid_column_cancellation', 'repeated_text_join_probe_keys_reserve_every_copy')):
        # Existing narrow budget cases alone do not establish the now-known conversion guarantee.
        result.discard('AC-015')
    for observation in data.get('observations', []):
        if (observation.get('status') == 'PASS' and observation.get('campaign') == 'recorded-final-cancellation-validation'
                and observation.get('cases') == 5 and observation.get('signals') == ['SIGINT','SIGTERM']
                and observation.get('behavioral_control_sequence') == ['PASS','FAIL','PASS']
                and observation.get('current_product_source_matches_capture') is True
                and observation.get('remote_repository') == 'C-X1an/rillscope'
                and observation.get('remote_job_name') == 'publication-boundary'
                and observation.get('remote_job_conclusion') == 'success'
                and 'ubuntu-24.04' in observation.get('remote_runner_labels',[])
                and re.fullmatch('[0-9a-f]{64}',observation.get('remote_artifact_sha256',''))
                and {'scripts/verify_publication_evidence.py','tests/system/publication_decision.py',
                     'tests/system/publication_mutation.py'} <= sources
                and applied_publication_clarification(observation,root)):
            result.update(('AC-018','FINAL-CANCELLATION'))
        if (observation.get('status') == 'PASS' and observation.get('campaign') == 'observed-public-linux-CI'
                and observation.get('remote_repository') == 'C-X1an/rillscope'
                and observation.get('remote_job_conclusion') == 'success'
                and 'ubuntu-24.04' in observation.get('remote_runner_labels',[])
                and re.fullmatch('[0-9a-f]{40}',observation.get('remote_commit',''))
                and re.fullmatch('[0-9a-f]{64}',observation.get('remote_log_sha256',''))
                and 'scripts/verify_ci_observations.py' in sources):
            from verify_ci_observations import REMOTE_SOURCES
            remote = dict(observation.get('remote_source_files',[]))
            remote_names = set(observation.get('remote_python_test_names',[]))
            def remote_matches(identifier):
                return all((root / name).is_file() and remote.get(name) == hashlib.sha256((root / name).read_bytes()).hexdigest()
                           for name in REMOTE_SOURCES[identifier])
            if (observation.get('remote_job_name') == 'rust-product' and remote_matches('AC-016')
                    and {'test_symbolic_link_is_rejected','test_even_allowlisted_env_resume_marker_and_credentials_fail',
                         'test_exact_allowlist_and_missing_files','test_real_staging_and_zip_have_exact_regular_allowlist'} <= remote_names):
                result.add('AC-016')
            if remote_matches('AC-026') and evidence_controls <= remote_names:
                result.update(('AC-026','LINUX-COMMAND-LIFETIME'))
        if (observation.get('status') == 'PASS' and observation.get('campaign') == 'fresh-committed-Rust-demo'
                and observation.get('fresh_checkout') is True and observation.get('recorded_make_demo_status') == 'PASS'
                and observation.get('current_execution_source_identity_matches') is True
                and observation.get('captured_generator_report_matches') is True
                and observation.get('captured_generator_artifacts_match') is True
                and observation.get('implementation') == 'rust' and observation.get('cases') == 3
                and observation.get('oracle_match') is True and observation.get('browser_review_status') == 'RECORDED'
                and re.fullmatch('[0-9a-f]{40}',observation.get('fresh_checkout_commit',''))
                and re.fullmatch('[0-9a-f]{64}',observation.get('report_sha256',''))
                and re.fullmatch('[0-9a-f]{64}',observation.get('browser_record_sha256',''))
                and len(observation.get('actual_screenshot_sha256',[])) >= 2
                and all(re.fullmatch('[0-9a-f]{64}',value) for value in observation['actual_screenshot_sha256'])
                and 'scripts/verify_demo_evidence.py' in sources):
            result.add('AC-008')
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
                and observation.get('evidence_schema_version') == 3 and observation.get('build_provenance_status') == 'RECORDED'
                and observation.get('current_release_evidence_qualified') is True
                and observation.get('required_success_cases_checked') == 290 and observation.get('independent_semantic_comparisons',0) > 0):
            result.add('FULL-GRID-VALIDATION')
        if (observation.get('status') == 'PASS' and observation.get('profile') == 'sort-null-supplement'
                and observation.get('observations_checked') == 4200 and observation.get('cases_checked') == 40
                and observation.get('required_success_cases_checked') == 40
                and observation.get('current_release_evidence_qualified') is True
                and observation.get('independent_semantic_comparisons') == 2400):
            result.add('NULL-SORT-VALIDATION')
        if observation.get('audit_status') == 'PASS' and observation.get('errors') == [] and 'scripts/release_audit.py' in sources:
            result.add('AC-027')
        reference = observation.get('reference_host_preflight')
        if (reference and reference.get('status') == 'READY' and observation.get('allocation_receipt_stable') is True
                and observation.get('status') == 'PASS' and observation.get('experiment_environment_errors') == []
                and set(observation.get('experiment_environments',{})) == {'grid-start','grid-end','cancellation-start','cancellation-end','wrapper-end'}):
            targets = observation.get('filter_project_target_by_seed', [])
            if len(targets) == 5 and all(row.get('target_status') in ('MET', 'MISSED') and row.get('execution_ns',{}).get('n') == 30
                    and row.get('end_to_end_ns',{}).get('n') == 30 and row.get('independent_semantic_comparisons') == 60 for row in targets): result.add('AC-022')
            if observation.get('cancellation_reference_target', {}).get('status') in ('MET', 'MISSED'): result.add('AC-023')
        if observation.get('mode') == 'fresh-committed-Rust-checkout' and observation.get('status') == 'PASS' and observation.get('source_stable') is True and observation.get('cargo_target_dir_enforced_inside_fresh_clone') is True:
            commands = {row['target']: row['status'] for row in observation.get('commands', [])}
            if all(commands.get(target) == 'PASS' for target in ('bootstrap', 'verify', 'demo')): result.add('AC-024')
    return result


def license_sources(root):
    inventory = json.loads((root / 'licenses/dependency-inventory.json').read_bytes())
    expected_notices = set()
    for package in inventory['packages']:
        for notice in package['notices']:
            path = Path(notice['path'])
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'licenses':
                raise ValueError('non-public notice path')
            expected_notices.add(path.as_posix())
    return {'Cargo.lock','LICENSE','scripts/license_audit.py','THIRD_PARTY_NOTICES.md'} | expected_notices | {
        path.relative_to(root).as_posix() for path in (root / 'licenses').rglob('*') if path.is_file()}


def required_sources(identifier, root):
    if identifier in {'AC-016'}: return {'scripts/export_policy.py', 'tests/security/test_export.py','scripts/verify_ci_observations.py'}
    if identifier == 'AC-026': return {'scripts/evidence.py','scripts/owned_process.py', 'tests/test_evidence.py','tests/test_review_427.py','tests/test_review_e7.py','scripts/verify_ci_observations.py'}
    if identifier == 'AC-027': return {'scripts/release_audit.py', 'scripts/evidence_coverage.py', 'CLAIMS_EVIDENCE.md'}
    if identifier == 'AC-030': return license_sources(root) | set(wording_hashes(root))
    core = {file.relative_to(root).as_posix() for file in (root / 'src').rglob('*.rs') if 'bin' not in file.parts and file.name != 'seed.rs'}
    core |= {'Cargo.toml', 'Cargo.lock', 'ACCEPTANCE_SPEC.md', 'spec/acceptance.json', 'verification/spec-lock.json'}
    if identifier == 'AC-018':
        core |= {'rust-toolchain.toml','TEST_SPEC_EXCEPTION_AC-018.md','spec/ac018-clarification.json','scripts/verify_publication_evidence.py',
                 'scripts/product_build.py','benchmarks/build.py','scripts/evidence.py',
                 'scripts/verify_ci_observations.py','tests/acceptance_locked/test_product.py',
                 'tests/acceptance_locked/product_helpers.py','tests/system/publication_decision.py',
                 'tests/system/publication_mutation.py','tests/system/publication_record_control.py'}
    if identifier == 'AC-024':
        # A historical fresh checkout cannot approve a changed verification
        # recipe or a narrowed test/measurement/security procedure.
        core |= {'Makefile','rust-toolchain.toml','deny.toml'}
        for folder in ('scripts','tests','tools','benchmarks','.github'):
            core |= {path.relative_to(root).as_posix() for path in (root / folder).rglob('*')
                     if path.is_file() and path.suffix in ('.py','.yml','.yaml')}
    if identifier in {'AC-008','AC-029'}:
        core |= {'scripts/demo.py','tools/fixed_scope.py','tests/acceptance_locked/test_demo.py',
                 'tests/acceptance_locked/product_helpers.py'}
        if identifier == 'AC-008': core.add('scripts/verify_demo_evidence.py')
    if identifier in {'AC-021', 'AC-022', 'AC-023'}:
        core |= {file.relative_to(root).as_posix() for file in (root / 'benchmarks').glob('*.py')}
        core.add('src/bin/rillscope-measure.rs')
    return core
