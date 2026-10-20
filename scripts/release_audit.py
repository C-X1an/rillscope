#!/usr/bin/env python3
"""Audit claim/evidence links and locked coverage; never infer unrun acceptance."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from evidence_coverage import coverage, license_sources, required_sources, performance_dependency_path

ROOT = Path(__file__).resolve().parents[1]
STATUSES = {'PASS', 'FAIL', 'BLOCKED', 'NOT RUN', 'NOT YET MEASURED'}


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def public_file(name, allow_missing=False):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts: raise ValueError('non-public evidence path')
    path = ROOT / relative
    for component in (path, *path.parents):
        if component == ROOT: break
        if component.is_symlink() or (hasattr(component, 'is_junction') and component.is_junction()):
            raise ValueError('evidence cannot traverse a symbolic link/reparse point')
    if not path.resolve().is_relative_to(ROOT) or (not path.is_file() and not (allow_missing and not path.exists())):
        raise ValueError('missing/non-regular public evidence file')
    return path


def audit(index, require_all=False):
    errors, unproved, historical, stale_requirements = [], [], [], []
    locked = {row['id'] for row in json.loads((ROOT / 'spec/acceptance.json').read_bytes())['criteria']}
    if set(index['criteria']) != locked: errors.append('evidence index must cover exactly the thirty locked criteria')
    artifacts = {}
    observed = set()
    for name, artifact in index['artifacts'].items():
        path = public_file(artifact['path'])
        if digest(path) != artifact['sha256']: errors.append('public evidence digest mismatch: ' + name)
        data = json.loads(path.read_bytes())
        artifacts[name] = data
        observed.update(coverage(data,ROOT))
        if not data.get('source_files') or any(not re.fullmatch('[0-9a-f]{64}', data.get(key, '')) for key in ('source_before_sha256', 'source_after_sha256', 'raw_stdout_sha256', 'raw_stderr_sha256')):
            errors.append('required source/output provenance missing: ' + name)
        if data.get('status') == 'PASS' and (data.get('exit_code') != 0 or data.get('source_before_sha256') != data.get('source_after_sha256')):
            errors.append('passing run lacks exit-zero/stable-source provenance: ' + name)
        # Old evidence stays visible as dated evidence. It cannot establish a new all-green release.
        for source, expected in data.get('source_files', []):
            if source.startswith(('src/', 'tests/', 'tools/', 'benchmarks/', 'scripts/','licenses/')) or source.endswith('.md') or source in ('Cargo.toml', 'Cargo.lock', 'Makefile','LICENSE'):
                file = public_file(source,allow_missing=True)
                if not file.is_file() or digest(file) != expected:
                    historical.append(name); break
    table = (ROOT / 'CLAIMS_EVIDENCE.md').read_text(encoding='utf-8')
    for identifier in sorted(locked):
        row = index['criteria'].get(identifier)
        if row is None: continue
        if row['status'] not in STATUSES: errors.append('unknown status: ' + identifier)
        matching = [line for line in table.splitlines() if line.startswith('| C-' + identifier[3:] + ':')]
        if len(matching) != 1 or not matching[0].endswith('| ' + row['status'] + ' |'):
            errors.append('claim table/index status differs: ' + identifier)
        if len(matching) == 1:
            cells = matching[0].split('|')
            links = re.findall(r'\[[^\]]+\]\(([^)]+)\)', cells[4]) if len(cells) == 7 else []
            expected_links = [index['artifacts'][name]['path'] for name in row['runs'] if name in index['artifacts']]
            if sorted(links) != sorted(expected_links): errors.append('claim Markdown links/index artifacts differ: ' + identifier)
            for link in links:
                try: public_file(link)
                except ValueError: errors.append('claim Markdown evidence link is missing/invalid: ' + identifier)
            expected_cell = ', '.join('[' + name + '](' + index['artifacts'][name]['path'] + ')' for name in row['runs'] if name in index['artifacts']) or row['scope']
            if len(cells) != 7 or cells[4].strip() != expected_cell:
                errors.append('claim evidence field is not the canonical live-validated index value: ' + identifier)
        if row['status'] != 'PASS': unproved.append(identifier + ': ' + row['status'])
        if row['status'] == 'PASS' and not row['runs']: errors.append('PASS claim lacks evidence: ' + identifier)
        for name in row['runs']:
            if name not in artifacts: errors.append('claim references missing artifact: ' + identifier)
            elif row['status'] == 'PASS' and artifacts[name]['status'] != 'PASS':
                errors.append('PASS claim references a nonpassing run: ' + identifier)
        if row['status'] == 'PASS':
            selected = [artifacts[name] for name in row['runs'] if name in artifacts]
            subjects = set().union(*(coverage(data,ROOT) for data in selected))
            if identifier == 'AC-025':
                static = any({'fmt', 'lint', 'check', 'test'} <= set(data.get('executed_targets', [])) for data in selected)
                if 'MALFORMED-CORPUS' not in subjects or not static: errors.append('static/malformed criterion evidence missing: ' + identifier)
            elif identifier == 'AC-030':
                if not {'LICENSE-NOTICES', 'PUBLIC-WORDING'} <= subjects: errors.append('license/notices and independent wording evidence missing: ' + identifier)
            elif identifier == 'AC-018':
                if not {'AC-018','OUTPUT-CAPS','FINAL-CANCELLATION'} <= subjects:
                    errors.append('ordinary output/cancel tests and explicitly disposed final-boundary evidence missing: ' + identifier)
            elif identifier == 'AC-021':
                if not {'FULL-GRID-CAPTURE','FULL-GRID-VALIDATION','NULL-SORT-VALIDATION'} <= subjects:
                    errors.append('criterion-specific executed observation missing: ' + identifier)
                    errors.append('full captured grid and current-product artifact validation missing: ' + identifier)
            elif identifier == 'AC-026':
                if not {'AC-026','LINUX-COMMAND-LIFETIME'} <= subjects:
                    errors.append('current runner controls and actual Linux descendant-lifetime evidence missing: ' + identifier)
            elif identifier not in subjects: errors.append('criterion-specific executed observation missing: ' + identifier)
            # Coverage and freshness must come from the same qualifying run.
            # A current exit-zero receipt cannot refresh an unrelated old proof.
            if identifier == 'AC-030':
                source_candidates = [data for data in selected if 'LICENSE-NOTICES' in coverage(data,ROOT)]
            elif identifier == 'AC-021':
                source_candidates = [data for data in selected if
                                     {'FULL-GRID-VALIDATION','NULL-SORT-VALIDATION'} & coverage(data,ROOT)]
            elif identifier == 'AC-025':
                source_candidates = [data for data in selected if 'MALFORMED-CORPUS' in coverage(data,ROOT)
                                     or {'fmt','lint','check','test'} <= set(data.get('executed_targets',[]))]
            else:
                source_candidates = [data for data in selected if identifier in coverage(data,ROOT)]
            supplied = set().union(*({source for source, _ in data.get('source_files', [])} for data in source_candidates))
            # A full live-validated PUBLIC-WORDING map supplies wording coverage.
            # License obligations remain separate, including overlapping prose.
            needed = license_sources(ROOT) if identifier == 'AC-030' else required_sources(identifier, ROOT)
            missing = needed - supplied
            if missing: errors.append('criterion source coverage missing: ' + identifier + ': ' + ', '.join(sorted(missing)))
            current_sources = {}
            for source in needed - missing:
                # This invocation reads and validates the live claim table above.
                # Its proof-link/status fields cannot hash their own future receipt.
                if identifier == 'AC-027' and source == 'CLAIMS_EVIDENCE.md': continue
                file = public_file(source,allow_missing=True)
                current = digest(file) if file.is_file() else None
                current_sources[source] = current
                if current is None or not any([source,current] in data['source_files'] for data in source_candidates):
                    stale_requirements.append(identifier + ': ' + source)
            if identifier in {'AC-024','AC-030'} and (missing or not any(
                    all(current_sources.get(source) is not None and [source,current_sources[source]] in data['source_files']
                        for source in needed) for data in source_candidates)):
                stale_requirements.append(identifier + ': no single qualifying run matches the complete required source set')
            if identifier == 'AC-018':
                ordinary_tests = {'tests/acceptance_locked/test_product.py','tests/acceptance_locked/product_helpers.py'}
                ordinary = required_sources('AC-001',ROOT) | ordinary_tests | {
                    'rust-toolchain.toml','scripts/product_build.py','benchmarks/build.py','scripts/evidence.py'}
                boundary = needed - ordinary_tests
                for subject,dependencies in (('OUTPUT-CAPS',ordinary),('FINAL-CANCELLATION',boundary)):
                    candidates = [data for data in selected if subject in coverage(data,ROOT)]
                    if not any(all(current_sources.get(source) is not None and
                            [source,current_sources[source]] in data['source_files'] for source in dependencies)
                            for data in candidates):
                        stale_requirements.append(identifier + ': no single current ' + subject + ' run matches its complete dependency set')
            if identifier in {'AC-021', 'AC-022', 'AC-023', 'AC-025'}:
                def complete_current(data):
                    if not all(current_sources.get(source) is not None
                            and [source, current_sources[source]] in data['source_files'] for source in needed):
                        return False
                    # A removed executable must not disappear from an older
                    # proof's dependency set merely because discovery is live.
                    for source, expected in data['source_files']:
                        if (performance_dependency_path(source) or identifier == 'AC-025'
                                and source.startswith('tests/') and source.endswith('.py')):
                            file = public_file(source, allow_missing=True)
                            if not file.is_file() or digest(file) != expected: return False
                    return True
                subjects = (('FULL-GRID-CAPTURE', 'FULL-GRID-VALIDATION', 'NULL-SORT-VALIDATION')
                    if identifier == 'AC-021' else ('STATIC-CHECKS', 'MALFORMED-CORPUS')
                    if identifier == 'AC-025' else (identifier,))
                for subject in subjects:
                    candidates = [data for data in selected if
                        ({'fmt', 'lint', 'check', 'test'} <= set(data.get('executed_targets', []))
                         if subject == 'STATIC-CHECKS' else subject in coverage(data, ROOT))]
                    if not any(complete_current(data) for data in candidates):
                        stale_requirements.append(identifier + ': no single current ' + subject
                            + ' run matches its complete dependency set')
    referenced = {name for row in index['criteria'].values() if row['status'] == 'PASS' for name in row['runs']}
    if require_all:
        errors += ['unproved required criterion: ' + value for value in unproved]
        errors += ['current criterion source evidence missing: ' + value for value in stale_requirements]
    return {'audit_status': 'FAIL' if errors else 'PASS', 'all_declared_criteria_have_current_passing_evidence_links': not unproved and not stale_requirements and not errors,
            'criterion_status_counts': dict(Counter(row['status'] for row in index['criteria'].values())),
            'unproved': unproved, 'historical_source_evidence': sorted(set(historical)), 'errors': errors,
            'stale_required_sources': sorted(set(stale_requirements)),
            'scope': 'public claim status/link/digest/provenance audit; no new runtime execution or independent prose review',
            'claims_sha256': digest(ROOT / 'CLAIMS_EVIDENCE.md'),
            'wording_binding': 'public Markdown, HTML, static report assets and generation code; canonical evidence-link/status fields are validated live against the index'}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--require-all', action='store_true')
    parser.add_argument('--index', type=Path, default=ROOT / 'verification/product/index.json'); args = parser.parse_args()
    try: result = audit(json.loads(args.index.read_bytes()), args.require_all)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {'audit_status': 'FAIL', 'errors': ['missing/invalid release evidence: ' + type(error).__name__]}
    print(json.dumps(result, indent=2))
    return 0 if result['audit_status'] == 'PASS' else 78


if __name__ == '__main__': raise SystemExit(main())
