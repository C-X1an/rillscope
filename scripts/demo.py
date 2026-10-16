#!/usr/bin/env python3
"""Run actual fixed-scope Rust clients and independent SQLite; render offline HTML."""
from pathlib import Path
import argparse
import hashlib
import html
import json
import os
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from tools.fixed_scope import FixedScopeAdapter, ENVIRONMENT_KEYS
from product_build import bound_binary

LABEL = 'Escaped label <img src=x onerror="alert(1)">'
def digest(data): return hashlib.sha256(data).hexdigest()
def as_json(value): return json.dumps(value, indent=2, ensure_ascii=False) + '\n'

def oracle(catalog, tenant):
    table = catalog['tables']['sales']
    indices = {field['name']: i for i, field in enumerate(table['columns'])}
    with sqlite3.connect(':memory:') as database:
        database.execute('CREATE TABLE sales(id INTEGER NOT NULL, amount INTEGER)')
        # Physically materialize only this tenant and the granted columns before the query.
        values = [(row[indices['id']], row[indices['amount']]) for row in table['rows']
                  if row[indices['tenant']] == tenant]
        database.executemany('INSERT INTO sales VALUES (?,?)', values)
        return [list(row) for row in database.execute('SELECT COUNT(*), SUM(amount) FROM sales')]

def table(result):
    if result['status'] == 'error':
        error = result['error']
        return '<p class="denied">Rejected: <code>' + html.escape(error['code']) + '</code></p><p>' + html.escape(error['message']) + '</p>'
    fields = result['schema']
    head = ''.join('<th scope="col">' + html.escape(f['name']) + '<small>' + html.escape(f['type']) + (' · nullable' if f['nullable'] else ' · required') + '</small></th>' for f in fields)
    rows = ''.join('<tr>' + ''.join('<td>' + html.escape('NULL' if value is None else str(value)) + '</td>' for value in row) + '</tr>' for row in result['rows'])
    return '<div class="table-wrap"><table><caption>Actual Rust result</caption><thead><tr>' + head + '</tr></thead><tbody>' + rows + '</tbody></table></div>'

def render(cases, explain, label=LABEL):
    sections = []
    for case in cases:
        result = case['result']
        extra = ('<p class="match">Independent SQLite rows match exactly.</p><pre aria-label="SQLite result">' + html.escape(json.dumps(case['oracle_rows'])) + '</pre>') if 'oracle_rows' in case else '<p>No result rows were published.</p>'
        sections.append('<section id="' + html.escape(case['id'], quote=True) + '"><p class="eyebrow">' + html.escape(case['scope']) + '</p><h2>' + html.escape(case['title']) + '</h2>' + table(result) + extra + '</section>')
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>RillScope | Scoped query inspector</title><style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f4f6f2;color:#17231d;font:17px/1.6 system-ui,sans-serif}a{color:#145239;text-underline-offset:.2em}a:focus-visible,summary:focus-visible{outline:3px solid #925600;outline-offset:5px}.shell{max-width:68rem;margin:auto;padding:2.5rem 1.5rem}header{padding:2rem 0 3rem;border-bottom:2px solid #233d2d}.eyebrow{font-size:.8rem;font-weight:750;letter-spacing:.1em;text-transform:uppercase;color:#425a4a}h1{max-width:18ch;font-size:clamp(2.3rem,5vw,4.1rem);line-height:1.08;letter-spacing:-.035em;margin:1rem 0 1.5rem}h2{font-size:1.8rem;line-height:1.2;margin:.5rem 0 1.5rem}header p{max-width:60ch}nav{display:flex;gap:1.5rem;flex-wrap:wrap;margin-top:2rem}section{padding:2.5rem 0;border-bottom:1px solid #a7b4a9}.table-wrap{overflow:auto}table{border-collapse:collapse;min-width:22rem;width:100%;background:#fff}caption{text-align:left;font-size:.85rem;font-weight:650;padding-bottom:.6rem}th,td{border:1px solid #a7b4a9;padding:.85rem 1rem;text-align:left}th{background:#e3eae2}th small{display:block;font-size:.75rem;font-weight:400;color:#425a4a}td{font:1.4rem/1.5 ui-monospace,monospace}.match{font-weight:650;color:#145239}.denied{padding:1rem;border-left:4px solid #7a291e;background:#f5e4df;color:#642015;font-weight:650}code,pre{font:14px/1.6 ui-monospace,monospace}pre{max-width:100%;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;padding:1rem;background:#e7ece5;border:1px solid #a7b4a9}summary{cursor:pointer;font-weight:650;padding:.5rem 0}footer{padding:2rem 0;font-size:.9rem;color:#425a4a}@media(max-width:36rem){.shell{padding:1rem}header{padding-top:1rem}section{padding:2rem 0}th,td{padding:.7rem}nav{gap:1rem}}
</style></head><body><div class="shell"><header><p class="eyebrow">RillScope / Rust query inspector</p><h1>One query.<br>A fixed data scope.</h1><p>This offline report shows actual executions of the original Rust compiler and bounded executor. Two host-configured tenants receive separate results; a forbidden column fails before execution.</p><nav aria-label="Report sections"><a href="#allowed">Tenant alpha</a><a href="#denied">Forbidden column</a><a href="#second">Tenant beta</a><a href="#plan">Plan &amp; limits</a></nav></header><main>''' + ''.join(sections) + '''<section id="plan"><p class="eyebrow">Inspect the boundary</p><h2>Plan &amp; limits</h2><details><summary>Show redacted verified plan</summary><pre>''' + html.escape(json.dumps(explain, indent=2)) + '''</pre></details><p>The adapter accepts only query text/format and output choice. Catalog, context, tenant and budgets are host configuration. The core uses logical reservations and cooperative work limits; these do not impose an operating-system RSS limit.</p><p>Experimental local software. This report establishes these synthetic outcomes, not production readiness or complete security coverage.</p><p>Supplied label, displayed as text: <code>''' + html.escape(label) + '''</code></p></section></main><footer><p>No scripts, external fonts or service requests. Synthetic fixtures only. Inputs, exact results, hashes and command provenance are saved alongside this report.</p></footer></div></body></html>'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists(): parser.error('output directory must be new')
    bound_binary()
    binary = ROOT / 'target/debug' / ('rillscope.exe' if os.name == 'nt' else 'rillscope')
    catalog_path = ROOT / 'examples/catalog.json'
    alpha_path, beta_path = ROOT / 'examples/context.json', ROOT / 'examples/context-beta.json'
    query_data = (ROOT / 'examples/query.json').read_text(encoding='utf-8')
    forbidden = (ROOT / 'examples/forbidden.json').read_text(encoding='utf-8')
    alpha = FixedScopeAdapter(binary=binary, catalog=catalog_path, context=alpha_path)
    beta = FixedScopeAdapter(binary=binary, catalog=catalog_path, context=beta_path)
    def call(client, source, output='rows'):
        return client.call({'query': {'format': 'json', 'source': source}, 'output': output})
    allowed, denied, second = call(alpha, query_data), call(alpha, forbidden), call(beta, query_data)
    explain = call(alpha, query_data, 'explain')
    cat = json.loads(catalog_path.read_bytes())
    expected_alpha, expected_beta = oracle(cat, 'alpha'), oracle(cat, 'beta')
    assert allowed['implementation'] == second['implementation'] == denied['implementation'] == 'rust'
    assert allowed['status'] == second['status'] == explain['status'] == 'ok'
    assert allowed['rows'] == expected_alpha == [[3, 40]]
    assert second['rows'] == expected_beta == [[1, 999]]
    assert denied['status'] == 'error' and denied['error']['code'] == 'E_FORBIDDEN' and 'rows' not in denied
    cases = [{'id': 'allowed', 'scope': 'Trusted context · alpha', 'title': 'Authorized aggregate', 'result': allowed, 'oracle_rows': expected_alpha},
             {'id': 'denied', 'scope': 'Trusted context · alpha', 'title': 'Forbidden column', 'result': denied},
             {'id': 'second', 'scope': 'Trusted context · beta', 'title': 'A separate tenant result', 'result': second, 'oracle_rows': expected_beta}]
    payload = as_json({'cases': cases, 'explain': explain}).encode('utf-8')
    report = render(cases, explain).encode('utf-8')
    for canary in ('private-a', 'private-b', 'private-c', 'private-d'):
        assert canary.encode() not in report and canary.encode() not in payload
    args.out.mkdir(parents=True)
    (args.out / 'results.json').write_bytes(payload)
    (args.out / 'report.html').write_bytes(report)
    inputs = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in
              (catalog_path, alpha_path, beta_path, ROOT / 'examples/query.json', ROOT / 'examples/forbidden.json')}
    manifest = {'implementation': 'rust', 'cases': 3, 'oracle': 'SQLite on independently materialized authorized relations',
                'sqlite_version': sqlite3.sqlite_version, 'binary_sha256': digest(binary.read_bytes()),
                'inputs_sha256': inputs, 'results_sha256': digest(payload), 'report_sha256': digest(report),
                'environment_keys_forwarded': list(ENVIRONMENT_KEYS), 'browser_visual_review': 'NOT RUN by this generator'}
    manifest['process_calls'] = [
        {'case': case, 'argv_relative_to_repository': ['target/debug/' + binary.name, command, '--catalog', 'examples/catalog.json', '--context', context, '--query', '-', '--format', 'json'],
         'stdin_sha256': digest(source.encode('utf-8'))}
        for case, command, context, source in [('allowed', 'run', 'examples/context.json', query_data),
                                               ('denied', 'run', 'examples/context.json', forbidden),
                                               ('second', 'run', 'examples/context-beta.json', query_data),
                                               ('explain', 'explain', 'examples/context.json', query_data)]
    ]
    (args.out / 'manifest.json').write_text(as_json(manifest), encoding='utf-8')
    print(json.dumps({'implementation': 'rust', 'cases': 3, 'report': str(args.out / 'report.html'),
                      'report_sha256': digest(report), 'oracle_match': True}))
    return 0

if __name__ == '__main__': raise SystemExit(main())
