#!/usr/bin/env python3
"""Execute real reference cases and render escaped script-free HTML evidence."""
from pathlib import Path
import argparse
import html
import json
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.reference.engine import Limits, evaluate, strict_loads


def render(cases):
    articles = []
    for name, result in cases:
        articles.append('<section><h2>' + html.escape(name) + '</h2><pre>' + html.escape(json.dumps(result, indent=2, ensure_ascii=False)) + '</pre></section>')
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>RillScope | Reference laboratory</title><style>body{max-width:68rem;margin:3rem auto;padding:0 1.5rem;font:17px/1.65 system-ui,sans-serif}header{border-bottom:2px solid;padding-bottom:1.5rem}h1{font-size:3rem;line-height:1.1}h2{margin-top:2rem}pre{overflow:auto;padding:1.25rem;border:1px solid;border-radius:.5rem;font:14px/1.5 monospace}.label{font-weight:700;letter-spacing:.1em;text-transform:uppercase}footer{border-top:1px solid;margin-top:3rem;padding-top:1rem}@media(prefers-color-scheme:dark){body{background:#101820;color:#edf4f8}pre{background:#16232e}}@media(prefers-color-scheme:light){body{background:#fafbfc;color:#182333}pre{background:#fff}}</style></head><body><header><p class="label">RillScope / Executable reference</p><h1>Make query authority<br>part of the plan.</h1><p>Three actual Python-reference executions. No external scripts, requests or model API. This is not the Rust engine, a production security boundary or performance evidence.</p></header><main>''' + ''.join(articles) + '''</main><footer><p>Inputs: repository synthetic catalog and fixed alpha-tenant context. All text is HTML-escaped. Inspect source and verification records before interpreting claims.</p></footer></body></html>'''


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True); args = parser.parse_args()
    if args.out.exists(): parser.error('output directory must be new')
    args.out.mkdir(parents=True)
    cat, ctx = (strict_loads((ROOT / 'examples' / x).read_text()) for x in ('catalog.json', 'context.json'))
    q = strict_loads((ROOT / 'examples/query.json').read_text())
    bad = strict_loads((ROOT / 'examples/forbidden.json').read_text())
    cases = [('Authorized aggregate', evaluate(cat, ctx, q)), ('Forbidden column', evaluate(cat, ctx, bad)),
             ('Resource exhaustion', evaluate(cat, ctx, q, Limits(work=1)))]
    assert cases[0][1]['rows'] == [[3, 40]]
    assert cases[1][1]['error']['code'] == 'E_FORBIDDEN'
    assert cases[2][1]['error']['code'] == 'E_BUDGET'
    (args.out / 'results.json').write_text(json.dumps(cases, indent=2) + '\n')
    (args.out / 'report.html').write_text(render(cases))
    print(json.dumps({'implementation': 'python-reference', 'cases': len(cases), 'report': str(args.out / 'report.html')}))
    return 0

if __name__ == '__main__': raise SystemExit(main())
