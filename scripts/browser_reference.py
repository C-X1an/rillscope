#!/usr/bin/env python3
"""Optional real-browser QA of the generated reference report; requires Playwright."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--chromium', default=None)
    args = parser.parse_args()
    if not args.report.is_file(): parser.error('report does not exist')
    if args.out.exists(): parser.error('output directory must be new')
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print('BLOCKED: optional Playwright is not installed', file=sys.stderr)
        return 77
    executable = args.chromium or shutil.which('chromium') or shutil.which('chromium-browser')
    if not executable:
        print('BLOCKED: a Chromium executable is required', file=sys.stderr)
        return 77
    args.out.mkdir(parents=True)
    observations = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=executable, headless=True, args=['--no-sandbox'])
        version = browser.version
        for name, width, height in [('desktop', 1440, 1000), ('mobile', 390, 844)]:
            page = browser.new_page(viewport={'width': width, 'height': height}, color_scheme='light')
            errors, remote = [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda req: remote.append(req.url) if req.url.startswith(('http:', 'https:')) else None)
            page.set_content(args.report.read_text(), wait_until='load')
            values = page.evaluate('''() => ({lang: document.documentElement.lang,
                h1: document.querySelectorAll('h1').length,
                sections: document.querySelectorAll('main section').length,
                horizontalOverflow: document.documentElement.scrollWidth > window.innerWidth,
                title: document.title, text: document.body.innerText})''')
            checks = {'english_lang': values['lang'] == 'en', 'one_h1': values['h1'] == 1,
                      'three_executions': values['sections'] == 3,
                      'no_page_overflow': not values['horizontalOverflow'],
                      'reference_label': 'This is not the Rust engine' in values['text'],
                      'no_script_errors': not errors, 'no_external_requests': not remote}
            page.screenshot(path=str(args.out / f'{name}.png'), full_page=True)
            observations.append({'viewport': {'width': width, 'height': height}, 'name': name,
                                 'checks': checks, 'errors': errors, 'external_requests': remote})
            page.close()
        browser.close()
    result = {'implementation': 'python-reference', 'browser': 'Chromium', 'version': version,
              'report_sha256': hashlib.sha256(args.report.read_bytes()).hexdigest(),
              'load_method': 'in-memory exact HTML bytes; file URL navigation is not tested',
              'observations': observations,
              'limitations': 'Layout and selected semantic checks only; not a full accessibility audit or Rust end-to-end test.'}
    (args.out / 'observations.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if all(all(item['checks'].values()) for item in observations) else 1


if __name__ == '__main__': raise SystemExit(main())
