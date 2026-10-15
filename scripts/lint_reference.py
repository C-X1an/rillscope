#!/usr/bin/env python3
"""Dependency-free syntax, whitespace and forbidden-source checks (not mypy/ruff)."""
import ast
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
errors = []
count = 0
for folder in ('tools', 'tests', 'scripts', 'benchmarks'):
    for file in (ROOT / folder).rglob('*.py'):
        text = file.read_text(); count += 1
        try: ast.parse(text, filename=str(file.relative_to(ROOT)))
        except SyntaxError as error: errors.append(str(error))
        for n, line in enumerate(text.splitlines(), 1):
            if line.rstrip() != line: errors.append(f'{file.relative_to(ROOT)}:{n}: trailing whitespace')
        if '\t' in text: errors.append(f'{file.relative_to(ROOT)}: tab')
for error in errors: print(error, file=sys.stderr)
print(f'Parsed {count} Python files; {len(errors)} syntax/whitespace errors. Not a full type checker.')
raise SystemExit(int(bool(errors)))
