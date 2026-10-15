#!/usr/bin/env python3
"""Independent baseline: physically scoped relations, with separately labeled timers."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import time

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--measurement', type=Path, required=True); args = parser.parse_args()
    started = time.perf_counter_ns()
    catalog = json.loads((args.case / 'catalog.json').read_bytes())
    context = json.loads((args.case / 'context.json').read_bytes())
    spec = json.loads((args.case / 'case.json').read_bytes())
    database = sqlite3.connect(':memory:')
    for name, table in catalog['tables'].items():
        grant = context['tables'][name]
        by_name = {field['name']: i for i, field in enumerate(table['columns'])}
        names = grant['columns']
        types = {'i64': 'INTEGER', 'bool': 'INTEGER', 'text': 'TEXT'}
        declarations = [column + ' ' + types[table['columns'][by_name[column]]['type']] for column in names]
        database.execute('CREATE TABLE ' + name + '(' + ','.join(declarations) + ')')
        # No tenant predicate is injected into SQL. Only physically authorized cells enter SQLite.
        values = ([row[by_name[column]] for column in names] for row in table['rows'] if row[by_name[grant['tenant_column']]] == context['tenant'])
        database.executemany('INSERT INTO ' + name + ' VALUES (' + ','.join('?' for _ in names) + ')', values)
    materialization_ns = time.perf_counter_ns() - started
    executed = time.perf_counter_ns()
    rows = [list(row) for row in database.execute(spec['sql'])]
    execution_only_ns = time.perf_counter_ns() - executed
    for row in rows:
        for index, field in enumerate(spec['schema']):
            if field['type'] == 'bool' and row[index] is not None: row[index] = bool(row[index])
    result = {'version': 1, 'status': 'ok', 'implementation': 'sqlite-baseline', 'schema': spec['schema'], 'rows': rows}
    serialized = time.perf_counter_ns()
    payload = json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode()
    serialization_ns = time.perf_counter_ns() - serialized
    # These are harness output rules, not claims that SQLite implements RillScope's budget.
    if len(rows) > 10000 or len(payload) > 1024 * 1024:
        result = {'version': 1, 'status': 'error', 'implementation': 'sqlite-baseline', 'error': {'code': 'E_OUTPUT_LIMIT', 'scope': 'baseline harness output cap'}}
        payload = json.dumps(result, separators=(',', ':')).encode()
    measured = {'implementation': 'sqlite-baseline', 'sqlite_version': sqlite3.sqlite_version,
                'materialization_ns': materialization_ns, 'execution_only_ns': execution_only_ns,
                'serialization_ns': serialization_ns,
                'result_sha256': hashlib.sha256(payload).hexdigest(), 'emitted_rows': len(rows) if result['status'] == 'ok' else None,
                'policy': 'physically scoped relations; harness row/byte cap only; no Rust work/memory equivalence'}
    args.measurement.write_bytes(json.dumps(measured, separators=(',', ':')).encode())
    database.close()
    print(payload.decode())
    return 0

if __name__ == '__main__': raise SystemExit(main())
