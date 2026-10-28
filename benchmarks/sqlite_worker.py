#!/usr/bin/env python3
"""Independent baseline: physically scoped relations, with separately labeled timers."""
import argparse
import gc
import hashlib
import json
from operator import itemgetter
from itertools import chain, islice
from pathlib import Path
import sqlite3
import time

def insert_authorized_rows(database, name, names, values):
    """Bind bounded groups of already authorized rows into a fresh table."""
    values = iter(values)
    row_sql = '(' + ','.join('?' for _ in names) + ')'
    prefix = 'INSERT INTO ' + name + ' VALUES '
    single_sql = prefix + row_sql
    width = len(names)
    variables = database.getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER)
    sql_bytes = database.getlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH)
    if not width or variables < width or sql_bytes < len(single_sql.encode('utf-8')):
        # Keep SQLite's original prepare-time rejection, including no rows.
        database.executemany(single_sql, values)
        return
    bind_rows = variables // width
    sql_rows = (sql_bytes - len(prefix.encode('utf-8')) + 1) // (len(row_sql) + 1)
    batch_rows = min(128, bind_rows, sql_rows)
    statement = prefix + ','.join([row_sql] * batch_rows)
    # An empty parameter sequence prepares this exact INSERT without binding
    # or stepping any data rows. Do not retry errors from actual insertion.
    transaction = database.in_transaction
    try:
        prepared = database.executemany(statement, ())
    except MemoryError:
        # A lost prior transaction must escape to the owning loader's close.
        if transaction and not database.in_transaction:
            raise
        database.executemany(single_sql, values)
        return
    else:
        prepared.close()
    while chunk := tuple(islice(values, batch_rows)):
        current = statement if len(chunk) == batch_rows else prefix + ','.join([row_sql] * len(chunk))
        database.execute(current, tuple(chain.from_iterable(chunk)))


def materialize_catalog(database, catalog, context):
    for name, table in catalog['tables'].items():
        grant = context['tables'][name]
        by_name = {field['name']: i for i, field in enumerate(table['columns'])}
        names = grant['columns']
        types = {'i64': 'INTEGER', 'bool': 'INTEGER', 'text': 'TEXT'}
        declarations = [column + ' ' + types[table['columns'][by_name[column]]['type']] for column in names]
        # Preserve the existing SQLite rejection for an empty visible schema.
        database.execute('CREATE TABLE ' + name + '(' + ','.join(declarations) + ')')
        tenant_index = by_name[grant['tenant_column']]
        tenant = context['tenant']
        indices = tuple(by_name[column] for column in names)
        authorized = (row for row in table['rows'] if row[tenant_index] == tenant)
        # itemgetter returns a scalar for one index; SQLite still needs a tuple.
        if len(indices) == 1:
            index = indices[0]
            values = ((row[index],) for row in authorized)
        else:
            values = map(itemgetter(*indices), authorized)
        # No tenant predicate is injected into SQL. Only physically authorized cells enter SQLite.
        insert_authorized_rows(database, name, names, values)


def load_authorized_database(case):
    """Load every input and materialize fresh tables inside the caller's timer."""
    enabled = gc.isenabled()
    database = None
    try:
        try:
            if enabled:
                gc.disable()
            # Standard JSON without custom hooks creates no reference cycles.
            # All decoding and insertion remain inside materialization timing.
            catalog = json.loads((case / 'catalog.json').read_bytes())
            context = json.loads((case / 'context.json').read_bytes())
            spec = json.loads((case / 'case.json').read_bytes())
            database = sqlite3.connect(':memory:')
            materialize_catalog(database, catalog, context)
        finally:
            if enabled:
                gc.enable()
        # Ownership remains here until GC restoration has also succeeded.
        return database, spec
    except BaseException:
        try:
            if database is not None:
                database.close()
        finally:
            # A one-shot interruption of the normal restore must not leave
            # the prior enabled collector disabled on the failure path.
            if enabled and not gc.isenabled():
                gc.enable()
        raise


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--measurement', type=Path, required=True); args = parser.parse_args()
    started = time.perf_counter_ns()
    database, spec = load_authorized_database(args.case)
    materialization_ns = time.perf_counter_ns() - started
    executed = time.perf_counter_ns()
    rows = [list(row) for row in database.execute(spec['sql'])]
    execution_only_ns = time.perf_counter_ns() - executed
    # The query and complete row collection above stay inside execution timing.
    # Once the row cap is exceeded, its terminal error cannot contain these
    # cells. Avoid normalizing and serializing a discarded success envelope.
    row_limit_exceeded = len(rows) > 10000
    if row_limit_exceeded:
        result = {'version': 1, 'status': 'error', 'implementation': 'sqlite-baseline', 'error': {'code': 'E_OUTPUT_LIMIT', 'scope': 'baseline harness output cap'}}
    else:
        for row in rows:
            for index, field in enumerate(spec['schema']):
                if field['type'] == 'bool' and row[index] is not None: row[index] = bool(row[index])
        result = {'version': 1, 'status': 'ok', 'implementation': 'sqlite-baseline', 'schema': spec['schema'], 'rows': rows}
    serialized = time.perf_counter_ns()
    payload = json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode()
    serialization_ns = time.perf_counter_ns() - serialized
    # These are harness output rules, not claims that SQLite implements RillScope's budget.
    if not row_limit_exceeded and len(payload) > 1024 * 1024:
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
