"""Actual Rust subprocesses and physically prefiltered independent SQLite tables."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / 'target/debug' / ('rillscope.exe' if os.name == 'nt' else 'rillscope')

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def column(name): return {'col': name}
def literal(value): return {'lit': value}
def binary(op, left, right): return {'op': op, 'left': left, 'right': right}
def scan(table='sales', alias='s'): return {'op': 'scan', 'table': table, 'alias': alias}
def project(input, pairs): return {'op': 'project', 'input': input, 'columns': [{'name': name, 'expr': expr} for name, expr in pairs]}
def filtered(input, predicate): return {'op': 'filter', 'input': input, 'predicate': predicate}
def ordered(input, names, direction='asc', nulls='last'):
    return {'op': 'sort', 'input': input, 'keys': [{'expr': column(name), 'direction': direction, 'nulls': nulls} for name in names]}

def fixture(rows=None, lookup=None):
    def field(name, type, nullable): return {'name': name, 'type': type, 'nullable': nullable}
    sales = {'columns': [field('tenant', 'text', False), field('id', 'i64', True), field('amount', 'i64', True),
                         field('grp', 'text', True), field('enabled', 'bool', True), field('salary', 'i64', False), field('secret', 'text', False)],
             'rows': rows if rows is not None else [['alpha', 1, 20, 'x', True, 7, 'A_HIDDEN_CANARY'],
                     ['beta', 1, 9223372036854775807, 'B_TENANT_CANARY', False, 9999, 'B_HIDDEN_CANARY'],
                     ['alpha', 1, 10, None, None, 8, 'A_HIDDEN_CANARY'], ['alpha', None, None, 'x', False, 9, 'A_HIDDEN_CANARY']]}
    look = {'columns': [field('tenant', 'text', False), field('key', 'i64', True), field('flag', 'bool', True), field('secret', 'text', False)],
            'rows': lookup if lookup is not None else [['alpha', 1, True, 'L_HIDDEN_CANARY'], ['alpha', 1, None, 'L_HIDDEN_CANARY'],
                    ['beta', 1, False, 'B_LOOKUP_CANARY'], ['alpha', None, False, 'L_HIDDEN_CANARY']]}
    return {'version': 1, 'snapshot': 'synthetic-product-v1', 'tables': {'sales': sales, 'lookup': look}}

def context(tenant='alpha'):
    return {'version': 1, 'policy_revision': 'FAKE_CONFIG_CANARY', 'tenant': tenant,
            'tables': {'sales': {'tenant_column': 'tenant', 'columns': ['id', 'amount', 'grp', 'enabled']},
                       'lookup': {'tenant_column': 'tenant', 'columns': ['key', 'flag']}}}

def oracle(catalog, tenant):
    connection = sqlite3.connect(':memory:')
    for name, table in catalog['tables'].items():
        grant = context(tenant)['tables'][name]
        names = grant['columns']
        indices = [next(i for i, field in enumerate(table['columns']) if field['name'] == n) for n in names]
        # The oracle physically stores only the authorized relation and visible columns.
        connection.execute('CREATE TABLE ' + name + ' (' + ','.join(names) + ')')
        values = [[row[i] for i in indices] for row in table['rows'] if row[0] == tenant]
        connection.executemany('INSERT INTO ' + name + ' VALUES (' + ','.join('?' for _ in names) + ')', values)
    return connection

class Client:
    def __init__(self, folder, catalog, tenant='alpha'):
        self.catalog = Path(folder) / 'catalog.json'
        self.context = Path(folder) / 'context.json'
        self.catalog.write_text(json.dumps(catalog), encoding='utf-8')
        self.context.write_text(json.dumps(context(tenant)), encoding='utf-8')
        self.env = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'HOME') if key in os.environ}
        if not BINARY.is_file(): raise RuntimeError('Rust CLI is not built; product validation cannot use the reference')

    def call(self, query, format='json', optimize=True, command='run', extra=None):
        data = query if isinstance(query, bytes) else (query.encode() if format == 'sql' else json.dumps({'version': 1, 'plan': query}, ensure_ascii=False).encode())
        args = [str(BINARY), command, '--catalog', str(self.catalog), '--context', str(self.context), '--query', '-', '--format', format, '--optimize', 'on' if optimize else 'off']
        result = subprocess.run(args + (extra or []), input=data, capture_output=True, cwd=ROOT, env=self.env, timeout=20)
        if result.stderr: raise AssertionError('ordinary CLI emitted stderr: ' + result.stderr.decode(errors='replace'))
        value = json.loads(result.stdout)
        if value.get('implementation') != 'rust': raise AssertionError('product gate must execute Rust')
        if value.get('status') not in ('ok', 'error'): raise AssertionError('missing terminal status')
        if value['status'] == 'ok' and result.returncode != 0: raise AssertionError('successful rows with failure exit')
        if value['status'] == 'error' and ('rows' in value or result.returncode == 0): raise AssertionError('partial or successful error')
        return result.returncode, value

def compare_rows(actual, expected, schema, ordered=False):
    converted = [[bool(value) if field['type'] == 'bool' and value is not None else value for value, field in zip(row, schema)] for row in expected]
    for row in actual:
        if len(row) != len(schema): raise AssertionError('row/schema width mismatch')
        for value, field in zip(row, schema):
            if value is None:
                if not field['nullable']: raise AssertionError('NULL in nonnullable result')
            elif field['type'] == 'i64' and type(value) is not int: raise AssertionError('integer was not exact')
            elif field['type'] == 'bool' and type(value) is not bool: raise AssertionError('Boolean was not exact')
            elif field['type'] == 'text' and type(value) is not str: raise AssertionError('text was not exact')
    if ordered:
        if actual != converted: raise AssertionError((actual, converted))
    else:
        key = lambda row: json.dumps(row, ensure_ascii=False, separators=(',', ':'))
        if sorted(actual, key=key) != sorted(converted, key=key): raise AssertionError((actual, converted))
