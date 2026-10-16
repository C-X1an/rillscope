"""Closed terminal framing and documented Rust exit mapping for measurement tools."""
import json

EXIT_CODES = {'E_INPUT': 2, 'E_UNSUPPORTED': 2, 'E_BIND': 2, 'E_TYPE': 2, 'E_FORBIDDEN': 2,
              'E_LIMIT': 3, 'E_BUDGET': 3, 'E_OUTPUT_LIMIT': 3, 'E_CANCELLED': 4,
              'E_CATALOG': 5, 'E_CONTEXT': 5, 'E_PLAN': 6, 'E_OVERFLOW': 6, 'E_INTERNAL': 6}


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result: raise ValueError('duplicate terminal field')
        result[name] = value
    return result


def terminal(stdout, stderr, code, mode):
    if stderr: raise ValueError('unexpected stderr')
    if len(stdout) > 1024 * 1024 + 2: raise ValueError('oversized terminal output')
    value = json.loads(stdout, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or type(value.get('version')) is not int or value.get('version') != 1 or value.get('status') not in ('ok', 'error'):
        raise ValueError('not a terminal envelope')
    if value['status'] == 'error':
        if 'rows' in value or 'schema' in value: raise ValueError('failure publishes result rows/schema')
        if set(value) != {'version', 'status', 'implementation', 'error'}: raise ValueError('unknown failure field')
        error = value.get('error')
        if not isinstance(error, dict) or error.get('code') not in EXIT_CODES: raise ValueError('unknown error envelope')
        expected = 0 if mode == 'sqlite' else EXIT_CODES[error['code']]
    else:
        if 'error' in value: raise ValueError('success includes an error')
        if not isinstance(value.get('rows'), list) or not isinstance(value.get('schema'), list):
            raise ValueError('success lacks typed result')
        for field in value['schema']:
            if (not isinstance(field, dict) or set(field) != {'name','type','nullable'}
                    or not isinstance(field['name'], str) or field['type'] not in ('i64','bool','text')
                    or type(field['nullable']) is not bool): raise ValueError('invalid typed result schema')
        for row in value['rows']:
            if not isinstance(row, list) or len(row) != len(value['schema']): raise ValueError('invalid typed row width')
            for cell, field in zip(row, value['schema']):
                if cell is None:
                    if not field['nullable']: raise ValueError('NULL in required field')
                elif field['type'] == 'i64':
                    if type(cell) is not int or not -(2**63) <= cell < 2**63: raise ValueError('invalid i64 cell')
                elif field['type'] == 'bool':
                    if type(cell) is not bool: raise ValueError('invalid Boolean cell')
                elif type(cell) is not str: raise ValueError('invalid text cell')
        expected = 0
    if code != expected: raise ValueError('exit code/envelope disagreement')
    if mode == 'sqlite':
        if value.get('implementation') != 'sqlite-baseline': raise ValueError('not the independent baseline')
    elif value.get('implementation') not in ('rust', 'rust-benchmark'):
        raise ValueError('not the Rust product')
    return value
