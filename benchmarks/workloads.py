"""Predetermined synthetic experiment grid; generated values are not production data."""
import json
from pathlib import Path
import random

SEEDS = tuple(20261014 + i for i in range(5))
def descriptors():
    out = []
    for size in (10000, 100000, 1000000):
        for selectivity in (0, 1, 10, 50, 100):
            for null_percent in (0, 10):
                for batch in (128, 1024):
                    out.append({'id': f'B01-n{size}-s{selectivity}-null{null_percent}-b{batch}', 'family': 'filter',
                                'rows': size, 'selectivity': selectivity, 'null_percent': null_percent, 'batch_rows': batch})
    for keys in (1000, 10000):
        for skew in ('uniform', 'heavy'):
            for composite in (False, True):
                out.append({'id': f'B02-k{keys}-{skew}-composite{int(composite)}', 'family': 'join',
                            'rows': keys * 3, 'keys': keys, 'skew': skew, 'composite': composite, 'null_percent': 10, 'batch_rows': 1024})
    for groups in (0, 10, 1000, 100000):
        out.append({'id': f'B03-g{groups}', 'family': 'aggregate', 'rows': 0 if groups == 0 else max(100000, groups * 2),
                    'groups': groups, 'null_percent': 10, 'batch_rows': 1024})
    out.append({'id': 'B03-all-null', 'family': 'aggregate', 'rows': 10000, 'groups': 0,
                'all_null': True, 'null_percent': 100, 'batch_rows': 1024})
    for size in (10000, 100000):
        for order in ('ordered', 'reverse', 'random', 'equal'):
            out.append({'id': f'B04-n{size}-{order}', 'family': 'sort', 'rows': size, 'order': order,
                        'null_percent': 0 if order == 'equal' else 10, 'batch_rows': 1024})
    out.append({'id': 'B06-tiny-work', 'family': 'budget', 'rows': 100, 'keys': 1, 'skew': 'heavy',
                'null_percent': 0, 'batch_rows': 1024, 'max_work': 1000, 'expected_product_status': 'E_BUDGET'})
    for row in out:
        oversized = (row['family'] == 'filter' and row['rows'] * row['selectivity'] // 100 > 10000)
        oversized |= row['family'] == 'aggregate' and row.get('groups', 0) > 10000
        row['expected_oracle_status'] = 'E_OUTPUT_LIMIT' if oversized else 'OK'
    return out

def make_catalog(description, seed):
    rng = random.Random(seed)
    columns = [{'name': 'tenant', 'type': 'text', 'nullable': False}, {'name': 'id', 'type': 'i64', 'nullable': True},
               {'name': 'amount', 'type': 'i64', 'nullable': True}, {'name': 'grp', 'type': 'text', 'nullable': True},
               {'name': 'flag', 'type': 'bool', 'nullable': True}, {'name': 'hidden', 'type': 'text', 'nullable': False}]
    lookup_columns = [{'name': 'tenant', 'type': 'text', 'nullable': False}, {'name': 'key', 'type': 'i64', 'nullable': True},
                      {'name': 'grp', 'type': 'text', 'nullable': True}, {'name': 'flag', 'type': 'bool', 'nullable': True},
                      {'name': 'hidden', 'type': 'text', 'nullable': False}]
    sales, lookup = [], []
    authorized_seen = 0
    for i in range(description['rows']):
        nullable = rng.randrange(100) < description['null_percent']
        family = description['family']
        tenant = 'alpha' if family == 'filter' or i % 4 != 3 else 'beta'
        authorized_ordinal = authorized_seen
        if tenant == 'alpha': authorized_seen += 1
        key = i
        if family in ('join', 'budget'):
            ordinal = authorized_ordinal if tenant == 'alpha' else i
            key = 0 if description['skew'] == 'heavy' and rng.randrange(100) < 80 else ordinal % description['keys']
            if nullable: key = None
            # Coverage is guaranteed inside the authorized relation, independently of tenant/NULL/skew.
            if tenant == 'alpha' and authorized_ordinal < description['keys']: key = authorized_ordinal
        elif family == 'sort' and description['order'] == 'equal': key = 1
        group = None if nullable else 'g' + str(i % max(1, description.get('groups', 100)))
        if family == 'aggregate' and description.get('groups', 0):
            groups = description['groups']
            if tenant == 'alpha' and authorized_ordinal < groups:
                group = None if authorized_ordinal == groups - 1 else 'g' + str(authorized_ordinal)
            else:
                group = None if nullable else 'g' + str(i % max(1, groups - 1))
        amount = None if nullable or description.get('all_null') else i % 100
        if family == 'sort' and description['order'] == 'equal': amount = 0
        if family in ('join', 'budget'):
            group = None if key is None else 'g' + str(i % 7)
        sales.append([tenant, key, amount, group, None if nullable else i % 2 == 0, 'SYNTHETIC_HIDDEN'])
        if family in ('join', 'budget'):
            lookup.append([tenant, key, group, None if nullable else i % 2 == 0, 'SYNTHETIC_LOOKUP_HIDDEN'])
    if description['family'] == 'sort':
        if description['order'] == 'reverse': sales.reverse()
        elif description['order'] == 'random': rng.shuffle(sales)
    return {'version': 1, 'snapshot': 'synthetic-benchmark-' + str(seed),
            'tables': {'sales': {'columns': columns, 'rows': sales}, 'lookup': {'columns': lookup_columns, 'rows': lookup}}}

def context():
    return {'version': 1, 'tenant': 'alpha', 'policy_revision': 'synthetic-benchmark-r1',
            'tables': {'sales': {'tenant_column': 'tenant', 'columns': ['id', 'amount', 'grp', 'flag']},
                       'lookup': {'tenant_column': 'tenant', 'columns': ['key', 'grp', 'flag']}}}

def query(description):
    family = description['family']
    col = lambda name: {'col': name}
    scan = lambda table, alias: {'op': 'scan', 'table': table, 'alias': alias}
    if family == 'filter':
        predicate = {'op': 'lt', 'left': col('s.amount'), 'right': {'lit': description['selectivity']}}
        plan = {'op': 'project', 'input': {'op': 'filter', 'input': scan('sales', 's'), 'predicate': predicate},
                'columns': [{'name': 'id', 'expr': col('s.id')}, {'name': 'amount', 'expr': col('s.amount')}]}
        sql = 'SELECT id, amount FROM sales WHERE amount < ' + str(description['selectivity'])
        schema = [{'name': 'id', 'type': 'i64', 'nullable': True}, {'name': 'amount', 'type': 'i64', 'nullable': True}]
    elif family in ('join', 'budget'):
        pairs = [{'left': col('s.id'), 'right': col('l.key')}]
        on = 's.id = l.key'
        if description.get('composite'):
            pairs.append({'left': col('s.grp'), 'right': col('l.grp')}); on += ' AND s.grp = l.grp'
        joined = {'op': 'join', 'left': scan('sales', 's'), 'right': scan('lookup', 'l'), 'on': pairs}
        plan = {'op': 'aggregate', 'input': joined, 'keys': [], 'aggregates': [{'name': 'n', 'kind': 'count_all'}, {'name': 'total', 'kind': 'sum', 'expr': col('s.amount')}]}
        sql = 'SELECT COUNT(*) AS n, SUM(s.amount) AS total FROM sales s JOIN lookup l ON ' + on
        schema = [{'name': 'n', 'type': 'i64', 'nullable': False}, {'name': 'total', 'type': 'i64', 'nullable': True}]
    elif family == 'aggregate':
        grouped = description.get('groups', 0) != 0
        plan = {'op': 'aggregate', 'input': scan('sales', 's'), 'keys': [{'name': 'grp', 'expr': col('s.grp')}] if grouped else [],
                'aggregates': [{'name': 'n', 'kind': 'count_all'}, {'name': 'present', 'kind': 'count', 'expr': col('s.amount')}, {'name': 'total', 'kind': 'sum', 'expr': col('s.amount')}]}
        sql = 'SELECT ' + ('grp, ' if grouped else '') + 'COUNT(*) AS n, COUNT(amount) AS present, SUM(amount) AS total FROM sales' + (' GROUP BY grp' if grouped else '')
        schema = ([{'name': 'grp', 'type': 'text', 'nullable': True}] if grouped else []) + [
            {'name': 'n', 'type': 'i64', 'nullable': False}, {'name': 'present', 'type': 'i64', 'nullable': False}, {'name': 'total', 'type': 'i64', 'nullable': True}]
    else:
        selected = {'op': 'project', 'input': scan('sales', 's'), 'columns': [{'name': 'id', 'expr': col('s.id')}, {'name': 'amount', 'expr': col('s.amount')}]}
        plan = {'op': 'limit', 'count': 1000, 'input': {'op': 'sort', 'input': selected, 'keys': [
            {'expr': col('id'), 'direction': 'desc', 'nulls': 'last'}, {'expr': col('amount'), 'direction': 'asc', 'nulls': 'last'}]}}
        sql = 'SELECT id, amount FROM sales ORDER BY id DESC NULLS LAST, amount ASC NULLS LAST LIMIT 1000'
        schema = [{'name': 'id', 'type': 'i64', 'nullable': True}, {'name': 'amount', 'type': 'i64', 'nullable': True}]
    return {'version': 1, 'plan': plan}, sql, schema, family == 'sort'

def write_case(directory: Path, description, seed):
    directory.mkdir(parents=True, exist_ok=True)
    catalog = make_catalog(description, seed)
    request, sql, schema, ordered = query(description)
    for name, value in [('catalog.json', catalog), ('context.json', context()), ('query.json', request)]:
        (directory / name).write_bytes(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode())
    realized = realized_shape(catalog)
    if description['family'] == 'aggregate' and description.get('groups', 0):
        if realized['authorized_distinct_group_values_including_null'] != description['groups']:
            raise ValueError('advertised authorized group cardinality not realized')
    if description['family'] in ('join', 'budget'):
        if realized['authorized_distinct_nonnull_keys'] != description['keys']:
            raise ValueError('advertised authorized join key cardinality not realized')
        if description.get('composite') and not realized['first_key_collisions_with_distinct_second_keys']:
            raise ValueError('composite components are not independently distinguishing')
    if description['family'] == 'sort' and description['order'] == 'equal' and realized['authorized_distinct_complete_sort_keys'] != 1:
        raise ValueError('equal sort workload does not have equal complete keys')
    spec = {'description': description, 'seed': seed, 'sql': sql, 'schema': schema, 'ordered': ordered,
            'realized_shape': realized, 'group_cardinality_definition': 'authorized distinct group values including NULL',
            'null_percent_definition': 'nominal seeded selection; mandatory authorized key/group coverage may override key NULLs'}
    (directory / 'case.json').write_bytes(json.dumps(spec, ensure_ascii=False).encode())
    return spec


def realized_shape(catalog):
    rows = [row for row in catalog['tables']['sales']['rows'] if row[0] == 'alpha']
    components = {}
    for row in rows:
        if row[1] is not None and row[3] is not None: components.setdefault(row[1], set()).add(row[3])
    return {'authorized_rows': len(rows), 'authorized_null_join_keys': sum(row[1] is None for row in rows),
            'authorized_distinct_nonnull_keys': len({row[1] for row in rows if row[1] is not None}),
            'authorized_distinct_group_values_including_null': len({row[3] for row in rows}),
            'authorized_distinct_complete_sort_keys': len({(row[1], row[2]) for row in rows}),
            'first_key_collisions_with_distinct_second_keys': any(len(values) > 1 for values in components.values())}
