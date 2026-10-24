"""Closed new-method serial events; no event grants allocation or qualification."""
import base64

import canonical_reference_allocation as allocation

PREFIX = 'RILLSCOPE_CANONICAL_REFERENCE_V1 '
MAX_EVENTS = 3
COMMON = {'schema_version', 'method', 'phase', 'commit', 'source_sha256', 'boot_id',
    'allocation_sha256', 'utc_ns', 'monotonic_ns', 'reference_qualified'}
EXTRA = {'prefix-start': set(), 'ready': {'stage', 'request_sha256', 'config_sha256'},
    'attempt-end': {'status'}}


def check(row):
    allocation.require(type(row) is dict and type(row.get('phase')) is str and row['phase'] in EXTRA
        and set(row) == COMMON | EXTRA[row['phase']]
        and type(row['schema_version']) is int and row['schema_version'] == 1
        and row['method'] == allocation.METHOD and row['reference_qualified'] is False
        and allocation.hex_value(row['commit'], 40) and allocation.hex_value(row['source_sha256'], 64)
        and allocation.hex_value(row['allocation_sha256'], 64) and allocation.boot(row['boot_id'])
        and allocation.integer(row['utc_ns']) and allocation.integer(row['monotonic_ns']),
        'closed new-method source/boot/grant event required')
    if row['phase'] == 'ready':
        allocation.require(row['stage'] == 'grid' and allocation.hex_value(row['request_sha256'], 64)
            and allocation.hex_value(row['config_sha256'], 64), 'exact first inner measured request required')
    if row['phase'] == 'attempt-end':
        allocation.require(type(row['status']) is str and row['status'] in {'PASS', 'FAIL'},
            'closed actual canonical attempt result required')
    return row


def parse(serial):
    allocation.require(type(serial) is str, 'bounded decoded serial text required')
    rows = []
    for line in serial.splitlines():
        if PREFIX not in line: continue
        frame = line.split(PREFIX, 1)[1].strip()
        allocation.require(len(frame) <= 4 * ((allocation.FRAME_LIMIT + 2) // 3),
            'canonical lifecycle encoded frame exceeds bound')
        try: raw = base64.b64decode(frame, validate=True)
        except ValueError as error: raise ValueError('invalid canonical lifecycle base64') from error
        row = check(allocation.decode(raw))
        allocation.require(len(rows) < MAX_EVENTS and all(prior['phase'] != row['phase'] for prior in rows)
            and not any(prior['phase'] == 'attempt-end' for prior in rows),
            'canonical lifecycle replay or event after terminal result')
        if rows:
            allocation.require(row['monotonic_ns'] > rows[-1]['monotonic_ns']
                and all(row[key] == rows[0][key] for key in ('commit', 'source_sha256', 'boot_id', 'allocation_sha256')),
                'canonical lifecycle source/grant/boot changed or clock reversed')
        if row['phase'] == 'prefix-start': allocation.require(not rows, 'canonical prefix cannot follow measurements')
        if row['phase'] == 'ready':
            allocation.require([prior['phase'] for prior in rows] == ['prefix-start'],
                'canonical native prefix must precede first measurement')
        if row['phase'] == 'attempt-end' and row['status'] == 'PASS':
            allocation.require([prior['phase'] for prior in rows] == ['prefix-start', 'ready'],
                'canonical PASS event requires the actual ordered prefix and measurement boundary')
        rows.append(row)
    return rows


def bind(row, grant):
    """Cross-check original bytes/identities; this cannot authenticate an allocator."""
    check(row)
    request = {key: grant[key] for key in allocation.REQUEST_KEYS}
    request['kind'] = allocation.REQUEST_KIND
    allocation.validate_grant(grant, request)
    allocation.require(all(row[key] == grant[key] for key in ('commit', 'source_sha256', 'boot_id'))
        and row['allocation_sha256'] == allocation.digest(grant)
        and row['monotonic_ns'] >= grant['guest_pre_send_monotonic_ns'],
        'canonical event differs from the original prior guest grant')
    return row
