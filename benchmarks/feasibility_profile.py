"""Independent fixed expectations for an explicitly unqualified cost-tail pilot."""
import copy

PROFILE = 'kvm-cost-tail-pilot'
IDS = ('B01-n1000000-s10-null10-b1024', 'B02-k10000-heavy-composite1', 'B04-n100000-random')
# Literal expectations are separate from the runner's selection from descriptors().
# Neither captured manifests nor measured outcomes define this pilot's scope.
EXPECTED = (
    {'id': IDS[0], 'family': 'filter', 'rows': 1000000, 'selectivity': 10,
     'null_percent': 10, 'batch_rows': 1024, 'expected_oracle_status': 'E_OUTPUT_LIMIT',
     'expected_product_status': 'E_OUTPUT_LIMIT'},
    {'id': IDS[1], 'family': 'join', 'rows': 30000, 'keys': 10000, 'skew': 'heavy',
     'composite': True, 'null_percent': 10, 'batch_rows': 1024,
     'expected_oracle_status': 'OK', 'allowed_product_statuses': ['OK', 'E_BUDGET']},
    {'id': IDS[2], 'family': 'sort', 'rows': 100000, 'order': 'random',
     'null_percent': 10, 'batch_rows': 1024, 'expected_oracle_status': 'OK',
     'expected_product_status': 'OK'},
)


def expectations():
    return copy.deepcopy(list(EXPECTED))


def exact(value, expected):
    """Compare a bounded expected shape, preserving JSON bool/int distinctions."""
    if type(value) is not type(expected): return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(exact(value[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(value) == len(expected) and all(exact(a, b) for a, b in zip(value, expected))
    return value == expected


def header_errors(manifest, results):
    errors = []
    expected = {'profile': PROFILE, 'chosen_workloads': expectations(), 'seeds': [20261014],
                'warmups': 5, 'repetitions': 30, 'expected_cases': 3, 'expected_observations': 315}
    for key, value in expected.items():
        if not exact(manifest.get(key), value): errors.append('fixed cost-tail manifest differs: ' + key)
    for key, value in {'profile': PROFILE, 'completed_cases': 3, 'expected_cases': 3,
                       'complete_grid': False}.items():
        if not exact(results.get(key), value): errors.append('fixed cost-tail result differs: ' + key)
    return errors
