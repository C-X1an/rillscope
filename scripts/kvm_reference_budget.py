"""Closed whole-job accounting for one full attempt, never a completion forecast."""
import math

PROVIDER_SECONDS = 21600
PROVISION_SECONDS = 300
HOST_PREP_SECONDS = 600
GUEST_SETUP_SECONDS = 2400
COLLECTION_SECONDS = 15000
GUEST_FINISH_SECONDS = 600
VM_SECONDS = GUEST_SETUP_SECONDS + COLLECTION_SECONDS + GUEST_FINISH_SECONDS
RECOVERY_SECONDS = 600
CLEANUP_SECONDS = 120
OWNER_RESERVE_SECONDS = 180
OWNER_SECONDS = HOST_PREP_SECONDS + VM_SECONDS + RECOVERY_SECONDS + CLEANUP_SECONDS + OWNER_RESERVE_SECONDS
UPLOAD_SECONDS = 900
ACTIONS_RESERVE_SECONDS = 900
HOST_PERIOD_SECONDS = .5
GUEST_PERIOD_SECONDS = 2
MAX_HOST_SAMPLES = math.ceil(VM_SECONDS / HOST_PERIOD_SECONDS) + 4
MAX_GUEST_SAMPLES = math.ceil(VM_SECONDS / GUEST_PERIOD_SECONDS) + 4
MAX_SAMPLE_BYTES = 16 * 1024
MAX_HOST_LOG_BYTES = MAX_HOST_SAMPLES * MAX_SAMPLE_BYTES
MAX_GUEST_LOG_BYTES = MAX_GUEST_SAMPLES * MAX_SAMPLE_BYTES
MAX_GAP_NS = 15_000_000_000
PACKAGE_SECONDS = 180


def declaration():
    components = {'provision': PROVISION_SECONDS, 'owned_controller': OWNER_SECONDS,
                  'upload': UPLOAD_SECONDS, 'actions_reserve': ACTIONS_RESERVE_SECONDS}
    if sum(components.values()) != PROVIDER_SECONDS:
        raise ValueError('whole-job accounting does not equal the provider ceiling')
    if GUEST_SETUP_SECONDS + COLLECTION_SECONDS + GUEST_FINISH_SECONDS != VM_SECONDS:
        raise ValueError('guest sub-budgets omit setup, collection or finalization')
    actions = {'source_guard': 60, 'checkout': 120, 'owner_wrapper': 60,
               'fallback_recovery_step': 600, 'finalization': 60}
    if sum(actions.values()) != ACTIONS_RESERVE_SECONDS:
        raise ValueError('Actions reserve omits guard, wrapper, fallback or finalization')
    return {'provider_seconds': PROVIDER_SECONDS, 'components_seconds': components,
        'owner_seconds': OWNER_SECONDS, 'vm_seconds': VM_SECONDS,
        'actions_reserve_seconds': actions,
        'guest_seconds': {'setup': GUEST_SETUP_SECONDS, 'collection': COLLECTION_SECONDS, 'finish': GUEST_FINISH_SECONDS},
        'sample_caps': {'host': MAX_HOST_SAMPLES, 'guest': MAX_GUEST_SAMPLES, 'record_bytes': MAX_SAMPLE_BYTES,
            'host_log_bytes': MAX_HOST_LOG_BYTES, 'guest_log_bytes': MAX_GUEST_LOG_BYTES},
        'full_duration_fit': 'NOT YET MEASURED', 'reference_qualified': False,
        'scope': 'Finite upper bounds and reserved time only; deadline/storage exhaustion remains FAIL, '
                 'without reduced cases, repetitions, process deadlines or replacement samples'}
