"""Closed whole-job accounting for one full attempt, never a completion forecast."""
import math

PROVIDER_SECONDS = 21600
PROVISION_SECONDS = 300
HOST_PREP_SECONDS = 600
GUEST_SETUP_SECONDS = 2400
COLLECTION_SECONDS = 15000
GUEST_FINISH_SECONDS = 600
VM_SECONDS = GUEST_SETUP_SECONDS + COLLECTION_SECONDS + GUEST_FINISH_SECONDS
VM_TAIL_SECONDS = 120
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


def guest_command_deadline_ns(started_ns, ready_ns, *, request_ns, received_ns, host_remaining_ns):
    """Spend a host remaining-lifetime reply from the guest's pre-send clock.

    The clocks have unrelated epochs. Starting the host remainder at reception
    would add the return transit time. Starting it before the request spends the
    entire round trip conservatively, while retaining both independent bounds.
    """
    clocks = (started_ns, ready_ns, request_ns, received_ns, host_remaining_ns)
    if (any(type(value) is not int for value in clocks)
            or not 0 < started_ns <= request_ns <= received_ns <= ready_ns
            or not 0 < host_remaining_ns <= VM_SECONDS * 10**9):
        raise ValueError('actual ordered guest setup clock required')
    if ready_ns - started_ns >= (GUEST_SETUP_SECONDS - VM_TAIL_SECONDS) * 10**9:
        raise ValueError('guest setup consumed its boot/setup reserve')
    deadline = min(started_ns + (VM_SECONDS - VM_TAIL_SECONDS) * 10**9,
                   request_ns + host_remaining_ns - VM_TAIL_SECONDS * 10**9)
    if deadline - ready_ns <= GUEST_FINISH_SECONDS * 10**9:
        raise ValueError('guest setup left no collection and finish reserve')
    return deadline


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
        'collection_window_policy': {'base_collection_seconds': COLLECTION_SECONDS,
            'unused_setup_may_be_reclaimed': True,
            'clock_binding': 'one-shot host remaining lifetime spent from actual guest pre-send request',
            'cutoff_origin': 'actual host pre-QEMU VM start; conservative translation without shared clock epochs',
            'latest_guest_command_cutoff_seconds': VM_SECONDS - VM_TAIL_SECONDS,
            'finish_reserve_seconds': GUEST_FINISH_SECONDS,
            'maximum_collection_seconds_before_setup': VM_SECONDS - VM_TAIL_SECONDS - GUEST_FINISH_SECONDS,
            'vm_tail_seconds': VM_TAIL_SECONDS},
        'sample_caps': {'host': MAX_HOST_SAMPLES, 'guest': MAX_GUEST_SAMPLES, 'record_bytes': MAX_SAMPLE_BYTES,
            'host_log_bytes': MAX_HOST_LOG_BYTES, 'guest_log_bytes': MAX_GUEST_LOG_BYTES},
        'full_duration_fit': 'NOT YET MEASURED', 'reference_qualified': False,
        'scope': 'Finite upper bounds and reserved time only; deadline/storage exhaustion remains FAIL, '
                 'without reduced cases, repetitions, process deadlines or replacement samples'}
