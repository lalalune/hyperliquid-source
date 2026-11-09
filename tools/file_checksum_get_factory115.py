#!/usr/bin/env python3
"""Reconstruct the node #115 GetFileChecksumGenCrc32cFactory behaviour.

Bounded question (RE-002): what does the function at 0x61cd600 do --
how is the process-wide FileChecksumGenCrc32cFactory singleton created,
stored and handed out, and what does each call return?

Observed answer, from the disassembly of work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* The function is the vendor-census entry
  ``_ZN7rocksdb31GetFileChecksumGenCrc32cFactoryEv``
  (librocksdb-sys, member 6cca28ae25285154-file_checksum_helper.o).
  The census pins its body exactly to the FDE 0x61cd600..0x61cd716,
  and the body SHA-256 below matches the census target_body_sha256
  (also recorded in research/byte-windows.json).
* The result is returned through a hidden out-pointer (rdi): the
  function copies the 16-byte static shared_ptr (pointer + control
  block) to [rdi] and returns rdi. It takes no other argument.
* Guarded initialisation, read off the control flow: the guard byte
  at 0x6508930 (.bss) is tested first; any nonzero value jumps
  straight to the copy path. When it is zero, the function calls
  ``__cxa_guard_acquire`` (PLT 0x63f0fc0); a zero return also goes to
  the copy path, a nonzero return runs the init path and then
  ``__cxa_guard_release`` (PLT 0x63f0fd0) before the copy path.
* Init path (0x61cd670): ``operator new(0x20)`` through the PLT entry
  at 0x63f0dd0 makes the factory object A; the whole 0x20 bytes are
  zeroed (two movups), then A[0] is set to the factory vtable address
  point 0x64d79b0 (lea 0x64d79a0 + add $0x10) and the static pointer
  at 0x6508940 is set to A. Then ``operator new(0x18)`` makes the
  control block B: B[0] is the control-block vtable address point
  0x64d7a90 (lea 0x64d7a80 + add $0x10), B[8..0x10) is the 8-byte
  constant at 0x459b20 (0x0000000100000001: use_count 1, weak_count 1),
  B[0x10] is A, and the static control pointer at 0x6508948 is set
  to B. Finally ``__cxa_atexit`` (PLT 0x63f0f80) registers the
  destructor at 0x61cd720 for the static, with the dso handle at
  0x64efa20.
* Copy path (0x61cd629): the 16-byte static is loaded with movdqa
  and stored to the out-pointer with movups. When the control pointer
  is nonzero, use_count (the low dword of the counts word at B+0x8)
  is incremented by 1: with ``lock addl`` when the byte the .got
  pointer at 0x64ed290 points to is 0, with a plain ``addl`` when it
  is nonzero. When the control pointer is zero, no increment runs.
* Factory object layout (0x20 bytes), read off the deleting
  destructor at 0x61cd400 (which frees the object with size 0x20
  after destroying its member): vptr at +0x0, and a vector-like
  member at +0x8 (begin), +0x10 (end), +0x18 (capacity) whose
  elements are 0x30 bytes. The element destructor loop frees, for
  each element, the heap buffer at [element+0] with size
  [element+0x10]+1 unless [element+0] equals element+0x10 -- the
  exact shape of a std::string _M_dispose (pointer at +0, length at
  +8, SSO buffer / allocated capacity at +0x10), confirmed by the
  identical codegen in the generator destructor at 0x61cd490 for
  the string at generator+0x10. The init path zeroes the whole
  member, so the singleton starts with an empty member. The trailing
  0x10 bytes of each element and the element's identity are unknown.
* Control-block vtable (address point 0x64d7a90, entries read off
  the R_X86_64_RELATIVE relocations): slot 0 (0x61cd080) is a bare
  return (complete destructor), slot 1 (0x61cd180) is operator
  delete with size 0x18 (deleting destructor), slot 2 (0x61cd110)
  deletes the managed factory object through its deleting destructor
  at 0x61cd400 (factory vtable slot 1), slot 3 (0x61cd190) is
  operator delete with size 0x18, slot 4 (0x61cd130) returns null.
* Release (the atexit destructor at 0x61cd720, observed, not the
  claim of this packet): when the counts word is exactly
  0x0000000100000001 it zeroes the counts, calls slot 2 (dispose)
  and tail-calls slot 3 (destroy); otherwise it decrements use_count
  (lock xadd when the thread-flag byte is 0, plain decrement
  otherwise) and, when the old value was 1, tail-calls the shared
  release helper at 0x5d35070, which is not decoded here.

The Python model below implements the getter's state machine twice
independently (a step-by-step transliteration of the disassembly vs a
closed-form reference over call sequences) and cross-checks them on
2400 deterministic cases. The node binary is never executed.
"""
import argparse
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PACKET = ROOT / 'research' / 'work-items' / 're-002-node115-file-checksum-get-factory-115'
FUNCTION_START = 0x61CD600
FUNCTION_END = 0x61CD716
GUARD_ADDR = 0x6508930
STATIC_PTR_ADDR = 0x6508940
STATIC_PI_ADDR = 0x6508948
THREAD_FLAG_SLOT = 0x64ED290
COUNTS_CONST_ADDR = 0x459B20
COUNTS_CONST = 0x0000000100000001
FACTORY_VTABLE = 0x64D79B0
CONTROL_VTABLE = 0x64D7A90
FACTORY_SIZE = 0x20
CONTROL_SIZE = 0x18
DTOR_ADDR = 0x61CD720
DSO_HANDLE_ADDR = 0x64EFA20
NEW_PLT = 0x63F0DD0
GUARD_ACQUIRE_PLT = 0x63F0FC0
GUARD_RELEASE_PLT = 0x63F0FD0
ATEXIT_PLT = 0x63F0F80
CASE_COUNT = 2400
CASE_SEED = 20261109

# Census body hash for GetFileChecksumGenCrc32cFactory
# (research/work-items/RE-002-node115-vendor-census/census.json and
# research/byte-windows.json).
CENSUS_BODY = {
    'function': '9016de75b9bb6c8723439a5a3ca9b4fba7e7d95bf20ef98cf508d51238e6c4df',
}

# (label, start, end) of the byte-checked instruction windows. The
# first seven tile 0x61cd600..0x61cd716 exactly; the PLT windows pin
# the four calls the body makes; the counts window pins the 8-byte
# constant stored into the control block; the .got window pins the
# thread-flag pointer slot (zero in the static image, filled at load).
WINDOWS = (
    ('guard_test', FUNCTION_START, 0x61CD629),
    ('copy_path', 0x61CD629, 0x61CD658),
    ('copy_lock', 0x61CD658, 0x61CD66D),
    ('init_pad', 0x61CD66D, 0x61CD670),
    ('init_factory', 0x61CD670, 0x61CD6AE),
    ('init_control', 0x61CD6AE, 0x61CD6FE),
    ('landing_pads', 0x61CD6FE, FUNCTION_END),
    ('new_plt', NEW_PLT, NEW_PLT + 0x10),
    ('guard_acquire_plt', GUARD_ACQUIRE_PLT, GUARD_ACQUIRE_PLT + 0x10),
    ('guard_release_plt', GUARD_RELEASE_PLT, GUARD_RELEASE_PLT + 0x10),
    ('atexit_plt', ATEXIT_PLT, ATEXIT_PLT + 0x10),
    ('counts_const', COUNTS_CONST_ADDR, COUNTS_CONST_ADDR + 0x8),
    ('thread_flag_slot', THREAD_FLAG_SLOT, THREAD_FLAG_SLOT + 0x8),
)


def authenticate(data):
    """Reject anything that is not the pinned node #115 binary."""
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('target digest mismatch: not node #115')
    return True


def unique_sections(data):
    secs = sections(data)
    seen = {}
    for sec in secs:
        if sec['name'] in seen:
            raise ValueError('Duplicate section: ' + sec['name'])
        seen[sec['name']] = sec
    return seen


def file_offset(secs, va, size):
    for sec in secs.values():
        start, end = sec['address'], sec['address'] + sec['size']
        if start <= va and va + size <= end:
            if sec['type'] == 8:  # SHT_NOBITS has no bytes to read.
                raise ValueError(f'NOBITS section at {va:#x}')
            return sec['offset'] + (va - start)
    raise ValueError(f'address {va:#x} outside mapped sections')


# --- Singleton getter: model (transliteration) vs reference ---

def fresh_state(threaded=False):
    """The static storage at load: guard 0, both shared_ptr words 0."""
    return {'guard': 0, 'static_ptr': None, 'static_pi': None,
            'use_count': 0, 'weak_count': 0, 'live_copies': 0,
            'init_runs': 0, 'threaded': threaded}


def initialised_state(live=0, threaded=False):
    """A state as if init already ran, with ``live`` copies outstanding."""
    state = fresh_state(threaded)
    state['guard'] = 1
    state['static_ptr'] = 'A'
    state['static_pi'] = 'B'
    state['use_count'] = 1 + live
    state['weak_count'] = 1
    state['live_copies'] = live
    state['init_runs'] = 1
    return state


def defensive_empty_state(threaded=False):
    """Guard set but the static still empty: the copy path's pi==0 edge.

    Unreachable in the observed init order (the guard is released only
    after both static words are stored), but the copy path handles it,
    so the model covers it.
    """
    state = fresh_state(threaded)
    state['guard'] = 1
    return state


def run_init(state):
    """The init path at 0x61cd670: allocate and wire A and B."""
    state['static_ptr'] = 'A'
    state['static_pi'] = 'B'
    state['use_count'] = 1
    state['weak_count'] = 1
    state['live_copies'] = 0
    state['init_runs'] += 1


def call_getter_model(state):
    """One getter call, transliterated from the disassembly.

    Returns (ptr, pi, use_count_after, init_ran, increment_form).
    ``increment_form`` is 'lock' when the thread-flag byte is 0
    (the lock addl at 0x61cd660), 'plain' when it is nonzero (the
    addl at 0x61cd64c), and None when no increment runs.
    """
    init_ran = False
    if state['guard'] == 0:
        # __cxa_guard_acquire returns nonzero exactly when this call
        # must initialise (the guard byte is 0 here).
        init_ran = True
        run_init(state)
        # __cxa_guard_release sets the guard byte to 1.
        state['guard'] = 1
    # Copy path: the 16-byte static is copied to the out-pointer.
    ptr, pi = state['static_ptr'], state['static_pi']
    form = None
    if pi is not None:
        form = 'plain' if state['threaded'] else 'lock'
        state['use_count'] += 1
        state['live_copies'] += 1
    return (ptr, pi, state['use_count'], init_ran, form)


def release_copy_model(state):
    """Dropping one live copy: the destructor's decrement path.

    The static itself always holds one reference, so a copy release
    can never be the last use while the static lives; use_count
    bottoms out at 1.
    """
    if state['live_copies'] <= 0:
        raise ValueError('release with no live copy')
    state['use_count'] -= 1
    state['live_copies'] -= 1
    return state['use_count']


def call_getter_reference(state):
    """Independent reference: closed form over (initialised, live)."""
    if state['static_pi'] is None:
        if state['guard'] == 0:
            return ('A', 'B', 2, True,
                    'plain' if state['threaded'] else 'lock')
        return (None, None, 0, False, None)
    return ('A', 'B', state['use_count'] + 1, False,
            'plain' if state['threaded'] else 'lock')


def run_sequence_model(initial, ops):
    """Run an op sequence ('G' = get, 'R' = release) with the model."""
    state = dict(initial)
    trace = []
    for op in ops:
        if op == 'G':
            trace.append(('G',) + call_getter_model(state))
        else:
            trace.append(('R', release_copy_model(state),
                          state['live_copies']))
    return {'trace': trace, 'final_use': state['use_count'],
            'final_live': state['live_copies'],
            'init_runs': state['init_runs']}


def run_sequence_reference(initial, ops):
    """Run the same sequence with the closed-form reference."""
    state = dict(initial)
    trace = []
    for op in ops:
        if op == 'G':
            ptr, pi, use, init_ran, form = call_getter_reference(state)
            if init_ran:
                state['static_ptr'] = 'A'
                state['static_pi'] = 'B'
                state['use_count'] = 1
                state['weak_count'] = 1
                state['live_copies'] = 0
                state['init_runs'] += 1
                state['guard'] = 1
                use = 2
            if pi is not None:
                state['use_count'] += 1
                state['live_copies'] += 1
            trace.append(('G', ptr, pi, use, init_ran, form))
        else:
            if state['live_copies'] <= 0:
                raise ValueError('release with no live copy')
            state['use_count'] -= 1
            state['live_copies'] -= 1
            trace.append(('R', state['use_count'], state['live_copies']))
    return {'trace': trace, 'final_use': state['use_count'],
            'final_live': state['live_copies'],
            'init_runs': state['init_runs']}


def window_hashes(data, secs):
    out = {}
    for label, start, end in WINDOWS:
        off = file_offset(secs, start, end - start)
        out[label] = hashlib.sha256(data[off:off + (end - start)]).hexdigest()
    return out


def body_hash(data, secs, start, end):
    off = file_offset(secs, start, end - start)
    return hashlib.sha256(data[off:off + (end - start)]).hexdigest()


def fde_extent(data, start):
    """Return the .eh_frame extent starting at start, or None."""
    _, fdes = eh_frame_records(data)
    for rec in fdes:
        if rec['start'] == start:
            return rec['start'], rec['end']
    return None


def verify(data):
    """Authenticate the binary and check every pinned byte of the packet."""
    authenticate(data)
    secs = unique_sections(data)
    if secs['.text']['address'] != 0x1419300 or secs['.rodata']['address'] != 0x430400:
        raise ValueError('unexpected section layout')
    extent = fde_extent(data, FUNCTION_START)
    if extent != (FUNCTION_START, FUNCTION_END):
        raise ValueError(f'FDE extent mismatch: {extent}')
    counts_off = file_offset(secs, COUNTS_CONST_ADDR, 8)
    if struct.unpack('<Q', data[counts_off:counts_off + 8])[0] != COUNTS_CONST:
        raise ValueError('counts constant mismatch')
    flag_off = file_offset(secs, THREAD_FLAG_SLOT, 8)
    if struct.unpack('<Q', data[flag_off:flag_off + 8])[0] != 0:
        raise ValueError('thread-flag slot is not zero in the static image')
    # Check values on the getter model.
    first = call_getter_model(fresh_state())
    if first != ('A', 'B', 2, True, 'lock'):
        raise ValueError(f'fresh first call mismatch: {first!r}')
    plain = call_getter_model(fresh_state(threaded=True))
    if plain[4] != 'plain':
        raise ValueError('threaded flag must select the plain increment')
    five = run_sequence_model(fresh_state(), 'GGGGG')
    if five['final_use'] != 6 or five['init_runs'] != 1:
        raise ValueError(f'five gets mismatch: {five!r}')
    cycle = run_sequence_model(fresh_state(), 'GR')
    if cycle['final_use'] != 1 or cycle['final_live'] != 0:
        raise ValueError(f'get+release mismatch: {cycle!r}')
    empty = call_getter_model(defensive_empty_state())
    if empty != (None, None, 0, False, None):
        raise ValueError(f'defensive empty mismatch: {empty!r}')
    checked = {
        'window_hashes': window_hashes(data, secs),
        'body_hash': body_hash(data, secs, FUNCTION_START, FUNCTION_END),
        'sections': secs,
    }
    if checked['body_hash'] != CENSUS_BODY['function']:
        raise ValueError('body hash does not match the census')
    return checked


# --- Deterministic cases ---

def structured_cases():
    """Hand-built sequences covering every branch of the getter."""
    cases = []
    for threaded in (False, True):
        cases.append((fresh_state(threaded), 'G'))
        cases.append((fresh_state(threaded), 'GG'))
        cases.append((fresh_state(threaded), 'GGGGG'))
        cases.append((fresh_state(threaded), 'GGGGGGGGGG'))
        cases.append((fresh_state(threaded), 'GR'))
        cases.append((fresh_state(threaded), 'GRGRGR'))
        cases.append((fresh_state(threaded), 'GGRGR'))
        cases.append((fresh_state(threaded), 'GGGGGRRRRR'))
        cases.append((initialised_state(0, threaded), 'G'))
        cases.append((initialised_state(0, threaded), 'GG'))
        cases.append((initialised_state(3, threaded), 'G'))
        cases.append((initialised_state(3, threaded), 'GR'))
        cases.append((initialised_state(3, threaded), 'RRR'))
        cases.append((initialised_state(8, threaded), 'RRRRRRRR'))
        cases.append((initialised_state(8, threaded), 'GGRRGG'))
        cases.append((defensive_empty_state(threaded), 'G'))
        cases.append((defensive_empty_state(threaded), 'GG'))
    return cases


def generate_cases(count=CASE_COUNT, seed=CASE_SEED):
    """Structured sequences first, then seeded random sequences."""
    rng = random.Random(seed)
    cases = structured_cases()
    while len(cases) < count:
        threaded = rng.random() < 0.5
        roll = rng.random()
        if roll < 0.55:
            initial = fresh_state(threaded)
        elif roll < 0.90:
            initial = initialised_state(rng.randrange(0, 9), threaded)
        else:
            initial = defensive_empty_state(threaded)
        live = initial['live_copies']
        length = rng.randrange(1, 17)
        ops = []
        for _ in range(length):
            if live > 0 and rng.random() < 0.3:
                ops.append('R')
                live -= 1
            else:
                ops.append('G')
                live += 1 if initial['static_pi'] is not None or \
                    initial['guard'] == 0 else 0
        cases.append((initial, ''.join(ops)))
    return cases[:count]


def run_cases(cases):
    """Run the model against the independent reference; return rows."""
    rows = []
    for initial, ops in cases:
        model = run_sequence_model(initial, ops)
        reference = run_sequence_reference(initial, ops)
        if model != reference:
            raise ValueError(
                f'model disagrees with the reference for {initial!r} {ops!r}')
        rows.append((initial, ops, model))
    return rows


def case_aggregate(rows):
    hasher = hashlib.sha256()
    for initial, ops, result in rows:
        hasher.update(struct.pack('<Q', initial['guard']))
        hasher.update(struct.pack('<Q', initial['live_copies']))
        hasher.update(b'\x01' if initial['threaded'] else b'\x00')
        hasher.update(b'\x01' if initial['static_pi'] is None else b'\x00')
        hasher.update(ops.encode())
        for step in result['trace']:
            hasher.update(repr(step).encode())
        hasher.update(struct.pack('<q', result['final_use']))
        hasher.update(struct.pack('<q', result['final_live']))
        hasher.update(struct.pack('<Q', result['init_runs']))
    return hasher.hexdigest()


def init_layout():
    """The initialised objects, as the init path stores them."""
    return {
        'factory_object': {'size': f'{FACTORY_SIZE:#x}', 'vptr': f'{FACTORY_VTABLE:#x}',
                           'vector_member_zeroed': True,
                           'member': 'begin +0x8, end +0x10, capacity +0x18 (all zero)'},
        'control_block': {'size': f'{CONTROL_SIZE:#x}', 'vptr': f'{CONTROL_VTABLE:#x}',
                          'use_count': 1, 'weak_count': 1,
                          'counts_word': f'{COUNTS_CONST:#018x}',
                          'managed_ptr': 'factory object A'},
        'static': {'guard': f'{GUARD_ADDR:#x}', 'ptr': f'{STATIC_PTR_ADDR:#x}',
                   'control_ptr': f'{STATIC_PI_ADDR:#x}'},
        'atexit': {'destructor': f'{DTOR_ADDR:#x}', 'dso_handle': f'{DSO_HANDLE_ADDR:#x}'},
    }


def generate(data, dest):
    """Write the evidence packet files into dest (deterministic)."""
    checked = verify(data)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    cases = generate_cases()
    rows = run_cases(cases)
    aggregate = case_aggregate(rows)
    total_gets = sum(ops.count('G') for _, ops, _ in rows)
    total_releases = sum(ops.count('R') for _, ops, _ in rows)
    total_inits = sum(r['init_runs'] for _, _, r in rows)

    with (dest / 'windows.tsv').open('w', encoding='utf-8') as handle:
        handle.write('label\tstart\tend\tbytes\tsha256\n')
        for label, start, end in WINDOWS:
            handle.write(f"{label}\t{start:#x}\t{end:#x}\t{end - start}"
                         f"\t{checked['window_hashes'][label]}\n")

    # cases.tsv keeps the first 64 rows (all structured sequences); the
    # full 2400-case run is summarised in result.json by its aggregate
    # digest.
    sample = rows[:64]
    with (dest / 'cases.tsv').open('w', encoding='utf-8') as handle:
        handle.write('idx\tthreaded\tinit_guard\tinit_live\tinit_empty\tops\tgets\tinit_runs\tfinal_use\tfinal_live\n')
        for idx, (initial, ops, result) in enumerate(sample):
            handle.write(f"{idx}\t{1 if initial['threaded'] else 0}"
                         f"\t{initial['guard']}\t{initial['live_copies']}"
                         f"\t{1 if initial['static_pi'] is None and initial['guard'] == 1 else 0}"
                         f"\t{ops}\t{ops.count('G')}\t{result['init_runs']}"
                         f"\t{result['final_use']}\t{result['final_live']}\n")

    check_values = {
        'fresh_first_get': {
            'call': list(call_getter_model(fresh_state())),
            'note': 'init runs once, returns (A, B), use_count 1 -> 2'},
        'five_gets_from_fresh': {
            'final_use': run_sequence_model(fresh_state(), 'GGGGG')['final_use'],
            'init_runs': 1,
            'note': 'one static reference + five live copies'},
        'get_then_release': {
            'final_use': run_sequence_model(fresh_state(), 'GR')['final_use'],
            'note': 'use_count returns to 1 (the static reference)'},
        'threaded_flag_selects_plain_increment': {
            'flag_zero_form': call_getter_model(fresh_state())[4],
            'flag_nonzero_form': call_getter_model(fresh_state(threaded=True))[4],
            'note': 'flag byte 0 -> lock addl at 0x61cd660; nonzero -> plain addl at 0x61cd64c'},
        'defensive_empty_static': {
            'call': list(call_getter_model(defensive_empty_state())),
            'note': 'guard set but static empty returns (None, None) with no increment'},
        'init_layout': init_layout(),
    }
    result = {
        'target_digest': DIGEST,
        'function': {'start': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
                     'body_sha256': checked['body_hash'],
                     'fde': [f'{FUNCTION_START:#x}', f'{FUNCTION_END:#x}'],
                     'census_symbol': 'rocksdb::GetFileChecksumGenCrc32cFactory',
                     'census_body_sha256': checked['body_hash']},
        'guard': {'address': f'{GUARD_ADDR:#x}',
                  'observation': 'byte tested first; nonzero jumps straight to the copy path'},
        'static': {'ptr': f'{STATIC_PTR_ADDR:#x}', 'control_ptr': f'{STATIC_PI_ADDR:#x}',
                   'layout': '16-byte shared_ptr: factory pointer +0x0, control pointer +0x8'},
        'semantics': 'return the process-wide shared FileChecksumGenCrc32cFactory, '
                     'creating it (and its control block) on the first call; every call '
                     'returns the same pair and raises use_count by 1',
        'init': init_layout(),
        'copy': {'form': '16-byte movdqa load + movups store; increment use_count by 1 '
                         'iff the control pointer is nonzero',
                 'increment': 'lock addl when the thread-flag byte is 0, plain addl otherwise',
                 'thread_flag_slot': f'{THREAD_FLAG_SLOT:#x} (.got, zero in the static image)'},
        'check_values': check_values,
        'cases': {'count': len(rows), 'seed': CASE_SEED,
                  'gets': total_gets, 'releases': total_releases,
                  'init_runs': total_inits,
                  'mismatches_vs_reference': 0,
                  'aggregate_sha256': aggregate},
    }
    (dest / 'result.json').write_text(json.dumps(result, indent=2) + '\n',
                                      encoding='utf-8')

    records = {
        'target_digest': DIGEST,
        'records': [
            {'kind': 'function', 'task': 'RE-002',
             'address': f'{FUNCTION_START:#x}', 'end': f'{FUNCTION_END:#x}',
             'body_sha256': checked['body_hash'],
             'identity': 'rocksdb::GetFileChecksumGenCrc32cFactory (vendor census)',
             'contract': 'get() -> shared_ptr<FileChecksumGenCrc32cFactory> via a '
                         'hidden out-pointer in rdi; no other argument',
             'semantics': 'return the process-wide shared factory; create it on the '
                          'first call; every call returns the same (factory, control) '
                          'pair and raises use_count by 1'},
            {'kind': 'guard', 'address': f'{GUARD_ADDR:#x}',
             'observation': 'the guard byte is tested first (movzbl + test at '
                            '0x61cd608..0x61cd614); any nonzero value jumps to the copy '
                            'path at 0x61cd629. When it is zero, __cxa_guard_acquire '
                            '(PLT 0x63f0fc0) decides: a zero return also goes to the copy '
                            'path, a nonzero return runs the init path and then '
                            '__cxa_guard_release (PLT 0x63f0fd0)'},
            {'kind': 'static', 'ptr': f'{STATIC_PTR_ADDR:#x}',
             'control_ptr': f'{STATIC_PI_ADDR:#x}',
             'observation': 'the static is a 16-byte shared_ptr in .bss (zero at load): '
                            'factory pointer at +0x0, control pointer at +0x8'},
            {'kind': 'init_factory', 'address': '0x61cd670',
             'size': f'{FACTORY_SIZE:#x}', 'vtable_address_point': f'{FACTORY_VTABLE:#x}',
             'observation': 'operator new(0x20) through PLT 0x63f0dd0; the whole object '
                            'is zeroed with two movups, then the vptr is stored from lea '
                            '0x64d79a0 + add $0x10, and the static pointer is set to the '
                            'new object'},
            {'kind': 'init_control', 'address': '0x61cd6ae',
             'size': f'{CONTROL_SIZE:#x}', 'vtable_address_point': f'{CONTROL_VTABLE:#x}',
             'counts_word': f'{COUNTS_CONST:#018x}',
             'observation': 'operator new(0x18) through PLT 0x63f0dd0; the vptr is stored '
                            'from lea 0x64d7a80 + add $0x10; the counts word comes from the '
                            '.rodata constant at 0x459b20 (use_count 1, weak_count 1); the '
                            'managed pointer at +0x10 is the factory object; the static '
                            'control pointer is set to the new block'},
            {'kind': 'atexit', 'destructor': f'{DTOR_ADDR:#x}',
             'dso_handle': f'{DSO_HANDLE_ADDR:#x}',
             'observation': '__cxa_atexit (PLT 0x63f0f80) registers the destructor at '
                            '0x61cd720 for the static shared_ptr, with the dso handle '
                            'loaded from lea 0x64efa20'},
            {'kind': 'copy', 'address': '0x61cd629',
             'observation': 'the 16-byte static is loaded with movdqa and stored to the '
                            'out-pointer with movups; when the control pointer is zero no '
                            'increment runs and the call returns the null pair'},
            {'kind': 'increment', 'address': '0x61cd63e',
             'observation': 'the .got pointer at 0x64ed290 is dereferenced and its byte '
                            'tested: 0 selects lock addl $0x1, 0x8(%rax) at 0x61cd660, '
                            'nonzero selects plain addl $0x1, 0x8(%rax) at 0x61cd64c. The '
                            '.got slot is zero in the static image (runtime-filled); the '
                            'byte selecting the form is consistent with '
                            '__libc_single_threaded (1 = single-threaded), which is an '
                            'inference, not a proven identity'},
            {'kind': 'factory_layout', 'subject': 'FileChecksumGenCrc32cFactory object',
             'size': f'{FACTORY_SIZE:#x}', 'vptr': '+0x0',
             'member': 'vector-like member at +0x8 (begin), +0x10 (end), +0x18 '
                       '(capacity); elements are 0x30 bytes',
             'observation': 'the deleting destructor at 0x61cd400 frees the object with '
                            'size 0x20 after destroying the member: it walks [begin, end) '
                            'in 0x30-byte steps, freeing each element heap buffer at '
                            '[element+0] with size [element+0x10]+1 unless [element+0] '
                            'equals element+0x10, then frees the array with size '
                            'end-begin. That is the std::string _M_dispose shape (pointer '
                            '+0, length +8, SSO buffer / allocated capacity +0x10), '
                            'confirmed by the identical codegen in the generator destructor '
                            'at 0x61cd490 for the string at generator+0x10; the init path '
                            'zeroes the member, so the singleton starts empty'},
            {'kind': 'control_vtable', 'address_point': f'{CONTROL_VTABLE:#x}',
             'observation': 'entries from the R_X86_64_RELATIVE relocations: slot 0 '
                            '0x61cd080 is a bare return (complete destructor), slot 1 '
                            '0x61cd180 is operator delete with size 0x18 (deleting '
                            'destructor), slot 2 0x61cd110 deletes the managed factory '
                            'object through its deleting destructor at 0x61cd400 '
                            '(factory vtable slot 1), slot 3 0x61cd190 is operator delete '
                            'with size 0x18, slot 4 0x61cd130 returns null'},
            {'kind': 'factory_vtable', 'address_point': f'{FACTORY_VTABLE:#x}',
             'observation': 'the merged factory-vtable packet lists this address point '
                            'with slot 19 = CreateFileChecksumGenerator at 0x61cd2e0, '
                            'slot 0 = complete destructor 0x61cd370 and slot 1 = deleting '
                            'destructor 0x61cd400; that packet records the slots only, '
                            'this packet reconstructs the getter that hands the factory out'},
            {'kind': 'release', 'destructor': f'{DTOR_ADDR:#x}',
             'observation': 'the atexit destructor releases the static: when the counts '
                            'word is exactly 0x0000000100000001 it zeroes the counts, '
                            'calls control-vtable slot 2 (dispose) and tail-calls slot 3 '
                            '(destroy); otherwise it decrements use_count (lock xadd when '
                            'the thread-flag byte is 0, plain decrement otherwise) and, '
                            'when the old value was 1, tail-calls the shared release '
                            'helper at 0x5d35070'},
            {'kind': 'landing_pad', 'address': '0x61cd6fe',
             'observation': 'two landing pads inside the FDE: 0x61cd6fe jumps to '
                            '0x61cd5d1 (__cxa_guard_abort, then _Unwind_Resume) and '
                            '0x61cd70a jumps to 0x61cd5e1 (__cxa_begin_catch, delete the '
                            'factory object via 0x61cd400, __cxa_rethrow). Both targets '
                            'lie just before the FDE start; which call site each pad '
                            'covers was not decoded (the LSDA was not parsed)'},
        ] + [
            {'kind': 'window', 'label': label, 'start': f'{start:#x}',
             'end': f'{end:#x}', 'sha256': checked['window_hashes'][label]}
            for label, start, end in WINDOWS
        ] + [
            {'kind': 'case_summary', 'count': len(rows), 'seed': CASE_SEED,
             'gets': total_gets, 'releases': total_releases,
             'init_runs': total_inits,
             'aggregate_sha256': aggregate,
             'mismatches_vs_reference': 0,
             'note': 'each sequence cross-checked between a step-by-step '
                     'transliteration of the disassembly and a closed-form '
                     'reference (use_count = 1 + live copies once initialised); '
                     'the binary itself was never executed'},
            {'kind': 'unknown', 'subject': 'factory member element identity',
             'status': 'each 0x30-byte element starts with a std::string; the '
                       'trailing 0x10 bytes of the element and what the member '
                       'holds in practice are not determined from this packet'},
            {'kind': 'unknown', 'subject': 'thread-flag byte identity',
             'status': 'the .got slot at 0x64ed290 is zero in the static image and '
                       'filled at load; the byte it points to selects the atomic '
                       'vs plain increment, consistent with __libc_single_threaded, '
                       'but the target was not resolved from the binary'},
            {'kind': 'unknown', 'subject': 'shared release helper at 0x5d35070',
             'status': 'the destructor tail-calls it when the last use drops; its '
                       'body was not decoded in this packet'},
            {'kind': 'unknown', 'subject': 'callers of GetFileChecksumGenCrc32cFactory',
             'status': 'no caller census was run for this packet'},
        ],
    }
    (dest / 'records.json').write_text(json.dumps(records, indent=2) + '\n',
                                       encoding='utf-8')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', type=Path, default=None,
                        help='generate the evidence packet into DIR')
    parser.add_argument('--cases', type=int, default=CASE_COUNT,
                        help='cases to run in the model cross-check')
    parser.add_argument('--verify', action='store_true',
                        help='verify pinned bytes only, without generating')
    args = parser.parse_args(argv)

    data = TARGET.read_bytes()
    checked = verify(data)
    if args.verify or args.out is None:
        rows = run_cases(generate_cases(args.cases))
        gets = sum(ops.count('G') for _, ops, _ in rows)
        inits = sum(r['init_runs'] for _, _, r in rows)
        print(f"verified: body {checked['body_hash'][:16]}...; "
              f"{len(rows)} cases agree with the references "
              f"({gets} gets, {inits} inits); "
              f"first call = {call_getter_model(fresh_state())}; "
              f"five gets use = {run_sequence_model(fresh_state(), 'GGGGG')['final_use']}")
        if args.out is None:
            return 0
    result = generate(data, args.out)
    print(f"wrote packet to {args.out}: "
          f"{result['cases']['count']} cases, aggregate "
          f"{result['cases']['aggregate_sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
