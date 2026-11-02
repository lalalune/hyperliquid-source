"""Finite counterexamples for the proved conditional relation, not an emulator.

The three ordered requests are formulated as a table of independent predicates
and value projections. This is an evidence model, not a production API or a
native differential against the target or libc.
"""
import struct

SENTINEL = 1_000_000_000
MAX_SECONDS = (1 << 31) - 1


def requests(record):
    if len(record) != 36:
        raise ValueError('exact 36-byte read projection')
    retries_tag, retries = struct.unpack_from('<II', record)
    seconds0, nanos0 = struct.unpack_from('<QI', record, 8)
    seconds1, nanos1 = struct.unpack_from('<QI', record, 24)
    candidates = [(nanos0 != SENTINEL, 4, min(seconds0, MAX_SECONDS)),
                  (nanos1 != SENTINEL, 5, min(seconds1, MAX_SECONDS)),
                  (retries_tag == 1, 6, retries)]
    return [(6, option, value.to_bytes(4, 'little'), 4)
            for present, option, value in candidates if present]


def helper(record, returns, errno):
    active = requests(record)
    if len(returns) != 3:
        raise ValueError('one result for each named option')
    failure = next((i for i, request in enumerate(active)
                    if returns[request[1] - 4] == -1), None)
    used = active if failure is None else active[:failure + 1]
    return {'requests': used, 'errno_reads': int(failure is not None),
            'rax': 0 if failure is None else ((errno & 0xffffffff) << 32) | 2}


def caller_stage(enabled, enable_return, record, option_returns, errno):
    """Both callers continue after normal returns from opaque logging helpers.

Returns a protocol observation, not the complete caller output/async state.
The server/config constructors are described separately in CONTRACT.md.
"""
    if not enabled:
        return {'calls': [], 'error_word': None, 'custom_drop': False, 'continues': True}
    calls = [(1, 9, b'\x01\0\0\0', 4)]
    if enable_return == -1:
        error = ((errno & 0xffffffff) << 32) | 2
    else:
        result = helper(record, option_returns, errno)
        calls += result['requests']
        error = result['rax'] or None
    return {'calls': calls, 'error_word': error,
            'custom_drop': error is not None and error & 3 == 1, 'continues': True}


def fixture(t=1, retries=0xffffffff, s0=0, n0=0, s1=0, n1=0):
    return struct.pack('<IIQI4xQI', t, retries, s0, n0, s1, n1)
