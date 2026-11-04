"""Mathematical read/write relation for supplied import outcomes.

This is an evidence aid, not a networking implementation, instruction evaluator,
or independently executed target oracle. Volatile post-accept register values
are optional observation parameters, never guessed incoming ABI values.
"""
U32 = (1 << 32) - 1
U64 = (1 << 64) - 1


def helper(listener_fd, accept_return, storage, initial_output, errno=0,
           output_address=0, volatile=None, returned_length=128, close_return=0):
    if not -(1 << 31) <= accept_return < (1 << 31):
        raise ValueError('supplied C int return')
    if len(initial_output) != 40 or not 0 <= output_address <= U64:
        raise ValueError('40-byte caller result image and numeric pointer')
    out = list(initial_output); writes = []; reads = []; events = []
    events.append(['accept4', listener_fd & U32, 128, 0x80800])

    def write(offset, value, size):
        bs = [None] * size if value is None else list((value % (1 << (8 * size))).to_bytes(size, 'little'))
        out[offset:offset + size] = bs
        writes.append([offset, ''.join('??' if b is None else f'{b:02x}' for b in bs)])

    def read(offset, size):
        if offset + size > len(storage):
            raise ValueError('reached initialized sockaddr bytes')
        reads.append([offset, size])
        return int.from_bytes(storage[offset:offset + size], 'little')

    if accept_return < 0:
        events.append(['errno', errno & U32])
        write(8, ((errno & U32) << 32) | 2, 8); write(0, 1, 4)
        kind, active = 'os-error', {'error_word': ((errno & U32) << 32) | 2}
    else:
        family = read(0, 2)
        if family not in (2, 10):
            write(8, 0x1400000003, 8); write(0, 1, 4)
            events.append(['close', accept_return, bytes(out).hex()])
            kind, active = 'family-error', {'error_word': 0x1400000003}
        else:
            if family == 2:
                address = read(4, 4); port = read(2, 2)
                port = ((port & 255) << 8) | (port >> 8)
                r11, r10, edi, esi = (None,) * 4 if volatile is None else volatile
                chunk, tail, family_tag = address, port, 0
                extra_port = 2  # ECX was overwritten by the full u16 family load.
                active = {'fd': accept_return, 'family': 4, 'address': storage[4:8].hex(), 'port': port}
            else:
                extra_port = read(2, 2)
                extra_port = ((extra_port & 255) << 8) | (extra_port >> 8)
                edi = read(4, 4); esi = read(24, 4)
                chunk = (read(8, 4) << 16) & U32
                tail = read(10, 2); r11 = read(12, 8); r10 = read(20, 4); family_tag = 1
                active = {'fd': accept_return, 'family': 6, 'address': storage[8:24].hex(),
                          'port': extra_port, 'flowinfo': edi, 'scope_id': esi}
            for offset, value, size in [(4, accept_return, 4), (8, family_tag, 2), (10, chunk, 4),
                                        (14, tail, 2), (16, r11, 8), (24, r10, 4), (28, edi, 4),
                                        (32, esi, 4), (36, extra_port, 2), (0, 0, 4)]:
                write(offset, value, size)
            kind = 'success'
    return {'kind': kind, 'active': active,
            'output_hex': ''.join('??' if b is None else f'{b:02x}' for b in out),
            'known_bytes': [b is not None for b in out], 'writes': writes,
            'sockaddr_reads': reads, 'events': events, 'rax': output_address}


def caller_boundary(caller_index, helper_kind, errno=0, family=4,
                    registration_tag=0, fd_after_registration=0, fd_after_cleanup=0):
    """Only the explicit local request/continuation boundary, not opaque effects.

The supplied post-callback fd values distinguish actual reloads from a guessed
preserved descriptor. Retry readiness/CAS progress, registration and cleanup
implementations, later loops and unwind remain outside this relation.
"""
    if caller_index not in range(4):
        raise ValueError('four static callers')
    if helper_kind == 'os-error':
        return {'boundary': 'would-block' if (errno & U32) == 11 else 'other-error', 'events': []}
    if helper_kind == 'family-error':
        return {'boundary': 'other-error', 'events': []}  # helper already requested close
    if helper_kind != 'success' or family not in (4, 6):
        raise ValueError('reached helper variant')
    events = [['register', 3]]
    if registration_tag == 2:
        events.append(['close', fd_after_registration & U32])
        return {'boundary': 'registration-error', 'events': events}
    if caller_index < 3 and family == 6:
        events += [['make-error', 'ip not v4'], ['cleanup']]
        if (fd_after_cleanup & U32) != U32:
            events.append(['close', fd_after_cleanup & U32])
        events.append(['drop'])
        return {'boundary': 'ipv6-rejected', 'events': events}
    return {'boundary': 'ipv4-continuation' if caller_index < 3 else 'address-forwarded', 'events': events}
