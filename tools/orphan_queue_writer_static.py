"""RE-005 node 115: who writes the SIGCHLD orphan queue?

Follow-up to the timeout cache object packet (PR #2947),
which pinned the park slow-path refresh body 0x5cee650 and
the orphan reap pass 0x5cee900 it drives (vendored tokio,
process/unix/orphan.rs:118), and recorded that no static
pusher for the orphan queue exists. This packet re-derives,
from the authenticated hl-node 115 artifact only:

* the orphan queue header layout (lock byte 0x64fede0,
  never-referenced word 0x64fede8, buffer pointer
  0x64fedf0, length 0x64fedf8) and its file initial values;
* the 0x1c-byte record layout the reap pass consumes
  (+0x00 status tag, +0x04 cached exit status, +0x08 pid,
  +0x0c pidfd, +0x10/+0x14/+0x18 stdio fds), read off the
  reap pass and its two wait bodies: the non-blocking
  convert/try-wait body 0x5c902e0 (reached only through
  GOT slot 0x64ec898, only from the reap pass) and the
  blocking wait body 0x5c94a80, with the pidfd helper
  0x5c875f0 both of them share;
* the complete RIP-relative reference census for every
  queue word, in both disp-final form and the
  trailing-immediate form (disp followed by up to 8 bytes
  of immediate): the queue globals are materialised ONLY
  by the refresh body and the reap pass itself, so no
  statically-addressing writer exists, and the enqueue is
  necessarily pointer-carried;
* the negative evidence: the single raw-scan hit for the
  0x64fede8 word is a mid-instruction byte pattern inside
  an unrelated constructor body 0x63ba600, the x28 stride
  arithmetic appears in the process region only inside
  the reap pass, and the only process-module panic
  Location in the binary is orphan.rs:118:20.

Any drift in a body hash, census, slot resolution,
Location count, byte pin or initial value fails
verification rather than silently rewriting the packet.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SNAPSHOT = 'artifacts/node/115/hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7a8278'
                 'fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-orphan-queue-writer'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM

BODIES = {
    'refresh': 0x5cee650,
    'reap': 0x5cee900,
    'convert': 0x5c902e0,
    'wait': 0x5c94a80,
    'fdhelper': 0x5c875f0,
    'spawn': 0x5c84a40,
    'waituser': 0x5c98260,
    'appwait_a': 0x1535fd0,
    'appwait_b': 0x1565460,
    'falsepos': 0x63ba600,
}

GLOBALS = {
    'lock_orphan': 0x64fede0,
    'queue_word_e8': 0x64fede8,
    'queue_base': 0x64fedf0,
    'queue_len': 0x64fedf8,
    'slab_counter': 0x64fedd8,
}

SLOTS = {
    'convert_slot': 0x64ec898,
    'waitpid_slot': 0x64ec8a0,
}

BYTE_PINS = {
    # refresh: cmpq $0x0, queue_len(%rip) - trailing imm8 form
    'refresh_len_test': (0x5cee6e0, '48833d1007810000'),
    # reap pass: lea rcx, [rax + rax*8] (x9 of the x28 stride)
    'reap_stride_x9': (0x5cee922, '488d0cc0'),
    # reap pass: mov rcx, queue_len store after swap-remove
    'reap_len_store': (0x5cee9d3, '48890d1e048100'),
    # convert: cmpl $0x1, (%rsi) - record status tag test
    'convert_tag_test': (0x5c902ee, '833e01'),
    # convert: mov 0xc(%rsi), %eax - record pidfd load
    'convert_pidfd_load': (0x5c90305, '8b460c'),
    # convert: mov $0x5, %edx - waitid flags WEXITED|WNOHANG
    'convert_waitid_mode': (0x5c90316, 'ba05000000'),
    # convert: mov 0x8(%rsi), %edi - record pid load
    'convert_pid_load': (0x5c90336, '8b7e08'),
    # convert: mov $0x1, %edx - waitpid WNOHANG
    'convert_waitpid_flags': (0x5c9033d, 'ba01000000'),
    # convert: movl $0x1, (%r14) - mark record reaped
    'convert_mark_reaped': (0x5c90387, '41c70601000000'),
    # convert: mov %eax, 0x4(%r14) - cache raw exit status
    'convert_status_store': (0x5c9038e, '41894604'),
    # wait: cmpl $0x1, (%rsi) - record status tag test
    'wait_tag_test': (0x5c94a97, '833e01'),
    # wait: mov 0xc(%r14), %esi - record pidfd load
    'wait_pidfd_load': (0x5c94aa5, '418b760c'),
    # wait: mov $0x4, %edx - waitid flags WEXITED (blocking)
    'wait_waitid_mode': (0x5c94ab2, 'ba04000000'),
    # wait: mov 0x8(%r14), %r15d - record pid load
    'wait_pid_load': (0x5c94ae1, '458b7e08'),
    # wait: xor %edx, %edx - waitpid flags 0 (blocking)
    'wait_waitpid_flags': (0x5c94aec, '31d2'),
    # fdhelper: mov $0x3, %edi - waitid idtype P_PIDFD
    'fdhelper_pidfd_idtype': (0x5c8764c, 'bf03000000'),
    # fdhelper: mov $0xc040ff0b, %esi - pidfd ioctl fallback
    'fdhelper_ioctl': (0x5c876de, 'be0bff40c0'),
    # false positive body: movb $0x0, 0x14(%rdi) - the byte
    # pattern the raw scan mistook for a disp32 to 0x64fede8
    'falsepos_movb': (0x63ba61e, 'c6471400'),
    # false positive body: movl $0x0, 0x20(%rdi)
    'falsepos_movl': (0x63ba622, 'c7472000000000'),
}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sections(data):
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
    raw = []
    for i in range(e_shnum):
        raw.append(struct.unpack_from(
            '<IIQQQQ', data, e_shoff + i * e_shentsize))
    strbase = raw[e_shstrndx][4]
    out = {}
    for name, typ, flags, addr, offset, size in raw:
        end = data.index(b'\x00', strbase + name)
        out[data[strbase + name:end].decode()] = {
            'type': typ, 'addr': addr, 'offset': offset,
            'size': size}
    return out


def va_slice(data, secs, va, size):
    for sec in secs.values():
        if sec['addr'] <= va < sec['addr'] + sec['size']:
            off = sec['offset'] + (va - sec['addr'])
            return data[off:off + size]
    raise ValueError('va not mapped: %#x' % va)


def va_qword(data, secs, va):
    return struct.unpack('<Q', va_slice(data, secs, va, 8))[0]


def va_byte(data, secs, va):
    return va_slice(data, secs, va, 1)[0]


def fde_table():
    text = subprocess.run(
        ['readelf', '--debug-dump=frames', str(TARGET)],
        capture_output=True, text=True).stdout
    table = []
    for line in text.splitlines():
        m = re.search(r'pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
        if m:
            table.append((int(m.group(1), 16),
                          int(m.group(2), 16)))
    table.sort()
    return table


def fde_of(table, va):
    import bisect
    starts = [s for s, _ in table]
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and table[i][0] <= va < table[i][1]:
        return table[i]
    return None


def rip_scan(data, secs, table):
    """One pass over .text: disp-final census for all census
    targets, plus the trailing-immediate form (k = 1..8) for
    the queue words. Returns {name: [site records]}."""
    import numpy as np
    ts = secs['.text']
    base = ts['addr']
    blob = data[ts['offset']:ts['offset'] + ts['size']]
    out = {}

    def record(name, idx, k):
        end = base + idx + 4
        fde = fde_of(table, end - 1)
        out.setdefault(name, []).append({
            'disp_end': hex(end),
            'k': k,
            'in_body': hex(fde[0]) if fde else None})

    final_targets = dict(GLOBALS)
    final_targets.update(SLOTS)
    trail_targets = ('lock_orphan', 'queue_word_e8',
                     'queue_base', 'queue_len')
    # Overlapping disp32 windows at every byte offset of
    # .text, processed in chunks: val = end + disp.
    chunk = 1 << 22
    u8 = np.frombuffer(blob, dtype=np.uint8)
    n = len(blob) - 3
    for start in range(0, n, chunk):
        stop = min(start + chunk, n)
        w = u8[start:stop + 3].astype(np.int64)
        disp = (w[:-3] | (w[1:-2] << 8) | (w[2:-1] << 16)
                | (w[3:] << 24))
        disp = np.where(disp >= 1 << 31, disp - (1 << 32),
                        disp)
        ends = base + start + np.arange(stop - start,
                                        dtype=np.int64) + 4
        vals = ends + disp
        for name, tgt in final_targets.items():
            for idx in np.nonzero(vals == tgt)[0]:
                record(name, start + int(idx), 0)
        for name in trail_targets:
            tgt = GLOBALS[name]
            for k in range(1, 9):
                for idx in np.nonzero(vals == tgt - k)[0]:
                    record(name + '_trail', start + int(idx),
                           k)
    for sites in out.values():
        sites.sort(key=lambda s: (int(s['disp_end'], 16),
                                  s['k']))
    return out


def rel32_census(data, secs, table, targets):
    ts = secs['.text']
    base = ts['addr']
    blob = data[ts['offset']:ts['offset'] + ts['size']]
    wanted = {v: k for k, v in targets.items()}
    out = {}
    for i in range(len(blob) - 5):
        op = blob[i]
        if op in (0xe8, 0xe9):
            rel = struct.unpack_from('<i', blob, i + 1)[0]
            tgt = base + i + 5 + rel
            if tgt in wanted:
                fde = fde_of(table, base + i)
                out.setdefault(wanted[tgt], []).append({
                    'site': hex(base + i),
                    'kind': 'call' if op == 0xe8 else 'jmp',
                    'in_body': hex(fde[0]) if fde else None})
    for sites in out.values():
        sites.sort(key=lambda s: int(s['site'], 16))
    return out


def rela_map():
    text = subprocess.run(['readelf', '-rW', str(TARGET)],
                          capture_output=True, text=True).stdout
    out = {}
    for line in text.splitlines():
        m = re.match(r'\s*([0-9a-f]+)\s+([0-9a-f]+)\s+(\S+)'
                     r'\s+([0-9a-f]+)(?:\s+(.*))?$', line)
        if not m:
            continue
        off = int(m.group(1), 16)
        if off in SLOTS.values():
            out[hex(off)] = {'type': m.group(3),
                             'addend_or_sym': m.group(5) or ''}
    return out


def idiom_scan(data, secs):
    """x28 stride idiom: lea r,[r+r*8] followed within 16
    bytes by lea r,[r+r*2], in the process region
    0x5c00000..0x5d00000. The reap pass uses it to scale a
    queue index; any producer scaling an index into the
    same queue would need the same arithmetic."""
    ts = secs['.text']
    base = ts['addr']
    blob = data[ts['offset']:ts['offset'] + ts['size']]
    hits = []
    lo = 0x5c00000 - base
    hi = 0x5d00000 - base
    for i in range(lo, hi - 3):
        if blob[i] in (0x48, 0x4c) and blob[i + 1] == 0x8d:
            modrm = blob[i + 2]
            sib = blob[i + 3]
            if (modrm >> 6) == 0 and (modrm & 7) == 4 \
                    and (sib >> 6) == 3 and (sib & 7) == (sib >> 3) & 7:
                start = base + i
                for j in range(i, min(i + 16, hi - 3)):
                    if blob[j] in (0x48, 0x4c) \
                            and blob[j + 1] == 0x8d:
                        m2 = blob[j + 2]
                        s2 = blob[j + 3]
                        if (m2 >> 6) == 0 and (m2 & 7) == 4 \
                                and (s2 >> 6) == 1 \
                                and (s2 & 7) == (s2 >> 3) & 7:
                            hits.append(hex(start))
                            break
    return hits


def imul_scan(data, secs):
    """imul with imm8 0x1c (the other x28 encoding)."""
    ts = secs['.text']
    base = ts['addr']
    blob = data[ts['offset']:ts['offset'] + ts['size']]
    hits = []
    for i in range(len(blob) - 3):
        if blob[i] == 0x6b and blob[i + 3] == 0x1c:
            hits.append(hex(base + i))
    return hits


def stored_scan(data, values):
    out = {}
    for name, va in values.items():
        needle = struct.pack('<Q', va)
        offs = []
        start = 0
        while True:
            j = data.find(needle, start)
            if j < 0:
                break
            offs.append(hex(j))
            start = j + 1
        out[name] = offs
    return out


def analyze(data):
    check(len(data) == TARGET_SIZE, 'artifact size drift')
    check(sha(data) == TARGET_SHA256, 'artifact sha256 drift')
    secs = sections(data)
    table = fde_table()

    bodies = {}
    for name, va in BODIES.items():
        fde = fde_of(table, va)
        check(fde is not None and fde[0] == va,
              'body %s not at an FDE start' % name)
        size = fde[1] - fde[0]
        bodies[name] = {'va': hex(va), 'size': size,
                        'sha256': sha(va_slice(data, secs,
                                               va, size))}

    queue_init = {
        'lock_orphan': va_byte(data, secs, GLOBALS['lock_orphan']),
        'queue_word_e8': va_qword(data, secs,
                                  GLOBALS['queue_word_e8']),
        'queue_base': va_qword(data, secs, GLOBALS['queue_base']),
        'queue_len': va_qword(data, secs, GLOBALS['queue_len']),
    }

    pins = {}
    for name, (va, want) in BYTE_PINS.items():
        got = va_slice(data, secs, va,
                       len(bytes.fromhex(want))).hex()
        check(got == want, 'byte pin drift: %s' % name)
        pins[name] = {'va': hex(va), 'bytes': want}

    rip = rip_scan(data, secs, table)
    calls = rel32_census(data, secs, table,
                         {'convert': BODIES['convert'],
                          'wait': BODIES['wait']})
    rela = rela_map()
    idiom = idiom_scan(data, secs)
    imul = imul_scan(data, secs)
    stored = stored_scan(data, {
        'queue_lock_va': GLOBALS['lock_orphan'],
        'queue_e8_va': GLOBALS['queue_word_e8'],
        'queue_base_va': GLOBALS['queue_base'],
        'queue_len_va': GLOBALS['queue_len'],
        'convert_va': BODIES['convert'],
        'wait_va': BODIES['wait'],
        'reap_va': BODIES['reap'],
        'refresh_va': BODIES['refresh'],
    })
    strings = {
        'process_path_count':
            data.count(b'z_vendor/tokio/src/process/'),
        'orphan_rs_count': data.count(b'orphan.rs'),
    }

    return {
        'artifact': {'size': TARGET_SIZE,
                     'sha256': TARGET_SHA256,
                     'snapshot': SNAPSHOT},
        'bodies': bodies,
        'queue_init': queue_init,
        'byte_pins': pins,
        'rip_census': rip,
        'call_census': calls,
        'rela': rela,
        'stride_idiom_x28': idiom,
        'imul_0x1c_sites': imul,
        'stored_pointers': stored,
        'string_census': strings,
    }


def exports(role):
    return BODIES[role]


def frame_lines():
    table = fde_table()
    lines = []
    for name, va in BODIES.items():
        fde = fde_of(table, va)
        lines.append('%s %s..%s' % (name, hex(fde[0]),
                                    hex(fde[1])))
    return lines


def generate(records):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(
        '\n'.join(frame_lines()) + '\n')
    for name, va in BODIES.items():
        fde = fde_of(fde_table(), va)
        text = subprocess.run(
            ['objdump', '-d', '--start-address=%#x' % fde[0],
             '--stop-address=%#x' % fde[1], str(TARGET)],
            capture_output=True, text=True).stdout
        (OUT / ('%s.objdump.txt' % name)).write_text(text)


def main(argv):
    if '--generate' in argv:
        generate(analyze(TARGET.read_bytes()))
        return 0
    records = analyze(TARGET.read_bytes())
    print(json.dumps(records, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
