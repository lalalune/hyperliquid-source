#!/usr/bin/env python3
"""Bind the node #115 parent mode byte +0x248 / +0x249 writers (76th stage).

Continues the startup-check flag packet (open #6074). That packet traced the
startup future's bytes +0x0 / +0x1 back to parent byte +0x248 and the byte
after it. This tool binds:

1. every write to parent +0x248 / +0x249 in the two parents 0x2ae41e0 and
   0x2cde430: two byte stores per parent (2 on the tag-2 path, 1 on the
   tag-3 path), no byte or word store to +0x249, and four 16-byte stores per
   parent that copy zero/constant blocks after a different sub-future;
2. the pollers 0x2aeaef0 and 0x2cb6500: each has exactly two direct calls,
   both right after one of those byte stores, and no relocation names them;
   each copies its own +0x28..+0x38 (parent +0x248..+0x258) to +0x38;
3. 0x2c7d950, the caller of the second line counter 0x1563bc0: a loop that
   sleeps 60 s with clock_nanosleep(CLOCK_MONOTONIC), retries on EINTR,
   panics (std thread/unix.rs:581:17) on any other error, then copies a
   locked byte buffer and passes it to slot 0x64e1218 -> 0x1563bc0.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check, manifest_item  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from freeze_snapshot_115 import (  # noqa: E402
    RELATIVE, SHA256, TARGET, fixed, read_va, relative_relocations, text)

PACKET = ROOT / 'research/work-items/RE-008-parent-mode-bytes-115'

PARENTS = {'0x2ae41e0': (0x2ae41e0, 0x2ae6d66), '0x2cde430': (0x2cde430, 0x2ce0dd1)}
POLLERS = {0x2aeaef0: (0x2ae4627, 0x2ae548c), 0x2cb6500: (0x2cde6f4, 0x2cdf58b)}
SLEEP_SLOT, LINE_SLOT, LINE_FN = 0x64e11e8, 0x64e1218, 0x1563bc0
LOOP = (0x2c7d950, 0x2c7db49)
LOCATION = 0x64c3bc8

FIXED = {
    # parent A: tag-2 and tag-3 mode stores, then the poller call on rbx+0x220
    0x2ae4604: 'c6834802000002', 0x2ae461d: '4c8db320020000', 0x2ae4624: '4c89f7',
    0x2ae5469: 'c6834802000001', 0x2ae5482: '4c8db320020000', 0x2ae5489: '4c89f7',
    # parent B: same on r13+0x220
    0x2cde6d0: '41c6854802000002', 0x2cde6e7: '4d8db520020000', 0x2cde6ee: '4c89f7',
    0x2cdf567: '41c6854802000001', 0x2cdf57e: '4d8da520020000', 0x2cdf585: '4c89e7',
    # pollers: entry copies +0x28..+0x38 to +0x38
    0x2aeaf65: '0f104328', 0x2aeaf69: '0f114338',
    0x2cb6575: '0f104328', 0x2cb6579: '0f114338',
    # 0x2c7d950 loop
    0x2c7d972: '4c8b35', 0x2c7d980: '41bf3c000000', 0x2c7d9b9: 'bf01000000',
    0x2c7d9c6: '41ffd6', 0x2c7d9cd: '85c0', 0x2c7d9d1: '83f804',
    0x2c7d9fe: 'f0410fb04c2410', 0x2c7da78: 'ff15', 0x2c7da95: 'e9e6feffff',
    0x2c7da9d: 'ba00ca9a3b', 0x2c7dac1: '4c8d0d',
}
MODE_STORES = {0x2ae4604: 2, 0x2ae5469: 1, 0x2cde6d0: 2, 0x2cdf567: 1}
ZERO_BLOCK = 0x457d30


def dynsym_name(data, slot):
    secs = sections(data)
    rela = [s for s in secs if s['type'] == 4]
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    for sec in rela:
        for va, info, _ in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if va == slot and info & 0xffffffff == 6:
                idx = info >> 32
                name_off = struct.unpack_from('<I', data, dynsym['offset'] + 24 * idx)[0]
                end = data.index(b'\0', dynstr['offset'] + name_off)
                return data[dynstr['offset'] + name_off:end].decode()
    raise ValueError(f'no GLOB_DAT at {slot:#x}')


def writes_248(data, lo, hi):
    """Stores to [reg+0x248] / [reg+0x249] (disp32, no SIB) in [lo, hi).

    Matches byte-immediate (c6), byte/word/qword register (88/89) and 16-byte
    (0f 11) stores, with an optional REX/0x66 prefix. Loads are not matched.
    """
    base, code = text(data)
    blob = code[lo - base:hi - base]
    out = []
    for disp in (0x248, 0x249):
        for m in re.finditer(re.escape(struct.pack('<I', disp)), blob):
            p = m.start()
            if p < 2:
                continue
            modrm = blob[p - 1]
            if modrm >> 6 != 2 or modrm & 7 == 4:
                continue
            if blob[p - 2] in (0xc6, 0x88, 0x89):
                start = p - 2
            elif p >= 3 and blob[p - 3:p - 1] == b'\x0f\x11':
                start = p - 3
            else:
                continue
            if start > 0 and (0x40 <= blob[start - 1] <= 0x4f or blob[start - 1] == 0x66):
                start -= 1
            out.append((lo + start, disp))
    return sorted(set(out))


def call_census(data, targets):
    """One pass over .text: direct E8 calls to each target."""
    base, code = text(data)
    out = {t: [] for t in targets}
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code):
            t = base + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if t in out:
                out[t].append(base + i)
    return out


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    rel = relative_relocations(data)
    census = call_census(data, list(POLLERS) + [LOOP[0]])
    for poller, sites in POLLERS.items():
        if sorted(census[poller]) != sorted(sites):
            raise ValueError(f'poller {poller:#x} call census changed')
        if poller in rel.values():
            raise ValueError(f'poller {poller:#x} gained a relocation')
    stores = {}
    for name, (lo, hi) in PARENTS.items():
        found = writes_248(data, lo, hi)
        bytes_ = [(v, d) for v, d in found if d == 0x248 and v in MODE_STORES]
        if sorted(v for v, _ in bytes_) != sorted(v for v in MODE_STORES if lo <= v < hi):
            raise ValueError(f'{name}: mode store census changed')
        if any(d == 0x249 for _, d in found):
            raise ValueError(f'{name}: a store to +0x249 appeared')
        wide = sorted(v for v, d in found if d == 0x248 and v not in MODE_STORES)
        stores[name] = {'mode_byte_stores': {hex(v): MODE_STORES[v] for v, _ in sorted(bytes_)},
                        'other_0x248_stores': [hex(v) for v in wide],
                        'stores_to_0x249': 0}
    zero = read_va(data, ZERO_BLOCK, 16)
    if zero != bytes(16):
        raise ValueError('zero block changed')
    if rel.get(LINE_SLOT) != LINE_FN:
        raise ValueError('line-count slot changed')
    if dynsym_name(data, SLEEP_SLOT) != 'clock_nanosleep':
        raise ValueError('sleep slot changed')
    ptr = rel[LOCATION]
    flen = struct.unpack('<Q', read_va(data, LOCATION + 8, 8))[0]
    line, col = struct.unpack('<II', read_va(data, LOCATION + 16, 8))
    path = read_va(data, ptr, flen).decode()
    if not path.endswith('library/std/src/sys/thread/unix.rs') or (line, col) != (581, 17):
        raise ValueError('loop panic Location changed')
    return {
        'target': RELATIVE, 'sha256': SHA256, 'task': 'RE-008', 'component': 'abci',
        'parents': stores,
        'zero_block_0x457d30': zero.hex(),
        'pollers': {hex(p): {'direct_calls': [hex(s) for s in sorted(sites)], 'relocations': 0,
                             'entry_copy': '+0x28..+0x38 -> +0x38'} for p, sites in POLLERS.items()},
        'line_count_loop': {
            'fn': [hex(v) for v in LOOP],
            'sleep': 'slot %s GLOB_DAT clock_nanosleep, edi=1 (CLOCK_MONOTONIC), r15d=0x3c (60 s)' % hex(SLEEP_SLOT),
            'eintr': 'eax == 4 retries; other non-zero -> panic at %s:%d:%d' % (path.split('/library/')[-1], line, col),
            'lock': '%s lock cmpxchg byte [r12+0x10]; contention -> slot 0x64e01f8 with 1000000000' % hex(0x2c7d9fe),
            'count': 'slot %s -> %s at %s, then jmp %s (sleep again)' % (hex(LINE_SLOT), hex(LINE_FN),
                                                                     hex(0x2c7da78), hex(0x2c7d980)),
            'callers': [hex(v) for v in census[LOOP[0]]],
        },
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(json.dumps({k: v['mode_byte_stores'] for k, v in result['parents'].items()}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
