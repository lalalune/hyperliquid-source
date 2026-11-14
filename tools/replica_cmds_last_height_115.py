#!/usr/bin/env python3
"""Bind how node #115 finds the last applied height in replica_cmds (73rd stage).

Stage 72 (#6067) found that the startup state machine 0x2b41b70 calls slot
0x64e7720 when its input byte +0x1 is 1, and panics with "invalid starting
height ... last_applied_height=" when the starting height is below the
returned value. This tool binds the slot target 0x595b1a0:

1. it formats {root}/data/replica_cmds (template 0x448b77, root cell slot
   0x64e0918, name 0x9383d2) and lists it with 0x1501290 (slot 0x64e0968;
   0x1501290 calls slot 0x64e0970 -> 0x5c9ca30, which calls opendir through
   GOT 0x64ec5f8), Location node/src/startup.rs:364:19;
2. it walks the listing from the back (0x5152d00 decrements the length at
   +0x40 and uses the back handle at +0x20) and takes at most 5 entries (the
   iterator's +0x48 counter, seeded with 5 at 0x595b2b9, decremented at
   0x543db5c);
3. for each entry the mapper 0x595b520 lists it again (startup.rs:376:21),
   takes its last child ("no date_dirs {}"), lists that child with 0x15021d0
   (slot 0x64e09d0; "no non-zipped flns {}"), takes the last name from the
   back, parses it as a decimal u64 (optional '+', digits only, overflow is an
   error), and adds the value 0x1500e50 returns for that file (slot
   0x64e0958, startup.rs:384:19), saturating at u64::MAX;
4. 0x1500e50 treats a name ending in ".lz4" differently and otherwise builds
   the argument pair "wc", "-l";
5. the outer function keeps the maximum over the mapped Ok values; when none
   is Ok it formats "no end heights found {}".

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents
from freeze_snapshot_115 import fixed, read_va, relative_relocations, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-replica-cmds-last-height-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

ENTRY = 0x595b1a0
MAPPER = 0x595b520
NEXT_BACK = 0x5152d00
COUNT_FILE = 0x1500e50

FIXED = {
    0x595b1b0: '488b1d6157b800',        # mov rbx, [root cell slot 0x64e0918]
    0x595b2b9: '48c7842498000000050000' '00',  # mov qword [rsp+0x98], 5 (take limit)
    0x595b3a4: '4d39ce',                # cmp r14, r9
    0x595b3a7: '4d0f46f1',              # cmovbe r14, r9 (keep maximum)
    0x543db5c: '48ff4c2468',            # dec qword [rsp+0x68] (take counter)
    0x5152d0e: '488b4640',              # mov rax, [rsi+0x40] (remaining length)
    0x5152d17: '48ffc8',                # dec rax
    0x5152d1e: '837e2001',              # cmp dword [rsi+0x20], 1 (back handle)
    0x595b5dd: '4883fb08',              # cmp rbx, 8 (descend to last leaf)
    0x595bae7: '83c2d0',                # add edx, -0x30 (ASCII digit)
    0x595baea: '83fa09',                # cmp edx, 9
    0x595bb29: 'bf0a000000',            # mov edi, 10 (decimal base)
    0x595bba9: '4d01fc',                # add r12, r15 (name + count)
    0x595bbac: '49c7c7ffffffff',        # mov r15, -1
    0x595bbb3: '4d0f43fc',              # cmovae r15, r12 (saturating)
    0x1500e71: '817c37fc2e6c7a34',      # cmp dword [rdi+rsi-4], '.lz4'
    0x1500e95: '48c744242802000000',    # mov qword [rsp+0x28], 2 (len "-l")
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x595b1d7, b'\x48\x8d\x05', 7, 0x64b6828),   # &"replica_cmds"
    (0x595b1ef, b'\x48\x8d\x35', 7, 0x448b77),    # {}/data/{}
    (0x595b210, b'\x48\x8d\x0d', 7, 0x64b6838),   # startup.rs:364:19
    (0x595b21f, b'\xff\x15', 6, 0x64e0968),       # list dir
    (0x595b2d2, b'\xe8', 5, 0x5accff0),           # collect mapped results
    (0x595b335, b'\x48\x8d\x3d', 7, 0x439f32),    # "no end heights found {}"
    (0x5acd0dc, b'\xe8', 5, 0x543dab0),           # iterator step
    (0x543db40, b'\xe8', 5, NEXT_BACK),
    (0x543db64, b'\xe8', 5, MAPPER),
    (0x595b547, b'\x48\x8d\x0d', 7, 0x64b6850),   # startup.rs:376:21
    (0x595b553, b'\xff\x15', 6, 0x64e0968),       # list entry
    (0x595b6a5, b'\xff\x15', 6, 0x64e09d0),       # list last child
    (0x595b726, b'\xe8', 5, NEXT_BACK),
    (0x595b78f, b'\x48\x8d\x05', 7, 0x44ea70),    # "no date_dirs {}"
    (0x595b9d5, b'\x48\x8d\x05', 7, 0x439085),    # "no non-zipped flns {}"
    (0x595bb8f, b'\x48\x8d\x15', 7, 0x64b6868),   # startup.rs:384:19
    (0x595bb9c, b'\xff\x15', 6, 0x64e0958),       # per-file count
    (0x1500e89, b'\x48\x8d\x05', 7, 0x4659f2),    # "wc"
    (0x5c9cb83, b'\xff\x15', 6, 0x64ec5f8),       # opendir GOT
)
RELOCS = {
    0x64e7720: ENTRY, 0x64e0968: 0x1501290, 0x64e0970: 0x5c9ca30, 0x64e09d0: 0x15021d0,
    0x64e0958: COUNT_FILE, 0x64b6828: 0x9383d2,
    0x64b6838: 0x438c81, 0x64b6850: 0x438c81, 0x64b6868: 0x438c81,
}
STRINGS = {
    0x9383d2: b'replica_cmds',
    0x438c81: b'node/src/startup.rs',
    0x439f32: b'\x15no end heights found ',
    0x44ea70: b'\rno date_dirs ',
    0x439085: b'\x13no non-zipped flns ',
    0x4659f2: b'wc-l',
    0x448b77: b'\xc0\x06/data/\xc0\x00',
}
LOCATIONS = {0x64b6838: (364, 19), 0x64b6850: (376, 21), 0x64b6868: (384, 19)}
EXTENTS = {ENTRY: 0x595b512, MAPPER: 0x595bc3a, NEXT_BACK: 0x515313a, COUNT_FILE: 0x150128b}


def glob_dat_symbol(data, slot):
    """Name of the dynamic symbol a GLOB_DAT slot points at, or None."""
    secs = sections(data)
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    for sec in secs:
        if sec['type'] != 4:
            continue
        for va, info, _ in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if va == slot and info & 0xffffffff == 6:
                idx = info >> 32
                name_off = struct.unpack_from('<I', data, dynsym['offset'] + idx * 24)[0]
                start = dynstr['offset'] + name_off
                return data[start:data.index(b'\0', start)].decode()
    return None


def call_census(data, targets, slots):
    """One pass over .text: direct E8 calls to targets, FF15 calls through slots."""
    base, code = text(data)
    direct = {t: [] for t in targets}
    via = {s: [] for s in slots}
    for m in re.finditer(rb'\xe8|\xff\x15', code):
        i = m.start()
        if code[i] == 0xe8 and i + 5 <= len(code):
            t = base + i + 5 + struct.unpack_from('<i', code, i + 1)[0]
            if t in direct:
                direct[t].append(base + i)
        elif i + 6 <= len(code):
            t = base + i + 6 + struct.unpack_from('<i', code, i + 2)[0]
            if t in via:
                via[t].append(base + i)
    return direct, via


def location(data, va):
    rel = relative_relocations(data)
    raw = read_va(data, va, 0x18)
    file_va = rel.get(va)
    length = struct.unpack_from('<Q', raw, 8)[0]
    line, col = struct.unpack_from('<II', raw, 16)
    return read_va(data, file_va, length).decode(), line, col


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    if glob_dat_symbol(data, 0x64ec5f8) != 'opendir':
        raise ValueError('opendir GOT slot changed')
    locs = {}
    for va, (line, col) in LOCATIONS.items():
        name, got_line, got_col = location(data, va)
        if (name, got_line, got_col) != ('node/src/startup.rs', line, col):
            raise ValueError(f'Location at {va:#x} changed')
        locs[hex(va)] = f'{name}:{line}:{col}'
    starts = {f['start']: f['end'] for f in fdes}
    for start, end in EXTENTS.items():
        if starts.get(start) != end:
            raise ValueError(f'FDE extent at {start:#x} changed')
    direct, via = call_census(data, [NEXT_BACK, MAPPER, COUNT_FILE], [0x64e7720, 0x64e0958])
    if direct[MAPPER] != [0x543db64] or via[0x64e7720] != [0x2b41d3c] or via[0x64e0958] != [0x1563bf0, 0x595bb9c] \
            or direct[NEXT_BACK] != [0x543db40, 0x595b726]:
        raise ValueError('call census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'entry': {
            'fn': hex(ENTRY), 'slot': '0x64e7720',
            'path': '{root}/data/replica_cmds (template 0x448b77, root slot 0x64e0918, name 0x9383d2)',
            'list': 'slot 0x64e0968 -> 0x1501290 -> slot 0x64e0970 -> 0x5c9ca30 (opendir via GOT 0x64ec5f8)',
            'walk': 'next_back 0x5152d00 (length +0x40, back handle +0x20), take 5 (iterator +0x48, '
                    'seed 0x595b2b9, decrement 0x543db5c)',
            'reduce': 'maximum of Ok values (cmovbe 0x595b3a7); none Ok -> "no end heights found {}" (0x439f32)',
        },
        'mapper': {
            'fn': hex(MAPPER),
            'steps': ['list the entry (startup.rs:376:21)',
                      'last child of the listing, else "no date_dirs {}" (0x44ea70)',
                      'list that child via slot 0x64e09d0 -> 0x15021d0, else "no non-zipped flns {}" (0x439085)',
                      'last name from the back (0x595b726)',
                      'decimal u64 from the name: optional +, digits 0-9, overflow is an error',
                      'add the count from slot 0x64e0958 -> 0x1500e50 (startup.rs:384:19), saturating'],
        },
        'count_file': {
            'fn': hex(COUNT_FILE),
            'lz4_suffix_check': hex(0x1500e71) + " cmp dword [rdi+rsi-4], 0x347a6c2e ('.lz4')",
            'arguments': '0x4659f2 "wc" (len 2), 0x4659f4 "-l" (len 2)',
        },
        'locations': locs,
        'census': {
            'slot_0x64e7720_calls': [hex(v) for v in via[0x64e7720]],
            'mapper_direct_calls': [hex(v) for v in direct[MAPPER]],
            'next_back_direct_calls': [hex(v) for v in direct[NEXT_BACK]],
            'count_file_slot_calls': [hex(v) for v in via[0x64e0958]],
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
    print(f"entry={result['entry']['fn']} mapper={result['mapper']['fn']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
