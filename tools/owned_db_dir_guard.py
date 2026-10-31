#!/usr/bin/env python3
"""Pin the OwnedDbDir constructor guard 0x158e870 of node #94.

Every number comes from ELF bytes read with struct: section headers through
tools/elf_index.py, FDE extents through tools/fde_extents.py, and RELATIVE
relocations from .rela.dyn. No external program runs and the binary is never
executed.
"""
import argparse
import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_NAME = 'owned-db-dir-guard.json'
LOCATION_MARK = b'/code_Mainnet/'
R_X86_64_RELATIVE = 8
SHT_NOBITS = 8

CONSTRUCTOR = 0x158e870
PANIC_TEMPLATE = 0x1f8d0b
PANIC_LOCATION = 0x56757d0
SLOT_PANIC = 0x576e098
PANIC_TARGET = 0x157b810
PANIC_BODY_CALL = 0x157b836
SLOT_SINGLETON = 0x576f4e0
SINGLETON_CTOR = 0x1439a40
SINGLETON_TEMPLATE = 0x1f05cd
SINGLETON_TEMPLATE_LEA = 0x1439ab4
SINGLETON_KIND = 0x25f8f4
SLOT_CONSTRUCTOR = 0x5770888
PATH_TEMPLATE = 0x1e938e
TAIL_NEEDLE = 0x25f8eb
FIRST_VECTOR = 0x208fb0
LAST_VECTOR = 0x204ef0
DISPLAY_ARG = 0x158f020
SLOT_PAD = 0x576e000
HELPER = 0x158ef30

# (va, instruction prefix, expected rel32 target, meaning)
RIP_PINS = [
    (0x158e904, '488d05', DISPLAY_ARG, 'panic argument formatter'),
    (0x158e910, '488d3d', PANIC_TEMPLATE, 'panic template'),
    (0x158e917, '488d15', PANIC_LOCATION, 'panic Location'),
    (0x158e923, 'ff15', SLOT_PANIC, 'diverging panic call'),
    (0x158e938, '488d05', TAIL_NEEDLE, 'needle tail for the vector verifier'),
    (0x158e929, 'e9', 0x158edb3, 'return from the panic slot lands on ud2'),
    (DISPLAY_ARG + 14, 'ff25', SLOT_PAD, 'panic argument pads the raw (ptr, len)'),
    (0x158ea16, '488d35', SINGLETON_KIND, 'singleton kind text'),
    (0x158ea30, 'ff15', SLOT_SINGLETON, 'singleton constructor call'),
    (0x158ea10, '0f85', 0x158e8ff, 'vector hit reaches the panic block'),
    (0x158ed9e, 'e9', 0x158e8ff, 'tail hit reaches the panic block'),
    (0x158ed98, '0f84', 0x158ea16, 'tail miss reaches the singleton block'),
    (0x158e8d7, '0f85', 0x158ea16, 'length below 10 skips the search'),
    (0x157b836, 'ff15', 0x57706e0, 'panic body enters the panic runtime'),
    (SINGLETON_TEMPLATE_LEA, '488d35', SINGLETON_TEMPLATE, 'singleton key template'),
]
# (va, exact bytes, meaning)
BYTE_PINS = [
    (0x158e88c, '4983ff0a', 'cmp r15, 10: shortest match length'),
    (0x158e892, '4983ff18', 'cmp r15, 24: last length of the scalar loop'),
    (0x158e89c, '48b8636865636b706f69', 'movabs rax, "checkpoi" in the scalar loop'),
    (0x158e8ba, '4881f76e740000', 'xor rdi, "nt" in the scalar loop'),
    (0x158e8cc, '4883f90b', 'cmp rcx, 11: scalar loop end'),
    (0x158e8dd, '48b8636865636b706f69', 'movabs rax, "checkpoi" for length 10'),
    (0x158e8ef, '4881f16e740000', 'xor rcx, "nt" for length 10'),
    (0x158e944, '48c744244009000000', 'needle tail length 9'),
    (0x158e94d, '4983ff4a', 'cmp r15, 74: block loop gate'),
    (0x158e95c, '498d4519', 'lea rax, [r13+25]: 16-byte loop gate'),
    (0x158e9a3, '498d4529', 'lea rax, [r13+41]: 16-byte loop continue'),
    (0x158e9ac, '4983c510', 'add r13, 16: 16-byte loop step'),
    (0x158e9df, 'f3430f6f443ee7', 'tail window at len-25'),
    (0x158e9e6, 'f3430f6f4c3ef0', 'tail last-byte window at len-16'),
    (0x158ebe8, '4d8d6c2440', 'lea r13, [r12+64]: block step'),
    (0x158ebed, '4981c489000000', 'add r12, 137: block loop continue'),
    (0x158ea25, 'ba0a000000', 'mov edx, 10: singleton kind length'),
    (0x158ea2a, '4c89f1', 'mov rcx, r14: path pointer'),
    (0x158ea2d, '4d89f8', 'mov r8, r15: path length'),
    (0x158eadd, 'bf58000000', 'mov edi, 0x58: allocation size'),
    (0x158edb3, '0f0b', 'ud2 after the panic call'),
    (0x157b83c, 'cc', 'int3 after the panic runtime call'),
]
NEEDLE_LEN = 10
MAX_MODEL_LEN = 512


class View:
    """Read-only VA view over file-backed sections, with .rela.dyn addends."""

    def __init__(self, data):
        self.data = data
        self.sections = elf_index.sections(data)
        self.loaded = [s for s in self.sections
                       if s['type'] != SHT_NOBITS and s['address'] and s['size']]
        self.addends = {}
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        for slot, info, addend in struct.iter_unpack(
                '<QQq', data[rela['offset']:rela['offset'] + rela['size']]):
            if info & 0xffffffff == R_X86_64_RELATIVE:
                self.addends[slot] = addend

    def mem(self, va, size):
        for sec in self.loaded:
            if sec['address'] <= va and va + size <= sec['address'] + sec['size']:
                start = sec['offset'] + va - sec['address']
                return self.data[start:start + size]
        raise ValueError(f'{va:#x}+{size} is outside file-backed sections')

    def text(self):
        sec = next(s for s in self.sections if s['name'] == '.text')
        return sec['address'], self.data[sec['offset']:sec['offset'] + sec['size']]

    def relative(self, slot):
        if slot not in self.addends:
            raise ValueError(f'no RELATIVE relocation at {slot:#x}')
        return self.addends[slot]

    def u64(self, va):
        return struct.unpack('<Q', self.mem(va, 8))[0]


def rip_target(view, va, prefix):
    """Resolve prefix + rel32 at va, failing closed on different bytes."""
    if view.mem(va, len(prefix)) != prefix:
        raise ValueError(f'instruction bytes differ at {va:#x}')
    end = va + len(prefix) + 4
    return end + struct.unpack('<i', view.mem(va + len(prefix), 4))[0]


def check_rip_pin(view, pin):
    va, prefix, expected, meaning = pin
    target = rip_target(view, va, bytes.fromhex(prefix))
    if target != expected:
        raise ValueError(f'{va:#x} targets {target:#x}, not {expected:#x}')
    return {'va': hex(va), 'bytes_prefix': prefix, 'target': hex(target), 'meaning': meaning}


def check_byte_pin(view, pin):
    va, raw, meaning = pin
    if view.mem(va, len(bytes.fromhex(raw))).hex() != raw:
        raise ValueError(f'bytes differ at {va:#x}')
    return {'va': hex(va), 'bytes': raw, 'meaning': meaning}


def decode_template(view, va):
    """Decode a Rust format template holding only literals and default slots."""
    pieces, pos = [], va
    for _ in range(16):
        tag = view.mem(pos, 1)[0]
        pos += 1
        if tag == 0:
            return pieces
        if tag == 0xc0:
            pieces.append(None)
        elif tag < 0x80:
            pieces.append(view.mem(pos, tag).decode('ascii'))
            pos += tag
        else:
            raise ValueError(f'unsupported template tag {tag:#x} at {pos - 1:#x}')
    raise ValueError(f'unterminated template at {va:#x}')


def needle(view):
    """Rebuild the needle from the immediates, and require all three forms to agree."""
    head = view.mem(0x158e89c + 2, 8)
    tail = view.mem(0x158e8ba + 3, 2)
    whole = head + tail
    if view.mem(0x158e8dd + 2, 8) + view.mem(0x158e8ef + 3, 2) != whole:
        raise ValueError('length-10 needle differs')
    first, last = view.mem(FIRST_VECTOR, 16), view.mem(LAST_VECTOR, 16)
    verifier = view.mem(TAIL_NEEDLE, 9)
    if first != whole[:1] * 16 or last != whole[-1:] * 16 or verifier != whole[1:]:
        raise ValueError('vector needle differs')
    return whole.decode('ascii')


def loop_constants(view):
    """Read each search bound from its immediate byte."""
    return {'exact': view.mem(0x158e88c + 3, 1)[0], 'scalar_max': view.mem(0x158e892 + 3, 1)[0],
            'scalar_stop': view.mem(0x158e8cc + 3, 1)[0], 'block_min': view.mem(0x158e94d + 3, 1)[0],
            'window_gate': view.mem(0x158e95c + 3, 1)[0], 'window_more': view.mem(0x158e9a3 + 3, 1)[0],
            'window_step': view.mem(0x158e9ac + 3, 1)[0], 'block_step': view.mem(0x158ebe8 + 4, 1)[0],
            'block_more': struct.unpack('<I', view.mem(0x158ebed + 3, 4))[0],
            'tail_back': 0x100 - view.mem(0x158e9df + 6, 1)[0]}


def covered_starts(length, k):
    """Return the match starts the constructor examines for one path length.

    Early exit on a hit is left out so this is the full miss path.
    """
    if length < k['exact']:
        return set()
    if length == k['exact']:
        return {0}
    if length <= k['scalar_max']:
        return set(range(length + 1 - k['scalar_stop'] + 1))
    seen, start = set(), 0
    if length >= k['block_min']:
        block = 0
        while True:
            seen.update(range(block, block + k['block_step']))
            start = block + k['block_step']
            if block + k['block_more'] >= length:
                break
            block = start
    if start + k['window_gate'] < length:
        while True:
            seen.update(range(start, start + k['window_step']))
            if start + k['window_more'] >= length:
                break
            start += k['window_step']
    tail = length - k['tail_back']
    seen.update(range(tail, tail + k['window_step']))
    return seen


def coverage(k, needle_len=NEEDLE_LEN, max_len=MAX_MODEL_LEN):
    """Compare examined starts with every possible start for each length."""
    gaps = []
    past_end = []
    for length in range(max_len + 1):
        want = set(range(max(0, length - needle_len + 1)))
        seen = covered_starts(length, k)
        gaps.extend((length, s) for s in sorted(want - seen))
        past_end.extend((length, s) for s in sorted(seen - want))
    return {'lengths': max_len + 1, 'missing_starts': len(gaps), 'first_missing': gaps[:3],
            'starts_past_end': len(past_end), 'first_past_end': past_end[:3]}


def location(view, slot):
    path = view.mem(view.relative(slot), view.u64(slot + 8))
    line, col = struct.unpack('<II', view.mem(slot + 16, 8))
    if LOCATION_MARK not in path:
        raise ValueError(f'unexpected Location path at {slot:#x}')
    return {'slot': hex(slot), 'file': path.split(LOCATION_MARK, 1)[1].decode('ascii'),
            'line': line, 'col': col}


def slot_calls(view, slot):
    """Find every ff 15 call whose rip-relative operand is slot."""
    base, text = view.text()
    found = []
    for match in re.finditer(rb'\xff\x15', text):
        index = match.start()
        if index + 6 > len(text):
            break
        if base + index + 6 + struct.unpack_from('<i', text, index + 2)[0] == slot:
            found.append(base + index)
    return found


def direct_calls(view, target):
    base, text = view.text()
    found = []
    for match in re.finditer(rb'[\xe8\xe9]', text):
        index = match.start()
        if index + 5 > len(text):
            break
        if base + index + 5 + struct.unpack_from('<i', text, index + 1)[0] == target:
            found.append(base + index)
    return found


def caller_row(view, site, row):
    """Find the nearest path template load before a constructor call."""
    window = view.mem(site - 0x28, 0x28)
    for index in range(len(window) - 7, -1, -1):
        if window[index:index + 3] in (b'\x48\x8d\x35',):
            target = site - 0x28 + index + 7 + struct.unpack_from('<i', window, index + 3)[0]
            if target == PATH_TEMPLATE:
                body = view.mem(row['start'], row['end'] - row['start'])
                return {'site': hex(site), 'fde_start': hex(row['start']), 'fde_end': hex(row['end']),
                        'path_template_lea': hex(site - 0x28 + index),
                        'compares_bundle_with_3': b'\x40\x80\xfd\x03' in body}
    raise ValueError(f'no path template before {site:#x}')


def fde_for(starts, ordered, va):
    index = bisect.bisect_right(starts, va) - 1
    row = ordered[index]
    if not row['start'] <= va < row['end']:
        raise ValueError(f'{va:#x} is outside every FDE')
    return row


def build(data):
    view = View(data)
    _, ordered, _ = fde_extents.fde_extents(data)
    starts = [row['start'] for row in ordered]
    if view.relative(SLOT_PANIC) != PANIC_TARGET or view.relative(SLOT_SINGLETON) != SINGLETON_CTOR:
        raise ValueError('slot targets differ')
    if view.relative(SLOT_CONSTRUCTOR) != CONSTRUCTOR:
        raise ValueError('constructor slot differs')
    if view.mem(DISPLAY_ARG, 14).hex() != '4889f0488b7708488b5710' + '4889c7':
        raise ValueError('panic argument formatter differs')
    rip_pins = [check_rip_pin(view, pin) for pin in RIP_PINS]
    byte_pins = [check_byte_pin(view, pin) for pin in BYTE_PINS]
    k = loop_constants(view)
    ctor_row = fde_for(starts, ordered, CONSTRUCTOR)
    return {
        'schema': 'owned-db-dir-guard/v1',
        'binary_sha256': hashlib.sha256(data).hexdigest(),
        'coordinate_system': 'ELF virtual addresses; FDE end exclusive',
        'constructor': {'start': hex(ctor_row['start']), 'end': hex(ctor_row['end']),
                        'slot': hex(SLOT_CONSTRUCTOR), 'direct_rel32_calls': len(direct_calls(view, CONSTRUCTOR))},
        'needle': needle(view),
        'loop_constants': k,
        'search_coverage': coverage(k),
        'panic': {'template_va': hex(PANIC_TEMPLATE), 'pieces': decode_template(view, PANIC_TEMPLATE),
                  'location': location(view, PANIC_LOCATION), 'slot': hex(SLOT_PANIC),
                  'slot_target': hex(PANIC_TARGET)},
        'singleton': {'slot': hex(SLOT_SINGLETON), 'slot_target': hex(SINGLETON_CTOR),
                      'kind': view.mem(SINGLETON_KIND, 10).decode('ascii'),
                      'key_pieces': decode_template(view, SINGLETON_TEMPLATE),
                      'allocation_bytes': 0x58},
        'callers': [caller_row(view, site, fde_for(starts, ordered, site))
                    for site in slot_calls(view, SLOT_CONSTRUCTOR)],
        'path_template': {'va': hex(PATH_TEMPLATE), 'pieces': decode_template(view, PATH_TEMPLATE)},
        'rip_pins': rip_pins,
        'byte_pins': byte_pins,
    }


def write_outputs(report, out):
    out.mkdir(parents=True, exist_ok=True)
    (out / JSON_NAME).write_text(json.dumps(report, indent=1, sort_keys=True) + '\n', encoding='utf-8')


def load_binary(path=BINARY, expected=SHA256):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('binary sha256 mismatch')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = build(load_binary())
    write_outputs(report, args.out)
    print(json.dumps(report['search_coverage'], sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
