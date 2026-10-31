#!/usr/bin/env python3
"""Pin the per-bundle CHECKPOINT_COMPLETE_<BUNDLE> marker path of node #94.

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
JSON_NAME = 'checkpoint-bundle-markers.json'
TSV_NAME = 'marker-sites.tsv'
LOCATION_MARK = b'/code_Mainnet/'
R_X86_64_RELATIVE = 8
SHT_NOBITS = 8

MARKER_BUILDER = 0x15867a0
BUNDLE_SAVE = 0x1589870
CHECKPOINT_CREATE = 0x158da60
TEMPLATE_BUNDLE = 0x1f2f3e
TEMPLATE_PLAIN = 0x1fd4ee
NAME_POINTERS = 0x5675538
NAME_LENGTHS = 0x25f7b8
MAX_NAME_LEN = 64

SLOT_PAD = 0x576e000
SLOT_UPPERCASE = 0x576e078
SLOT_FORMAT = 0x576e040
SLOT_IS_FILE = 0x576e9e8
SLOT_TOUCH = 0x576f668
SLOT_WRITE = 0x576f670

UPPERCASE = 0x1345580
UPPERCASE_SCALAR_VA = 0x134568a
UPPERCASE_SCALAR = bytes.fromhex('448d479f4180f81a410f92c041c0e0054130f8')
UPPERCASE_VECTORS = {0x2041b0: 0x9f, 0x204eb0: 0x19, 0x2092e0: 0x20}

TOUCH = 0x144fd70
TOUCH_LOCATION = 0x566a9f8
IS_FILE = 0x144a710
LOCATION_DIR_UNWRAP = 0x5675580
LOCATION_CHECKPOINT_UNWRAP = 0x56755b0

# (va, instruction prefix, kind of rel32 target or None, expected target)
RIP_PINS = [
    (0x15867f9, '488d0d', NAME_POINTERS, 'name pointer table'),
    (0x1586804, '488d0d', NAME_LENGTHS, 'name length table'),
    (0x1586814, 'ff15', SLOT_PAD, 'pad bundle name into a String'),
    (0x158683c, 'ff15', SLOT_UPPERCASE, 'uppercase the bundle String'),
    (0x158684c, '488d05', 0x158dc20, 'argument 1 prints the (ptr, len) directory'),
    (0x158685d, '488d05', 0x1586ec0, 'argument 2 prints the uppercased String'),
    (0x1586869, '488d35', TEMPLATE_BUNDLE, 'marker template'),
    (0x1586878, 'ff15', SLOT_FORMAT, 'format the marker path'),
    (0x144fd89, 'ff15', SLOT_IS_FILE, 'touch returns early on a regular file'),
    (0x144fe57, 'ff15', SLOT_WRITE, 'touch write call'),
    (0x1589aa8, '4c8d05', LOCATION_DIR_UNWRAP, 'directory create unwrap Location'),
    (0x1589ad4, '4c8d05', LOCATION_CHECKPOINT_UNWRAP, 'checkpoint create unwrap Location'),
    (0x15899c3, 'e8', CHECKPOINT_CREATE, 'bundle save creates the checkpoint'),
    (0x1589a38, 'e8', MARKER_BUILDER, 'bundle save builds the marker path'),
    (0x1589a51, 'ff15', SLOT_TOUCH, 'bundle save touches the marker'),
    (0x1589e19, 'e8', BUNDLE_SAVE, 'direct bundle save caller 1'),
    (0x326af78, 'e8', BUNDLE_SAVE, 'direct bundle save caller 2'),
]
# (va, exact bytes, meaning)
BYTE_PINS = [
    (0x15867f2, '400fb6c6', 'movzx eax, sil: bundle index has no bound check'),
    (0x15867f6, 'c1e003', 'shl eax, 3: index scales to 8-byte rows'),
    (0x144fd8f, '84c07407', 'test al, al; je over the early return'),
    (0x144fd93, '31c0', 'xor eax, eax: existing file returns None'),
    (0x144fe47, 'bf01000000', 'mov edi, 1: dangling empty slice pointer'),
    (0x144fe4c, '31f6', 'xor esi, esi: empty slice length'),
    (0x144a769, 'b800f00000', 'mov eax, 0xf000: st_mode format mask'),
    (0x144a772, '3d00800000', 'cmp eax, 0x8000: S_IFREG'),
    (0x1589e14, 'b902000000', 'mov ecx, 2 before direct caller 1'),
    (0x326af73, 'b902000000', 'mov ecx, 2 before direct caller 2'),
]
TEST_THEN_JE = [bytes.fromhex(x) for x in ('84c074', '4584f674', '4084ed74')]


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


def bundle_names(view):
    """Read the parallel pointer and length tables up to the first non-name row."""
    rows = []
    for index in range(16):
        length = view.u64(NAME_LENGTHS + index * 8)
        slot = NAME_POINTERS + index * 8
        if not 0 < length <= MAX_NAME_LEN or slot not in view.addends:
            return rows, {'row': index, 'length_word': hex(length)}
        text = view.mem(view.addends[slot], length)
        if not (text.isascii() and text.isalpha()):
            return rows, {'row': index, 'length_word': hex(length)}
        rows.append({'index': index, 'name_va': hex(view.addends[slot]),
                     'length': length, 'name': text.decode('ascii')})
    raise ValueError('name table has no end')


def ascii_uppercase(text):
    """The scalar rule pinned at UPPERCASE_SCALAR_VA for bytes below 0x80."""
    return bytes(c ^ 0x20 if (c - 0x61) & 0xff < 0x1a else c for c in text.encode('ascii')).decode('ascii')


def uppercase_rule(view):
    if view.relative(SLOT_UPPERCASE) != UPPERCASE:
        raise ValueError('uppercase slot moved')
    if view.mem(UPPERCASE_SCALAR_VA, len(UPPERCASE_SCALAR)) != UPPERCASE_SCALAR:
        raise ValueError('uppercase scalar rule differs')
    for va, byte in UPPERCASE_VECTORS.items():
        if view.mem(va, 16) != bytes([byte]) * 16:
            raise ValueError(f'uppercase vector differs at {va:#x}')
    return {'slot': hex(SLOT_UPPERCASE), 'callee': hex(UPPERCASE),
            'scalar_va': hex(UPPERCASE_SCALAR_VA), 'scalar_bytes': UPPERCASE_SCALAR.hex(),
            'rule': 'byte in 0x61..=0x7a is xored with 0x20',
            'vectors': {hex(k): hex(v) for k, v in UPPERCASE_VECTORS.items()}}


def location(view, slot):
    path = view.mem(view.relative(slot), view.u64(slot + 8))
    line, col = struct.unpack('<II', view.mem(slot + 16, 8))
    if LOCATION_MARK not in path:
        raise ValueError(f'unexpected Location path at {slot:#x}')
    return {'slot': hex(slot), 'file': path.split(LOCATION_MARK, 1)[1].decode('ascii'),
            'line': line, 'col': col}


def scan_calls(view, target):
    base, text = view.text()
    sites = []
    for match in re.finditer(b'\xe8', text):
        index = match.start()
        if index + 5 > len(text):
            break
        if base + index + 5 + struct.unpack_from('<i', text, index + 1)[0] == target:
            sites.append(base + index)
    return sites


def scan_rip_operands(view, targets):
    """Find every 48/4c 8d rip-relative load whose target is in targets."""
    base, text = view.text()
    found = {target: [] for target in targets}
    for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        index = match.start()
        if index + 7 > len(text):
            break
        target = base + index + 7 + struct.unpack_from('<i', text, index + 3)[0]
        if target in found:
            found[target].append(base + index)
    return found


def classify_argument(view, site):
    """Name the esi source in the 24 bytes before a marker builder call."""
    before = view.mem(site - 24, 24)
    if b'\xbe\x02\x00\x00\x00' in before:
        return 'immediate_2'
    if re.search(rb'\x0f\xb6\x74\x24.', before, re.S):
        return 'stack_byte'
    raise ValueError(f'unclassified bundle argument at {site:#x}')


def classify_use(view, site):
    """Name the first probe or touch slot call in the 48 bytes after a site."""
    after_va = site + 5
    after = view.mem(after_va, 48)
    for index in range(len(after) - 5):
        if after[index:index + 2] == b'\xff\x15':
            rel = struct.unpack_from('<i', after, index + 2)[0]
            slot = after_va + index + 6 + rel
            if slot == SLOT_IS_FILE:
                return 'probe'
            if slot == SLOT_TOUCH:
                return 'touch'
    raise ValueError(f'unclassified use at {site:#x}')


def reader_join(view, plain_site, marker_site):
    """Show both is_file hits fall into one address and the miss goes elsewhere."""
    window = view.mem(plain_site, marker_site - plain_site)
    for index in range(len(window) - 6):
        if window[index:index + 2] == b'\xff\x15':
            rel = struct.unpack_from('<i', window, index + 2)[0]
            if plain_site + index + 6 + rel == SLOT_IS_FILE:
                break
    else:
        raise ValueError(f'no plain probe after {plain_site:#x}')
    check_va = plain_site + index + 6
    if view.mem(check_va, 3) != b'\x84\xc0\x74':
        raise ValueError(f'no plain probe branch at {check_va:#x}')
    miss = check_va + 4 + view.mem(check_va + 3, 1)[0]
    if view.mem(miss - 2, 1) != b'\xeb':
        raise ValueError(f'no hit jump before {miss:#x}')
    hit_join = miss + struct.unpack('<b', view.mem(miss - 1, 1))[0]
    after = view.mem(marker_site + 5, 0x40)
    for index in range(len(after) - 4):
        for pattern in TEST_THEN_JE[1:]:
            if after[index:index + len(pattern)] == pattern:
                fall = marker_site + 5 + index + len(pattern) + 1
                if fall != hit_join:
                    raise ValueError(f'marker hit {fall:#x} differs from plain hit {hit_join:#x}')
                return {'plain_lea': hex(plain_site), 'plain_branch': hex(check_va),
                        'marker_call': hex(marker_site), 'both_hits_join': hex(hit_join),
                        'marker_miss': hex(fall + after[index + len(pattern)])}
    raise ValueError(f'no marker branch after {marker_site:#x}')


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

    bundle_tpl = decode_template(view, TEMPLATE_BUNDLE)
    plain_tpl = decode_template(view, TEMPLATE_PLAIN)
    if bundle_tpl != [None, '/CHECKPOINT_COMPLETE_', None] or plain_tpl != [None, '/CHECKPOINT_COMPLETE']:
        raise ValueError('marker templates differ')
    names, end_row = bundle_names(view)
    rule = uppercase_rule(view)
    for row in names:
        row['marker_file'] = 'CHECKPOINT_COMPLETE_' + ascii_uppercase(row['name'])

    sites = []
    for site in scan_calls(view, MARKER_BUILDER):
        row = fde_for(starts, ordered, site)
        sites.append({'site': hex(site), 'fde_start': hex(row['start']), 'fde_end': hex(row['end']),
                      'bundle_argument': classify_argument(view, site),
                      'use': classify_use(view, site)})
    leas = scan_rip_operands(view, {TEMPLATE_BUNDLE, TEMPLATE_PLAIN})
    plain_sites = sorted(leas[TEMPLATE_PLAIN])
    readers = []
    for plain in plain_sites:
        row = fde_for(starts, ordered, plain)
        probes = [int(s['site'], 16) for s in sites
                  if s['fde_start'] == hex(row['start']) and int(s['site'], 16) > plain]
        if len(probes) != 1:
            raise ValueError(f'plain template at {plain:#x} has {len(probes)} marker calls')
        readers.append(reader_join(view, plain, probes[0]))

    def count(key, value):
        return sum(1 for s in sites if s[key] == value)

    builder_row = fde_for(starts, ordered, MARKER_BUILDER)
    touch_row = fde_for(starts, ordered, TOUCH)
    save_row = fde_for(starts, ordered, BUNDLE_SAVE)
    return {
        'schema': 'checkpoint-bundle-markers/v1',
        'binary_sha256': hashlib.sha256(data).hexdigest(),
        'coordinate_system': 'ELF virtual addresses; FDE end exclusive',
        'file_backed_literal_counts': {
            'CHECKPOINT_COMPLETE_EVMSTATE': data.count(b'CHECKPOINT_COMPLETE_EVMSTATE'),
            'CHECKPOINT_COMPLETE_EvmState': data.count(b'CHECKPOINT_COMPLETE_EvmState'),
            '/CHECKPOINT_COMPLETE': data.count(b'/CHECKPOINT_COMPLETE'),
        },
        'templates': {
            'bundle': {'va': hex(TEMPLATE_BUNDLE), 'pieces': bundle_tpl,
                       'lea_sites': [hex(x) for x in sorted(leas[TEMPLATE_BUNDLE])]},
            'plain': {'va': hex(TEMPLATE_PLAIN), 'pieces': plain_tpl,
                      'lea_sites': [hex(x) for x in plain_sites]},
        },
        'bundle_names': names,
        'name_table_end': end_row,
        'uppercase': rule,
        'marker_builder': {'start': hex(builder_row['start']), 'end': hex(builder_row['end'])},
        'touch': {'start': hex(touch_row['start']), 'end': hex(touch_row['end']),
                  'slot': hex(SLOT_TOUCH), 'slot_target': hex(view.relative(SLOT_TOUCH)),
                  'location': location(view, TOUCH_LOCATION),
                  'is_file_slot_target': hex(view.relative(SLOT_IS_FILE))},
        'bundle_save': {'start': hex(save_row['start']), 'end': hex(save_row['end']),
                        'unwrap_locations': [location(view, LOCATION_DIR_UNWRAP),
                                             location(view, LOCATION_CHECKPOINT_UNWRAP)],
                        'direct_callers': [hex(x) for x in scan_calls(view, BUNDLE_SAVE)],
                        'order': 'checkpoint create 0x15899c3, then marker path 0x1589a38, then touch 0x1589a51'},
        'rip_pins': [check_rip_pin(view, pin) for pin in RIP_PINS],
        'byte_pins': [check_byte_pin(view, pin) for pin in BYTE_PINS],
        'site_counts': {'total': len(sites), 'touch': count('use', 'touch'), 'probe': count('use', 'probe'),
                        'immediate_2': count('bundle_argument', 'immediate_2'),
                        'stack_byte': count('bundle_argument', 'stack_byte')},
        'sites': sites,
        'plain_or_evmstate_readers': readers,
    }


def write_outputs(report, out):
    out.mkdir(parents=True, exist_ok=True)
    (out / JSON_NAME).write_text(json.dumps(report, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    lines = ['site\tfde_start\tfde_end\tbundle_argument\tuse']
    lines += ['\t'.join(s[k] for k in ('site', 'fde_start', 'fde_end', 'bundle_argument', 'use'))
              for s in report['sites']]
    (out / TSV_NAME).write_text('\n'.join(lines) + '\n', encoding='utf-8')


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
    print(json.dumps(report['site_counts'], sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
