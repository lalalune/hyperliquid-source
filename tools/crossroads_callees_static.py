#!/usr/bin/env python3
"""Authenticated node94 crossroads small-callee binding (0x14385c0, 0x454e5b0).

Binds the two small callees of the crossroads body (RE-001-crossroads-body-94)
to the node #94 digest: the 107-byte lazy getter 0x14385c0 (a ship-complete
cell whose fast path returns two value words, whose slow path drives the std
Once state machine with force flag 1 and the initializer 0x143ef30, carrying
the std sync/once.rs:219:20 Location; 87 GOT-mediated call sites) and the
100-byte capacity growth helper 0x454e5b0 (double-or-minimum-4 capacity,
element size 8, the observed 0x168 constant, one direct allocator call and
one error path; 8 GOT-mediated call sites). Static byte/record checks only;
the captured binary is never executed.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Lazy getter 0x14385c0.
GET_START, GET_END = 0x14385c0, 0x143862b
GET_FDE_VA = 0xceadd4
CELL_VA = 0x577ab80
CELL_INIT_FN = 0x143ef30
CELL_VALUE_VA = 0x577ab88
CELL_STATE_VA = 0x577ab98
CELL_STATE_SHIPPED = 3
ONCE_COMPANION_VA = 0x5669f68
STD_ONCE_LOC = 0x5669f50
STD_ONCE_PATH = (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/'
                 b'std/src/sync/once.rs')
GOT_ONCE, ONCE_FN = 0x576e8b8, 0x4ee3b20

# Capacity growth helper 0x454e5b0.
GROW_START, GROW_END = 0x454e5b0, 0x454e614
GROW_FDE_VA = 0xedb128
GROW_ALLOC_FN = 0x454f420
GROW_ELEMENT_SIZE = 8
GROW_MIN_CAPACITY = 4
GROW_OBSERVED_CONST = 0x168
GOT_ERR, ERR_FN = 0x576dfb8, 0x1346068

GET_ANCHORS = [
    (0x0, '8b05', 'load cell state'),
    (0xa, '488b05', 'load value word 1'),
    (0x1d, '488d05', 'lea initializer slot'),
    (0x33, '488d3d', 'lea cell state'),
    (0x3a, '488d0d', 'lea once companion'),
    (0x41, '4c8d05', 'lea std once Location'),
    (0x4d, 'be01000000', 'force flag 1'),
    (0x52, 'ff15', 'call the Once state machine'),
]

GROW_ANCHORS = [
    (0xa, '488b37', 'load current capacity'),
    (0xd, '488d0436', 'double the capacity'),
    (0x11, '4883f805', 'minimum threshold compare'),
    (0x15, '41be04000000', 'minimum capacity 4'),
    (0x1b, '4c0f43f0', 'cmovae selection'),
    (0x26, '41b808000000', 'element size 8'),
    (0x2c, '41b968010000', 'observed constant 0x168'),
    (0x35, 'e8360e0000', 'direct allocator call'),
    (0x3a, '833c2401', 'success tag compare'),
    (0x5e, 'ff15', 'error path call'),
]

GET_CALLERS_COUNT = 87
GROW_CALLERS_COUNT = 8

GET_BODY = bytes.fromhex(
'8b05d225340485c0750f488b05b7253404488b15b8253404c34883ec18488d05'
'9c2534044889442408488d4424084889442410488d3d9e253404488d0d671923'
'044c8d0548192304488d542410be01000000ff15a06233044883c418488b0565'
'253404488b1566253404c3')

GET_FDE = bytes.fromhex(
'14000000c0980000e4d774006b000000005d0e207f0e0800')

GROW_BODY = bytes.fromhex(
'4156534883ec184889fb488b37488d04364883f80541be040000004c0f43f048'
'8b57084889e741b80800000041b9680100004c89f1e8360e0000833c24017414'
'488b442408488943084c89334883c4185b415ec3488b7c2408488b742410ff15'
'a4f92101')

GROW_FDE = bytes.fromhex(
'28000000149c1f00803467036400000000420e10410e18440e3083038e020249'
'0e18410e10420e08410e3000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Reader:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.by_name = {s['name']: s for s in self.sections}

    def read(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'Ambiguous or unmapped VA {va:#x}')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + size]


def relocations(reader):
    raw = reader.read(reader.by_name['.rela.dyn']['address'],
                      reader.by_name['.rela.dyn']['size'])
    rels = {}
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if info == 8:
            require(address not in rels, 'Duplicate relative relocation')
            rels[address] = addend
    return rels


def analyze(data):
    reader = Reader(data)
    rels = relocations(reader)
    eh = reader.by_name['.eh_frame']

    # ---- Lazy getter: body, FDE, cell facts. ----
    body = reader.read(GET_START, GET_END - GET_START)
    require(body == GET_BODY, 'Lazy getter body bytes changed')
    require(eh['address'] <= GET_FDE_VA < eh['address'] + eh['size'], 'getter FDE outside .eh_frame')
    fde = reader.read(GET_FDE_VA, len(GET_FDE))
    require(fde == GET_FDE, 'Lazy getter FDE record changed')
    pc = GET_FDE_VA + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require((pc, pc + extent) == (GET_START, GET_END), 'getter FDE PC range changed')
    for offset, hexstr, label in GET_ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, f'Getter anchor changed: {label}')

    # Cell: initializer slot relocation, ship-complete state, zero value.
    require(rels.get(CELL_VA) == CELL_INIT_FN, 'cell initializer relocation changed')
    require(struct.unpack_from('<I', reader.read(CELL_STATE_VA, 4), 0)[0] == CELL_STATE_SHIPPED,
            'cell state no longer ships complete')
    require(reader.read(CELL_VALUE_VA, 16) == bytes(16), 'cell value no longer ships zero')
    # The slow path lea targets.
    disp = struct.unpack_from('<i', body, 0x20)[0]
    require(GET_START + 0x1d + 7 + disp == CELL_VA, 'initializer lea address changed')
    disp = struct.unpack_from('<i', body, 0x36)[0]
    require(GET_START + 0x33 + 7 + disp == CELL_STATE_VA, 'state lea address changed')
    disp = struct.unpack_from('<i', body, 0x3d)[0]
    require(GET_START + 0x3a + 7 + disp == ONCE_COMPANION_VA, 'companion lea address changed')
    disp = struct.unpack_from('<i', body, 0x44)[0]
    require(GET_START + 0x41 + 7 + disp == STD_ONCE_LOC, 'std once Location lea changed')
    # The Location struct and the Once call.
    path_va = rels.get(STD_ONCE_LOC)
    require(path_va is not None, 'std once Location relocation missing')
    str_len, line, column = struct.unpack('<QII', reader.read(STD_ONCE_LOC + 8, 16))
    require((str_len, line, column) == (len(STD_ONCE_PATH), 219, 20),
            'std once Location layout changed')
    require(reader.read(path_va, str_len) == STD_ONCE_PATH, 'std once path changed')
    disp = struct.unpack_from('<i', body, 0x54)[0]
    require(GET_START + 0x52 + 6 + disp == GOT_ONCE, 'Once call GOT changed')
    require(rels.get(GOT_ONCE) == ONCE_FN, 'Once call target changed')

    # ---- Capacity growth helper: body, FDE, anchors. ----
    grow = reader.read(GROW_START, GROW_END - GROW_START)
    require(grow == GROW_BODY, 'Growth helper body bytes changed')
    require(eh['address'] <= GROW_FDE_VA < eh['address'] + eh['size'], 'grow FDE outside .eh_frame')
    gfde = reader.read(GROW_FDE_VA, len(GROW_FDE))
    require(gfde == GROW_FDE, 'Growth helper FDE record changed')
    pc = GROW_FDE_VA + 8 + struct.unpack_from('<i', gfde, 8)[0]
    extent = struct.unpack_from('<I', gfde, 12)[0]
    require((pc, pc + extent) == (GROW_START, GROW_END), 'grow FDE PC range changed')
    for offset, hexstr, label in GROW_ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(grow[offset:offset + len(raw)] == raw, f'Growth anchor changed: {label}')
    # Direct allocator call and error path.
    disp = struct.unpack_from('<i', grow, 0x36)[0]
    require(GROW_START + 0x35 + 5 + disp == GROW_ALLOC_FN, 'allocator call target changed')
    disp = struct.unpack_from('<i', grow, 0x60)[0]
    require(GROW_START + 0x5e + 6 + disp == GOT_ERR, 'error path GOT changed')
    require(rels.get(GOT_ERR) == ERR_FN, 'error path target changed')

    # ---- Census over the whole .text. ----
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])

    def census(fn):
        direct, indirect, lea = [], [], []
        pos = 0
        while (pos := code.find(b'\xff\x15', pos)) >= 0:
            if pos + 6 <= len(code):
                slot = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
                if rels.get(slot) == fn:
                    indirect.append(text['address'] + pos)
            pos += 2
        pos = 0
        while (pos := code.find(b'\xe8', pos)) >= 0:
            if pos + 5 <= len(code):
                destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
                if destination == fn:
                    direct.append(text['address'] + pos)
            pos += 1
        for m in range(len(code) - 7):
            if code[m] == 0x48 and code[m + 1] == 0x8d and (code[m + 2] & 0xC7) == 0x05:
                d = struct.unpack_from('<i', code, m + 3)[0]
                if text['address'] + m + 7 + d == fn:
                    lea.append(text['address'] + m)
        return direct, indirect, lea

    direct, indirect, lea = census(GET_START)
    require(direct == [] and lea == [] and len(indirect) == GET_CALLERS_COUNT,
            f'Getter census changed: {len(indirect)} sites')
    direct, indirect, lea = census(GROW_START)
    require(direct == [] and lea == [] and len(indirect) == GROW_CALLERS_COUNT,
            f'Growth census changed: {len(indirect)} sites')

    # Capacity identity: the decoded selection is max(2 * current, 4).
    for current in (0, 1, 2, 3, 4, 5, 100):
        doubled = current + current
        expected = doubled if doubled >= 5 else 4
        require(expected == max(doubled, GROW_MIN_CAPACITY),
                f'Capacity identity failed for {current}')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        lazy_getter=dict(start_va=hex(GET_START), end_va_exclusive=hex(GET_END),
                         bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                         fde_va=hex(GET_FDE_VA), got_slot='0x576f488',
                         inferred_label='ship-complete lazy getter driving the Once machinery'),
        cell=dict(va=hex(CELL_VA), initializer=hex(CELL_INIT_FN),
                  value_va=hex(CELL_VALUE_VA), state_va=hex(CELL_STATE_VA),
                  shipped_state=CELL_STATE_SHIPPED, shipped_value='two zero qwords',
                  once_companion=hex(ONCE_COMPANION_VA),
                  std_location='std/src/sync/once.rs:219:20 (rustc '
                               'e408947bfd200af42db322daf0fadfe7e26d3bd1)'),
        growth_helper=dict(start_va=hex(GROW_START), end_va_exclusive=hex(GROW_END),
                           bytes=len(grow), sha256=hashlib.sha256(grow).hexdigest(),
                           fde_va=hex(GROW_FDE_VA), got_slot='0x57769d0',
                           allocator=hex(GROW_ALLOC_FN), error_target=hex(ERR_FN),
                           inferred_label='capacity growth: max(2 * current, 4) '
                                          'elements of 8 bytes',
                           observed_constant=hex(GROW_OBSERVED_CONST)),
        identities=dict(capacity_selection='max(2*current, 4) validated on a grid'),
        call_census=dict(getter_sites=GET_CALLERS_COUNT, growth_sites=GROW_CALLERS_COUNT,
                         note='byte-pattern census over the complete .text for '
                              'e8/ff15/lea encodings'),
        cross_links=dict(crossroads_body='0x44aa5a0 calls both (RE-001-crossroads-body-94)',
                         once_state_machine='0x4ee3b20 (RE-001-once-state-94)'),
        captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256,
            'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    parser.add_argument('--output', type=Path, help='Write the record JSON to this path')
    args = parser.parse_args()
    result = inspect(args.binary)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.check is not None:
        expected = args.check.read_text()
        require(text == expected, 'Retained evidence record drifted')
        print('Record matches retained evidence.')
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text)


if __name__ == '__main__':
    main()
