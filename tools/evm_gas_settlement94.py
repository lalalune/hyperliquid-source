#!/usr/bin/env python3
"""Extract fixed post-execution arithmetic evidence from the pinned node image."""
import argparse
import csv
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_index
import fde_extents

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are linked virtual addresses, never runtime addresses. Each fingerprint
# covers an entire independently parsed FDE range, including cold failure tails.
FUNCTIONS = (
    ('gross_adapter', 0x244f4b0, 0x244f4c4, '491c64dcc367cd798e93f3748af7b938a518b9d5d1822bf6b3c41c36347389f1'),
    ('net_adapter', 0x244f4f0, 0x244f504, 'f3fa0315fdd05b27c75ae4ef707fe29caef028fdb57c932103d168cf913c480e'),
    ('gross', 0x2468870, 0x2468aae, '67f20773bd2faa97051912a2bde2d81507919b836e4526590a6b086dbc8361f6'),
    ('net', 0x2468fa0, 0x2469249, '37d99c491255582de2c96397816b3c74d595b64362b2771e8bab3bbe575cb9ae'),
)

# Curated windows are deliberately bounded at manually inspected instruction
# boundaries. They are not a general x86 decoder or a function census.
WINDOWS = (
    ('gross_price_select', 0x24688a1, 0x2468978),
    ('gross_lookup_and_flag', 0x2468978, 0x24689a5),
    ('gross_quantity_subtract', 0x24689a5, 0x24689bc),
    ('gross_multiply', 0x24689bc, 0x24689e7),
    ('gross_add_and_store', 0x24689e7, 0x2468a52),
    ('gross_lookup_error', 0x2468a52, 0x2468a85),
    ('gross_underflow_tails', 0x2468a94, 0x2468aae),
    ('net_price_select_and_floor', 0x2468fd1, 0x246910b),
    ('net_lookup_and_flag', 0x246910b, 0x246913b),
    ('net_quantity_subtract', 0x246913b, 0x2469152),
    ('net_multiply', 0x2469152, 0x246917d),
    ('net_add_and_store', 0x246917d, 0x24691e9),
    ('net_lookup_error', 0x24691e9, 0x2469220),
    ('net_underflow_tails', 0x246922f, 0x2469249),
)

# Instruction-shaped anchors were read from the pinned bytes, not generated
# by a disassembler. The complete enclosing bodies are also fingerprinted.
ANCHORS = (
    ('gross_mode_test', 0x24688a1, '83bf7801000001'),
    ('net_mode_test', 0x2468fd1, '83bd7801000001'),
    ('gross_cap_low_load', 0x24688ae, '488baf40020000'),
    ('gross_unsigned_choose', 0x246894a, '480f42e9'),
    ('net_subtract_base', 0x24690e8, '4d29c54919fc4819d34883dd00'),
    ('net_floor_to_zero', 0x2469101, '31ed31db4531e44531ed'),
    ('gross_touch', 0x246899d, '41808ab000000004'),
    ('net_touch', 0x2469133, '41808ab000000004'),
    ('gross_first_subtract', 0x24689a8, '492b7e08'),
    ('gross_second_subtract', 0x24689b2, '492b7e10'),
    ('net_first_subtract', 0x246913e, '492b7f08'),
    ('net_second_subtract', 0x2469148, '492b7f10'),
    ('gross_first_multiply', 0x24689bf, '48f7e5'),
    ('gross_second_multiply', 0x24689cb, '49f7e5'),
    ('gross_third_multiply', 0x24689d7, '49f7e4'),
    ('gross_high_multiply', 0x24689da, '4c0fafff'),
    ('gross_product_carry_chain', 0x24689de, '4c01c64c11c84911d7'),
    ('net_first_multiply', 0x2469155, '49f7e5'),
    ('net_second_multiply', 0x2469161, '49f7e4'),
    ('net_third_multiply', 0x246916d, '48f7e3'),
    ('net_high_multiply', 0x2469170, '480fafef'),
    ('net_product_carry_chain', 0x2469174, '4c01c64c11c84811d5'),
    ('gross_saturation_first_limb', 0x2468a21, '48c7c1ffffffff'),
    ('net_saturation_first_limb', 0x24691b7, '48c7c1ffffffff'),
    ('gross_first_balance_store', 0x2468a3d, '49894a40'),
    ('net_first_balance_store', 0x24691d3, '49894a40'),
)

# Branch destinations are decoded from signed immediates, not objdump text.
# The expected opcode and destination are independently checked.
BRANCHES = (
    ('gross_mode_ne_1', 0x24688a8, '0f85', 0x246895c),
    ('gross_equal_price', 0x2468945, '74', 0x2468978),
    ('gross_lookup_not_5', 0x2468992, '0f85', 0x2468a52),
    ('gross_first_borrow', 0x24689ac, '0f82', 0x2468a94),
    ('gross_second_borrow', 0x24689b6, '0f82', 0x2468aa1),
    ('gross_balance_carry', 0x2468a1a, '72', 0x2468a21),
    ('gross_balance_no_carry', 0x2468a1f, '74', 0x2468a3d),
    ('net_mode_ne_1', 0x2468fd8, '0f85', 0x24690aa),
    ('net_equal_price', 0x246908a, '74', 0x246909f),
    ('net_base_exceeds_price', 0x24690fb, '72', 0x2469101),
    ('net_no_borrow', 0x24690ff, '74', 0x246910b),
    ('net_lookup_not_5', 0x2469128, '0f85', 0x24691e9),
    ('net_first_borrow', 0x2469142, '0f82', 0x246922f),
    ('net_second_borrow', 0x246914c, '0f82', 0x246923c),
    ('net_balance_carry', 0x24691b0, '72', 0x24691b7),
    ('net_balance_no_carry', 0x24691b5, '74', 0x24691d3),
)
CALLS = (
    ('gross_adapter', 0x244f4ba, 0x2468870),
    ('net_adapter', 0x244f4fa, 0x2468fa0),
    ('gross_lookup', 0x2468987, 0x2460ad0),
    ('net_lookup', 0x246911c, 0x24604b0),
)
INDIRECT_CALLS = (
    ('gross_first_underflow', 0x2468a9b, 0x576e150),
    ('gross_second_underflow', 0x2468aa8, 0x576e150),
    ('net_first_underflow', 0x2469236, 0x576e150),
    ('net_second_underflow', 0x2469243, 0x576e150),
)
LOCATIONS = (
    ('gross_first_underflow', 0x2468a94, 0x56b6fa0, 'revm-interpreter-15.0.0/src/gas.rs', 66, 9),
    ('gross_second_underflow', 0x2468aa1, 0x56b6fb8, 'revm-19.2.0/src/handler/mainnet/post_execution.rs', 54, 57),
    ('net_first_underflow', 0x246922f, 0x56b6fa0, 'revm-interpreter-15.0.0/src/gas.rs', 66, 9),
    ('net_second_underflow', 0x246923c, 0x56b6fb8, 'revm-19.2.0/src/handler/mainnet/post_execution.rs', 54, 57),
)


def verify_digest(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET:
        raise ValueError('Target SHA-256 mismatch')
    return digest


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = elf_index.sections(data)
        self.file_sections = [s for s in self.sections if s['type'] != 8 and s['size']]

    def offset(self, va, size):
        if size <= 0:
            raise ValueError('Empty or negative address range')
        hits = [s for s in self.file_sections if s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise ValueError('Address does not have one file-backed section mapping')
        section = hits[0]
        off = section['offset'] + va - section['address']
        if off < 0 or off + size > len(self.data):
            raise ValueError('Range outside file')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]


def match_anchor(image, va, expected_hex):
    raw = image.read(va, len(bytes.fromhex(expected_hex)))
    if raw.hex() != expected_hex:
        raise ValueError('Instruction anchor mismatch')
    return raw


def decoded_rel(image, va, opcode):
    prefix = bytes.fromhex(opcode)
    if prefix in (b'\x74', b'\x75', b'\x72'):
        size, fmt = 2, '<b'
    elif prefix in (b'\x0f\x85', b'\x0f\x82', b'\xe8'):
        size, fmt = len(prefix) + 4, '<i'
    else:
        raise ValueError('Unsupported relative instruction')
    raw = image.read(va, size)
    if not raw.startswith(prefix):
        raise ValueError('Relative instruction opcode mismatch')
    return va + size + struct.unpack_from(fmt, raw, len(prefix))[0], raw


def indirect_slot(image, va):
    raw = image.read(va, 6)
    if raw[:2] != b'\xff\x15':
        raise ValueError('Unexpected indirect call encoding')
    return va + 6 + struct.unpack_from('<i', raw, 2)[0], raw


def relative_relocations(image):
    hits = [s for s in image.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(hits) != 1 or hits[0]['size'] % 24:
        raise ValueError('Unsupported dynamic relocation section')
    section = hits[0]
    rows = {}
    for pos in range(section['offset'], section['offset'] + section['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', image.data, pos)
        if info == 8:
            if where in rows:
                raise ValueError('Duplicate relative relocation')
            rows[where] = addend
    return rows


def source_record(image, relocations, va, expected_suffix):
    if va not in relocations:
        raise ValueError('Location pointer lacks relative relocation')
    pointer = relocations[va]
    length, line, column = struct.unpack('<QII', image.read(va + 8, 16))
    if not 1 <= length <= 256:
        raise ValueError('Invalid source path length')
    raw = image.read(pointer, length)
    suffix = expected_suffix.encode('ascii')
    if not raw.endswith(b'/' + suffix):
        raise ValueError('Source path suffix mismatch')
    return pointer, length, line, column


def lea_target(image, va):
    raw = image.read(va, 7)
    if raw[:3] != b'\x48\x8d\x3d':
        raise ValueError('Unexpected location LEA')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0], raw


def rows_from_image(data):
    """Return curated raw records; fail closed on a changed input or mapping."""
    verify_digest(data)
    image = Image(data)
    _, index = elf_index.unwind_index(data)
    indexed = {row['start']: row for row in index}
    _, fdes = fde_extents.eh_frame_records(data, image.sections)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    functions, unwind = [], []
    for label, start, end, expected_hash in FUNCTIONS:
        matches = by_start.get(start, [])
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError('Missing, ambiguous or changed FDE')
        fde = matches[0]
        if start not in indexed or indexed[start]['fde'] != fde['fde']:
            raise ValueError('Unwind index does not reference the selected FDE')
        record_length = struct.unpack('<I', image.read(fde['fde'], 4))[0]
        if record_length in (0, 0xffffffff):
            raise ValueError('Unsupported selected FDE size')
        fde_raw = image.read(fde['fde'], 4 + record_length)
        unwind.append((label, indexed[start]['index'], hex(fde['fde']), hex(fde['cie']),
                       hex(image.offset(fde['fde'], len(fde_raw))), len(fde_raw), fde_raw.hex()))
        raw = image.read(start, end - start)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected_hash:
            raise ValueError('Function fingerprint mismatch')
        functions.append((label, hex(start), hex(end), hex(fde['fde']), hex(image.offset(start, len(raw))), len(raw), digest, raw.hex()))
    windows = []
    for name, start, end in WINDOWS:
        owners = [f for f in FUNCTIONS if f[1] <= start < end <= f[2]]
        if len(owners) != 1:
            raise ValueError('Window outside its function')
        raw = image.read(start, end - start)
        windows.append((name, owners[0][0], hex(start), hex(end), hex(image.offset(start, len(raw))), len(raw), hashlib.sha256(raw).hexdigest(), raw.hex()))
    anchors = []
    for name, va, expected_hex in ANCHORS:
        raw = match_anchor(image, va, expected_hex)
        anchors.append((name, hex(va), hex(image.offset(va, len(raw))), raw.hex()))
    branches = []
    for name, va, opcode, expected in BRANCHES:
        actual, raw = decoded_rel(image, va, opcode)
        if actual != expected:
            raise ValueError('Conditional destination mismatch')
        branches.append((name, hex(va), raw.hex(), hex(actual)))
    calls = []
    for name, va, expected in CALLS:
        actual, raw = decoded_rel(image, va, 'e8')
        if actual != expected:
            raise ValueError('Direct call destination mismatch')
        calls.append((name, hex(va), raw.hex(), hex(actual)))
    relocations = relative_relocations(image)
    indirect = []
    for name, va, expected_slot in INDIRECT_CALLS:
        slot, raw = indirect_slot(image, va)
        if slot != expected_slot or slot not in relocations:
            raise ValueError('Indirect call slot or relocation mismatch')
        indirect.append((name, hex(va), raw.hex(), hex(slot), hex(relocations[slot])))
    adapter_names = {start: name for name, start, _, _ in FUNCTIONS[:2]}
    slots = [(hex(slot), name, hex(target)) for slot, target in sorted(relocations.items())
             if (name := adapter_names.get(target)) is not None]
    counts = {name: sum(row[1] == name for row in slots) for name in adapter_names.values()}
    if counts != {'gross_adapter': 8, 'net_adapter': 7}:
        raise ValueError('Unexpected adapter relocation census')
    descriptors = []
    for slot_hex, name, target_hex in slots:
        slot = int(slot_hex, 16)
        start = slot - 0x28
        raw = image.read(start, 0x30)
        if struct.unpack_from('<QQQ', raw) != (0, 0, 1):
            raise ValueError('Unexpected callback descriptor prefix')
        if any(pos not in relocations for pos in (start + 0x18, start + 0x20, slot)):
            raise ValueError('Missing callback descriptor method relocation')
        descriptors.append((hex(start), hex(image.offset(start, len(raw))), raw.hex(),
                            hex(slot), name, target_hex))
    locations = []
    for name, lea, record, suffix, expected_line, expected_column in LOCATIONS:
        actual, raw = lea_target(image, lea)
        if actual != record:
            raise ValueError('Location record address mismatch')
        pointer, length, line, column = source_record(image, relocations, record, suffix)
        if (line, column) != (expected_line, expected_column):
            raise ValueError('Location coordinates mismatch')
        locations.append((name, hex(lea), raw.hex(), hex(record), hex(pointer), length, suffix, line, column))
    return {'functions.tsv': (('name','start_va','end_va_exclusive','fde_va','file_offset','size','sha256','raw_hex'), functions),
            'unwind.tsv': (('name','unwind_index','fde_va','cie_va','fde_file_offset','size','fde_raw_hex'), unwind),
            'windows.tsv': (('name','function','start_va','end_va_exclusive','file_offset','size','sha256','raw_hex'), windows),
            'anchors.tsv': (('name','instruction_va','file_offset','raw_hex'), anchors),
            'branches.tsv': (('name','instruction_va','raw_hex','destination_va'), branches),
            'calls.tsv': (('name','instruction_va','raw_hex','destination_va'), calls),
            'indirect-calls.tsv': (('name','instruction_va','raw_hex','slot_va','relocation_addend_va'), indirect),
            'adapter-slots.tsv': (('slot_va','adapter','relocation_addend_va'), slots),
            'descriptors.tsv': (('start_va','file_offset','raw_hex','method_slot_va','adapter','method_addend_va'), descriptors),
            'locations.tsv': (('name','lea_va','lea_hex','record_va','path_va','full_path_length','path_suffix','line','column'), locations)}


def write_outputs(out, records):
    out.mkdir(parents=True, exist_ok=True)
    for filename, (header, rows) in records.items():
        with (out / filename).open('w', encoding='ascii', newline='') as handle:
            writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
            writer.writerow(header)
            writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    records = rows_from_image(BINARY.read_bytes())
    write_outputs(args.out, records)
    print('wrote ' + ', '.join(f'{name}={len(rows)}' for name, (_, rows) in records.items()))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print(f'evm_gas_settlement94: {error}', file=sys.stderr)
        raise SystemExit(1)
