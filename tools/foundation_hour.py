#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 hour-extraction evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x14509f0, 0x1450a51
BODY = bytes.fromhex(
    '508b47043d00100e0073183d905f0100733689c1b8c5b3a291480fafc148c1e82b59c3'
    '488d3d9093dcfe488d0d1fa221044c8d05a0a02104488d542407be2b000000ff1510d63104'
    '488d3dea64dcfe488d1592632104be1c000000ff15b7d63104')
# Exported FDE/CIE bytes, independently checked with LLVM --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('180000000cad0000c84776006100000000410e10610e08410e100000')
CALLER_FDE = bytes.fromhex(
    '50000000e4bf00009c8b430079140000045f7d95ff410e10420e18420e20420e28420e30'
    '410e38470ef00483078c068d058e048f03860203b00d0e38410e30420e28420e20420e18420e10410e08410ef0040000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    body = read(START, END - START)
    require(body == BODY, 'Hour instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    caller_cie = bytes.fromhex('1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000')
    require(read(eh['address'] + 0x2dc714, len(caller_cie)) == caller_cie, 'Caller CIE changed')
    for offset, raw, start, end in [(0xad08, FDE, START, END),
                                    (0x2e86f4, CALLER_FDE, 0x14027b0, 0x1403c29)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # Both retained records use the CIE-confirmed pcrel/sdata4 initial PC.
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)

    def relative(address, expected):
        require(rels.get(address) == (8, expected), 'Relative relocation changed')
        require(read(address, 8) == b'\0' * 8, 'Unexpected pre-relocation pointer')

    relative(0x576efc0, START)
    relative(0x576e048, 0x157aa10)
    relative(0x576e108, 0x157b7f0)
    locations = []
    for address, string_va, path, line, column in [
        (0x566aac8, 0x1de94e, b'/home/ubuntu/hl/code_Mainnet/base/src/time.rs', 62, 44),
        (0x5666dd8, 0x1f0469, b'/home/ubuntu/hl/code_Mainnet/base/src/hour.rs', 12, 13),
    ]:
        relative(address, string_va)
        length, actual_line, actual_column = struct.unpack('<QII', read(address + 8, 16))
        require((length, actual_line, actual_column) == (len(path), line, column), 'Location layout changed')
        require(read(string_va, length) == path, 'Location path changed')
        locations.append(dict(location_va=hex(address), path_va=hex(string_va),
                              path=path.decode(), line=line, column=column))
    for va, message in [(0x219daa, b'called `Result::unwrap()` on an `Err` value'),
                        (0x216f29, b'assertion failed: hour <= 24')]:
        require(read(va, len(message)) == message, 'Error message changed')
    require(read(0x140380f, 11) == bytes.fromhex('488d7c2410ff15a6b73604'), 'Caller argument/call changed')

    # This byte-pattern scan is explicitly NOT a complete xref census. LLVM
    # disassembly from the caller FDE start validates the one retained candidate.
    text = by_name['.text']; code = read(text['address'], text['size'])
    indirect, direct = [], []
    for opcode in (b'\xff\x15', b'\xff\x25', b'\xe8'):
        pos = 0
        while (pos := code.find(opcode, pos)) >= 0:
            length = len(opcode) + 4
            if pos + length <= len(code):
                destination = text['address'] + pos + length + struct.unpack_from('<i', code, pos + len(opcode))[0]
                if destination == (START if opcode == b'\xe8' else 0x576efc0):
                    (direct if opcode == b'\xe8' else indirect).append(text['address'] + pos)
            pos += 1
    require(indirect == [0x1403814] and direct == [], 'Call-pattern candidate set changed')
    outer, inner = struct.unpack_from('<I', body, 5)[0], struct.unpack_from('<I', body, 12)[0]
    multiplier, shift = struct.unpack_from('<I', body, 21)[0], body[32]
    require((outer, inner, multiplier, shift) == (921600, 90000, 0x91a2b3c5, 43), 'Arithmetic constants changed')
    require(all((n * multiplier) >> shift == n // 3600 for n in range(inner)), 'Quotient identity failed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0xad08',
                              inferred_label='hour extraction from a datetime-like input'),
                arithmetic=dict(input_load='u32 at rdi+4', input_returning_domain=[0, inner-1],
                                multiplier=hex(multiplier), shift=shift, divisor=3600,
                                exhaustive_quotient_cases=inner, return_range=[0,24],
                                inner_error_domain=[inner,outer-1], outer_error_domain=[outer,0xffffffff]),
                source_locations=locations,
                outgoing_relative_slots={'0x576e048':'0x157aa10','0x576e108':'0x157b7f0'},
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           ff15_ff25_candidates=list(map(hex,indirect)), e8_candidates=direct,
                                           validated_caller_fde=['0x14027b0','0x1403c29'],
                                           complete_xref_census=False),
                captured_binary_executed=False, progress_gate_requested=False)


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'Duplicate key in retained check input: {key}')
        out[key] = value
    return out


def load_check(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=_unique_object)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256, 'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        require(result == load_check(args.check), 'Retained evidence differs')
        print('Foundation hour evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
