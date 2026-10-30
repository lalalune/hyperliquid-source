#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 days-to-date evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.

The window's FDE covers [0x1450810, 0x145085b) (75 bytes). The unwind index
stride to the next entry, 0x1450860, is 80 bytes only because five int3
padding bytes follow the FDE end; the stride is not the FDE extent.
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
START, FDE_END, INDEX_END = 0x1450810, 0x145085b, 0x1450860
BODY = bytes.fromhex(
    '5089f04869c08051010048b9000000004057ffff4801c148b881aefeff7faefeff4839c1'
    '720cff1574e0310485c0740259c3488d3d4894dcfe488d1530a22104be22000000ff150ddc3104')
PADDING = b'\xcc' * 5
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1800000078ac00007c4676004b00000000410e10700e08410e100000')
CONVERTER_FDE = bytes.fromhex(
    '4400000098500100bc9282002c02000000410e10410e18410e2083038602034c010e18410e'
    '10410e08410e2002770e18410e10410e08410e204f0e18410e10410e08410e20000000')
CALLER_FDE = bytes.fromhex(
    '4c000000b4cd1600505d8f022705000000410e10420e18420e20420e28420e30410e38470e'
    'e00483078c068d058e048f03860203c2020e38410e30420e28420e20420e18420e10410e08410ee0040000')
MESSAGE = b'`NaiveDate + TimeDelta` overflowed'
PATH = b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/chrono-0.4.38/src/naive/date/mod.rs'


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

    body = read(START, FDE_END - START)
    require(body == BODY, 'Days-to-date instruction window changed')
    require(read(FDE_END, INDEX_END - FDE_END) == PADDING, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0xac74, FDE, START, FDE_END),
                                    (0x15094, CONVERTER_FDE, 0x151f870, 0x151fa9c),
                                    (0x16cdb0, CALLER_FDE, 0x3744020, 0x3744547)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # All three retained records use the CIE-confirmed pcrel/sdata4 initial PC.
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

    relative(0x576e8b0, 0x151f870)
    relative(0x576e468, 0x157a9b0)
    relative(0x576f6b8, START)
    relative(0x566aa80, 0x1e6235)
    require(read(0x219c91, len(MESSAGE)) == MESSAGE, 'Expect message changed')
    length, line, column = struct.unpack('<QII', read(0x566aa80 + 8, 16))
    require((length, line, column) == (len(PATH), 1909, 38), 'Location layout changed')
    require(read(0x1e6235, length) == PATH, 'Location path changed')
    # Call-site bytes and RIP-relative slot targets inside the window.
    require(read(0x1450836, 6) == bytes.fromhex('ff1574e03104'), 'Converter call changed')
    require(0x1450836 + 6 + struct.unpack_from('<i', body, 40)[0] == 0x576e8b0,
            'Converter call slot changed')
    require(read(0x1450855, 6) == bytes.fromhex('ff150ddc3104'), 'Expect call changed')
    require(0x1450855 + 6 + struct.unpack_from('<i', body, 71)[0] == 0x576e468,
            'Expect call slot changed')
    require(body[37] == 0x0c and START + 38 + body[37] == 0x1450842, 'Range branch changed')
    require(body[47] == 0x02 and START + 48 + body[47] == 0x1450842, 'Result branch changed')
    # Incoming indirect calls through the window's slot, validated as bytes.
    require(read(0x374430c, 6) == bytes.fromhex('ff15a6b30202'), 'Incoming call 1 changed')
    require(read(0x3744324, 6) == bytes.fromhex('ff158eb30202'), 'Incoming call 2 changed')
    require(0x374430c + 6 + struct.unpack_from('<i', read(0x374430c, 6), 2)[0] == 0x576f6b8,
            'Incoming call 1 slot changed')
    require(0x3744324 + 6 + struct.unpack_from('<i', read(0x3744324, 6), 2)[0] == 0x576f6b8,
            'Incoming call 2 slot changed')

    # This byte-pattern scan is explicitly NOT a complete xref census. GNU
    # disassembly from the caller FDE start validates the two retained
    # candidates as instruction starts.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    indirect, direct = [], []
    for opcode in (b'\xff\x15', b'\xff\x25', b'\xe8'):
        pos = 0
        while (pos := code.find(opcode, pos)) >= 0:
            length = len(opcode) + 4
            if pos + length <= len(code):
                destination = text['address'] + pos + length + struct.unpack_from('<i', code, pos + len(opcode))[0]
                if destination == (START if opcode == b'\xe8' else 0x576f6b8):
                    (direct if opcode == b'\xe8' else indirect).append(text['address'] + pos)
            pos += 1
    require(indirect == [0x374430c, 0x3744324] and direct == [], 'Call-pattern candidate set changed')
    # Arithmetic constants parsed from the retained instruction bytes.
    multiplier = struct.unpack_from('<I', body, 6)[0]
    base = struct.unpack_from('<Q', body, 12)[0]
    bound = struct.unpack_from('<Q', body, 25)[0]
    require((multiplier, base, bound) == (86400, 0xffff574000000000, 0xfffeae7ffffeae81),
            'Arithmetic constants changed')
    gap = (1 << 64) - base
    require(gap % multiplier == 0 and gap // multiplier == 2 ** 31, 'Wrap threshold changed')
    threshold = gap // multiplier
    # Within the u32 input domain the unsigned branch outcome is exactly the
    # wrap outcome: pre-wrap values stay above the bound, post-wrap values
    # stay below it, because base > bound and the post-wrap maximum is below it.
    require(base > bound, 'Pre-wrap minimum not above bound')
    require((2 ** 32 - 1 - threshold) * multiplier < bound, 'Post-wrap maximum not below bound')
    require((base + (threshold - 1) * multiplier) % (1 << 64) >= bound, 'Below-threshold side changed')
    require((base + threshold * multiplier) % (1 << 64) < bound, 'At-threshold side changed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), fde_end_va_exclusive=hex(FDE_END),
                              index_stride_end_va_exclusive=hex(INDEX_END),
                              fde_bytes=len(body), index_stride_bytes=INDEX_END - START,
                              fde_body_sha256=hashlib.sha256(body).hexdigest(),
                              index_stride_sha256=hashlib.sha256(body + PADDING).hexdigest(),
                              fde_section_offset='0xac74',
                              inferred_label='days-to-date checked conversion helper'),
                arithmetic=dict(input='u32 in esi (mov esi,eax zero-extends)',
                                seconds_per_day=multiplier, base=hex(base), bound=hex(bound),
                                branch='unsigned: computed value < bound goes to expect block',
                                wrap_threshold_days=threshold,
                                below_threshold='converter call at 0x151f870',
                                at_threshold='expect block at 0x1450842',
                                converter_result='eax==0 goes to expect block, else eax returned'),
                call_edges=dict(converter_slot='0x576e8b0', converter_target='0x151f870',
                                converter_fde=['0x151f870', '0x151fa9c'],
                                expect_slot='0x576e468', expect_target='0x157a9b0',
                                expect_block='0x1450842',
                                incoming_slot='0x576f6b8',
                                incoming_sites=['0x374430c', '0x3744324'],
                                incoming_caller_fde=['0x3744020', '0x3744547']),
                source_location=dict(location_va='0x566aa80', path_va='0x1e6235',
                                     path=PATH.decode(), line=line, column=column,
                                     message_va='0x219c91', message=MESSAGE.decode()),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           ff15_ff25_candidates=list(map(hex, indirect)),
                                           e8_candidates=direct,
                                           validated_caller_fde=['0x3744020', '0x3744547'],
                                           complete_xref_census=False),
                captured_binary_executed=False, progress_gate_requested=False)


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
        require(result == json.loads(args.check.read_text()), 'Retained evidence differs')
        print('Foundation days-to-date evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
