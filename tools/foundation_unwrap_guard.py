#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 signed-value unwrap-guard evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is one sign test, one panic path with a readable message, and one
tail call. The tail-call target, the panic helper, and the argument slots are
left unnamed and undecoded beyond what is stated here.
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
START, END, STRIDE_END = 0x1510260, 0x1510293, 0x15102a0
BODY = bytes.fromhex(
    '4885f6780831d2ff25a3dd250450488d3db9d7d0fe488d0d6c0716044c8d05d5081604'
    '488d542407be2b000000ff15b5dd2504')
PAD = b'\xcc' * (STRIDE_END - END)
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000a83c01009cb0810033000000004e0e10')
TAIL_FDE = bytes.fromhex('1000000088ff2b000c785204a500000000000000')
MESSAGE = b'called `Result::unwrap()` on an `Err` value'
PATH = b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/bytes-1.11.1/src/bytes.rs'


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
    require(body == BODY, 'Unwrap-guard instruction window changed')
    require(read(END, STRIDE_END - END) == PAD, 'FDE padding changed')
    require(len(BODY) == END - START == 51, 'Body length changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x13ca4, FDE, START, END),
                                    (0x2bff84, TAIL_FDE, 0x54c8cb0, 0x54c8d55)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
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

    relative(0x576e010, 0x54c8cb0)
    relative(0x576e048, 0x157aa10)
    relative(0x5670b58, 0x2005f6)
    require(rels.get(0x56709e8) is None, 'Unexpected relocation at rcx slot')
    # Sign test and its two static paths, decoded from the body bytes.
    require(body[0:3] == bytes.fromhex('4885f6'), 'Sign test changed')
    require(body[3] == 0x78 and START + 5 + body[4] == 0x151026d, 'Panic branch changed')
    require(body[5:7] == bytes.fromhex('31d2'), 'Non-negative path changed')
    tail_slot = START + 7 + 6 + struct.unpack_from('<i', body, 9)[0]
    require(body[7:9] == bytes.fromhex('ff25') and tail_slot == 0x576e010, 'Tail-call slot changed')
    # Panic arm: push, message pointer, two pointer arguments, stack slot, length, helper call.
    require(body[13] == 0x50, 'Panic arm entry changed')
    msg_ptr = 0x151026e + 7 + struct.unpack_from('<i', body, 17)[0]
    require(body[14:17] == bytes.fromhex('488d3d') and msg_ptr == 0x21da2e, 'Message pointer changed')
    rcx_ptr = 0x1510275 + 7 + struct.unpack_from('<i', body, 24)[0]
    require(body[21:24] == bytes.fromhex('488d0d') and rcx_ptr == 0x56709e8, 'rcx argument changed')
    r8_ptr = 0x151027c + 7 + struct.unpack_from('<i', body, 31)[0]
    require(body[28:31] == bytes.fromhex('4c8d05') and r8_ptr == 0x5670b58, 'r8 argument changed')
    require(body[35:40] == bytes.fromhex('488d542407'), 'Stack-slot argument changed')
    require(body[40:45] == bytes.fromhex('be2b000000'), 'Message length changed')
    helper_slot = 0x151028d + 6 + struct.unpack_from('<i', body, 47)[0]
    require(body[45:47] == bytes.fromhex('ff15') and helper_slot == 0x576e048, 'Panic helper slot changed')
    require(read(0x21da2e, len(MESSAGE)) == MESSAGE, 'Panic message changed')
    require(len(MESSAGE) == 0x2b, 'Panic message length changed')
    require(read(0x2005f6, len(PATH)) == PATH, 'Argument path string changed')
    require(len(PATH) == 91, 'Argument path length changed')
    path_len, third = struct.unpack_from('<QQ', read(0x5670b58, 24), 8)
    require((path_len, third) == (91, 0x4900000548), 'r8 slot fields changed')
    rcx_fields = struct.unpack_from('<4Q', read(0x56709e8, 32), 0)
    require(rcx_fields == (0, 0, 1, 0), 'rcx slot fields changed')
    text = by_name['.text']
    require(text['address'] <= 0x54c8cb0 < text['address'] + text['size'], 'Tail target outside .text')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), stride_end_va=hex(STRIDE_END),
                              bytes=len(BODY), padding_bytes=STRIDE_END - END,
                              sha256=hashlib.sha256(BODY).hexdigest(), fde_section_offset='0x13ca4',
                              observed_behavior='sign test on rsi, panic path on negative, tail call otherwise',
                              inferred_label=None),
                sign_test=dict(instruction='test rsi,rsi', branch='js to panic arm',
                               panic_arm_va=hex(0x151026d), non_negative_path='xor edx,edx then tail call'),
                panic_arm=dict(message_va=hex(0x21da2e), message=MESSAGE.decode(), message_length=0x2b,
                               helper_slot=hex(0x576e048), helper_target=hex(0x157aa10),
                               argument_slots={'rcx': hex(0x56709e8), 'r8': hex(0x5670b58)}),
                tail_call=dict(slot=hex(0x576e010), target=hex(0x54c8cb0),
                               target_fde=[hex(0x54c8cb0), hex(0x54c8d55)], target_named=False),
                argument_slots=dict(r8_path=PATH.decode(), r8_path_length=91,
                                    r8_slot_fields=[0, 91, hex(0x4900000548), 0],
                                    rcx_slot_fields=[0, 0, 1, 0],
                                    rcx_slot_interpretation=None, r8_third_field_interpretation=None),
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
        print('Foundation unwrap-guard evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
