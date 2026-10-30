#!/usr/bin/env python3
"""RE-001: node94 HTTP-client factory result guard and raw timeout initialization."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x1439010, 0x143940b
BODY_SHA256 = '40e00039073ad06301362c8852215468d94fe1cf85a6497732b44b54020d96e0'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def observe(data):
    secs = sections(data)

    def read(va, size):
        ss = [s for s in secs if s['type'] != 8 and s['address'] <= va
              and va + size <= s['address'] + s['size']]
        require(len(ss) == 1, 'Expected one file-backed mapping')
        off = ss[0]['offset'] + va - ss[0]['address']
        require(off + size <= len(data), 'Truncated file mapping')
        return data[off:off + size]

    def code(va, prefix, size):
        raw = read(va, size)
        require(raw.startswith(bytes.fromhex(prefix)), f'Instruction changed at {va:#x}')
        return raw

    def rip(va, prefix):
        raw = code(va, prefix, 7)
        return va + 7 + struct.unpack_from('<i', raw, 3)[0]

    _, frames = eh_frame_records(data, secs)
    fs = [f for f in frames if f['start'] == START]
    require(len(fs) == 1 and fs[0]['end'] == END, 'HTTP factory FDE changed')
    relsec = next(s for s in secs if s['name'] == '.rela.dyn')
    raw_rela = read(relsec['address'], relsec['size'])
    require(len(raw_rela) % 24 == 0, 'Truncated RELA table')
    relocs = {}
    for slot, info, addend in struct.iter_unpack('<QQq', raw_rela):
        if info == 8:
            require(slot not in relocs, 'Duplicate RELATIVE relocation')
            relocs[slot] = addend

    base = struct.unpack_from('<Q', code(0x14390e9, '49be', 10), 2)[0]
    adjustment = code(0x1439144, '4983c6', 4)[3]
    expected_result = (base + adjustment) & ((1 << 64) - 1)
    require(expected_result == 0x8000000000000006, 'Builder result-word discriminator changed')
    require(read(0x143913f, 5) == bytes.fromhex('4c8b7c2410'), 'Builder result load changed')
    require(read(0x1439152, 3) == bytes.fromhex('4d39f7'), 'Result comparison registers changed')
    branch = code(0x1439155, '0f85', 6)
    error_target = 0x143915b + struct.unpack_from('<i', branch, 2)[0]
    require(error_target == 0x1439331, 'Error branch target changed')
    timeout_bytes = code(0x143927a, '48b8', 10)[2:]
    timeout = struct.unpack('<d', timeout_bytes)[0]
    timeout_offset = struct.unpack_from('<I', code(0x1439284, '488983', 7), 3)[0]
    tag = code(0x143928b, 'c683', 7)
    tag_offset = struct.unpack_from('<I', tag, 2)[0]
    require((timeout, timeout_offset) == (10.0, 0xb8), 'Raw timeout value/offset changed')
    require((tag_offset, tag[6]) == (0xc0, 1), 'Raw timeout tag changed')
    message_va = rip(0x1439367, '488d3d')
    message_len = struct.unpack_from('<I', code(0x1439384, 'be', 5), 1)[0]
    message = read(message_va, message_len)
    require(message == b'called `Result::unwrap()` on an `Err` value', 'Unwrap message changed')
    location_slot = rip(0x1439375, '4c8d05')
    require(relocs.get(location_slot) == 0x1eb91c, 'HTTP source Location relocation changed')
    size, line, column = struct.unpack('<QII', read(location_slot + 8, 16))
    path = read(relocs[location_slot], size).decode('utf-8')
    require((path, line, column) == ('/home/ubuntu/hl/code_Mainnet/base/src/http_client.rs', 24, 67),
            'HTTP source Location contents changed')
    calls = []
    for va, expected in [(0x143913a, 0x3cd75e0), (0x1439275, 0x14ee540)]:
        raw = code(va, 'e8', 5)
        target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        require(target == expected, 'Factory helper call changed')
        calls.append({'site_va': hex(va), 'target_va': hex(target)})
    raw = code(0x1439389, 'ff15', 6)
    panic_slot = 0x143938f + struct.unpack_from('<i', raw, 2)[0]
    require(panic_slot == 0x576e048 and relocs.get(panic_slot) == 0x157aa10,
            'Unwrap call slot binding changed')
    body = read(START, END - START)
    require(hashlib.sha256(body).hexdigest() == BODY_SHA256, 'Enclosing HTTP factory body changed')
    return {'target_sha256': SHA256,
            'range': {'start_va': hex(START), 'end_va_exclusive': hex(END), 'bytes': len(body),
                      'sha256': BODY_SHA256, 'fde_va': hex(fs[0]['fde']), 'cie_va': hex(fs[0]['cie'])},
            'builder_result_guard': {'word_stack_offset': '0x10', 'compared_value': hex(expected_result),
                                     'jne_site_va': '0x1439155', 'error_target_va': hex(error_target)},
            'raw_timeout_stores': {'f64': timeout, 'f64_bits': hex(struct.unpack('<Q', timeout_bytes)[0]),
                                   'value_offset': hex(timeout_offset), 'tag_offset': hex(tag_offset), 'tag': tag[6]},
            'unwrap': {'message_va': hex(message_va), 'message': message.decode(),
                       'location_slot_va': hex(location_slot), 'path_va': hex(relocs[location_slot]),
                       'path': path, 'line': line, 'column': column,
                       'call_slot_va': hex(panic_slot), 'call_target_va': hex(relocs[panic_slot])},
            'selected_factory_calls': calls, 'captured_binaries_executed': False,
            'limits': 'Raw caller-side result and timeout representation only. TLS helper internals, '
                      'network requests, effective timer units/consumers, Rust types/layout, full helper/caller '
                      'closure and node equivalence are not established. No progress gate.'}


def build(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Wrong node94 SHA-256')
    return observe(data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    p.add_argument('--out', type=Path, default=ROOT / 'work/http-client-init-94.json')
    args = p.parse_args()
    result = build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('Verified HTTP factory guard, timeout stores and source/panic bindings; no execution.')


if __name__ == '__main__':
    main()
