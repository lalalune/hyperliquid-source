#!/usr/bin/env python3
"""Check node #115 tree-route propagation of the replay timer delay pointer."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-017-node115-replay-tree-delay-pointer'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
FDE_SPECS = {
    'tracker_drain': (0x5afa030, 0x5afa1ee),
    'timer_map_apply': (0x4de0540, 0x4de0907),
    'tree_callback': (0x51520f0, 0x51528fb),
}
ANCHORS = {
    0x5afa06a: '498db688000000',       # lea rsi,[r14+0x88]
    0x5afa07f: '4889742418',           # mov [rsp+0x18],rsi
    0x5afa09d: '4889e6',               # mov rsi,rsp
    0x5afa0a0: 'e89b642eff',           # call 0x4de0540
    0x4de055d: '31c0',                 # xor eax,eax
    0x4de055f: '483b07',               # cmp rax,[rdi]
    0x4de0562: '0f818f000000',         # jno 0x4de05f7; tree path is fallthrough
    0x4de056c: '488b4630',             # load source context word +0x30
    0x4de0570: '48898424a0000000',     # save context word +0x30
    0x4de0578: '0f1006',               # copy source context words +0x00..+0x0f
    0x4de057b: '0f104e10',             # copy source context words +0x10..+0x1f
    0x4de057f: '0f105620',             # copy source context words +0x20..+0x2f
    0x4de0583: '0f29942490000000',     # save copied words +0x20..+0x2f
    0x4de058b: '0f298c2480000000',     # save copied words +0x10..+0x1f
    0x4de0593: '0f29442470',           # save copied words +0x00..+0x0f
    0x4de0755: '488d542470',           # lea rdx,[rsp+0x70]
    0x4de075a: '4889542428',           # descriptor word 0 = copied context
    0x4de0783: '4c89fe',               # pass descriptor in rsi
    0x4de0786: 'e865193700',           # call 0x51520f0
    0x5152101: '488b06',               # descriptor word 0 -> local context pointer
    0x5152181: '488b442408',           # reload local context pointer
    0x5152186: '4c8b38',               # load context word 0 (tracker)
    0x5152189: '488b4018',             # load context word +0x18 (tracker+0x88)
    0x515218d: 'f20f1000',             # read f64 through that pointer
}


def decode(data, start, end, secs):
    spans = [s for s in secs if s['type'] != 8 and s['address'] <= start
             and end <= s['address'] + s['size']]
    if len(spans) != 1:
        raise ValueError(f'ambiguous or missing text span: {start:#x}..{end:#x}')
    s = spans[0]
    offset = s['offset'] + start - s['address']
    body = data[offset:offset + end - start]
    insns = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, start))
    if sum(i.size for i in insns) != end - start:
        raise ValueError(f'incomplete instruction decode: {start:#x}..{end:#x}')
    return body, offset, insns


def verify(data, authenticate=True):
    digest = hashlib.sha256(data).hexdigest()
    if authenticate and digest != SHA:
        raise ValueError('node #115 target digest mismatch')
    secs = sections(data)
    _, fdes = eh_frame_records(data)
    windows = {}
    for name, (start, end) in FDE_SPECS.items():
        matches = [f for f in fdes if f['start'] == start and f['end'] == end]
        if len(matches) != 1:
            raise ValueError(f'exact {name} FDE missing')
        body, offset, insns = decode(data, start, end, secs)
        windows[name] = {'start': start, 'end': end, 'offset': offset,
                         'body': body, 'insns': {i.address: i for i in insns},
                         'fde': matches[0]}

    def read_va(va, size):
        hits = [s for s in secs if s['type'] != 8 and s['address'] <= va
                and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise ValueError(f'ambiguous or missing VA mapping at {va:#x}')
        s = hits[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    for va, expected_hex in ANCHORS.items():
        expected = bytes.fromhex(expected_hex)
        if read_va(va, len(expected)) != expected:
            raise ValueError(f'byte anchor mismatch at {va:#x}')

    def target_of_call(va):
        raw = read_va(va, 5)
        if raw[0] != 0xe8:
            raise ValueError(f'not a direct call at {va:#x}')
        return va + 5 + struct.unpack('<i', raw[1:])[0]

    if target_of_call(0x5afa0a0) != 0x4de0540:
        raise ValueError('drain call target changed')
    if target_of_call(0x4de0786) != 0x51520f0:
        raise ValueError('tree callback target changed')

    rendered_windows = {}
    for name, row in windows.items():
        rendered_windows[name] = {
            'start_va': row['start'], 'end_va': row['end'],
            'file_offset': row['offset'], 'body_sha256': hashlib.sha256(row['body']).hexdigest(),
            'instruction_count': len(row['insns']), 'fde': row['fde'],
        }
    return {
        'target_sha256': SHA,
        'target_size': len(data),
        'source_commit': 'e1528748a34c6ef79736ba16002caadbdff163a4',
        'question': 'Does the alternate tree callback receive the same tracker+0x88 delay pointer?',
        'claim_status': 'static pointer identity is established on the tree traversal path; runtime reachability and stored value remain unknown',
        'path_condition': '0x4de0540 falls through from jno at 0x4de0562 when the signed overflow flag is set by cmp 0,[map]; no broader map validity claim is made',
        'context_flow': [
            {'va': 0x5afa06a, 'observation': 'tracker+0x88 address formed'},
            {'va': 0x5afa07f, 'observation': 'address stored as caller context word +0x18'},
            {'va': 0x5afa09d, 'observation': 'caller context base passed in RSI to 0x4de0540'},
            {'va': 0x4de0578, 'observation': 'tree path copies source context bytes +0x00..+0x0f'},
            {'va': 0x4de057b, 'observation': 'tree path copies source context bytes +0x10..+0x1f, including pointer at +0x18'},
            {'va': 0x4de057f, 'observation': 'tree path copies source context bytes +0x20..+0x2f'},
            {'va': 0x4de056c, 'observation': 'tree path copies source context word +0x30 separately'},
            {'va': 0x4de0755, 'observation': 'descriptor points to the copied context'},
            {'va': 0x4de0786, 'observation': 'tree traversal calls callback 0x51520f0 with the descriptor'},
            {'va': 0x5152101, 'observation': 'callback loads descriptor word 0 as copied context pointer'},
            {'va': 0x5152189, 'observation': 'callback loads copied context word +0x18'},
            {'va': 0x515218d, 'observation': 'callback reads an 8-byte scalar through that pointer'},
        ],
        'windows': rendered_windows,
        'anchors': [{'va': va, 'bytes': raw.hex()} for va in ANCHORS
                    for raw in [bytes.fromhex(ANCHORS[va])]],
        'captured_target_executed': False,
        'component_gate_changed': False,
        'remaining_unknowns': [
            'who initializes or updates tracker+0x88 and its stored value',
            'runtime reachability of the tree/sentinel path and preceding eligibility checks',
            'concurrent mutation and callback return behavior',
            'full timer component behavior and source equivalence',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    result = verify(data)
    rejected = 0
    if args.self_test:
        for va, encoded in ANCHORS.items():
            changed = bytearray(data)
            changed_va = next(s['offset'] + va - s['address'] for s in sections(data)
                              if s['type'] != 8 and s['address'] <= va
                              and va + len(bytes.fromhex(encoded)) <= s['address'] + s['size'])
            changed[changed_va] ^= 1
            try:
                verify(changed, authenticate=False)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError(f'mutation accepted at {va:#x}')
    if args.write:
        PACKET.mkdir(parents=True, exist_ok=True)
        (PACKET / 'records.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        rows = ['va\tbytes\tmnemonic\toperands']
        for name, row in verify_windows(data).items():
            rows.extend(f'0x{i.address:x}\t{i.bytes.hex()}\t{i.mnemonic}\t{i.op_str or "<none>"}'
                        for i in row)
        (PACKET / 'instructions.tsv').write_text('\n'.join(rows) + '\n')
    elif (PACKET / 'records.json').read_text() != json.dumps(result, indent=2, sort_keys=True) + '\n':
        raise ValueError('retained records differ from authenticated target')
    print(json.dumps({'target_sha256': SHA, 'windows': len(FDE_SPECS),
                      'anchors': len(ANCHORS), 'mutations_rejected': rejected}))


def verify_windows(data):
    secs = sections(data)
    result = {}
    for name, (start, end) in FDE_SPECS.items():
        body, _, insns = decode(data, start, end, secs)
        result[name] = insns
    return result


if __name__ == '__main__':
    main()
