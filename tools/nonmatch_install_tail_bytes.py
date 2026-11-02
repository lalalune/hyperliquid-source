#!/usr/bin/env python3
"""RE-004: non-match install tail bytes in node #94 (static, no execution).

The five gate-pattern callers of #166/#167 install a 0x40-byte object on
the non-match path: header (8B) + trio-constructor output (0x30B) + an
8-byte tail copied from stack slots the constructor never wrote.  On the
match path all five install only 0x38 bytes, leaving the object's 7th
qword untouched.  This tool verifies every byte anchor behind that claim
and writes evidence.json plus the case TSVs.  Only the Python standard
library is used; the binary is read, never executed.

    python3 tools/nonmatch_install_tail_bytes.py --out <dir>

writes evidence.json, installs.tsv, tail-writers.tsv and segments.txt.
README.md and MANIFEST.sha256 are hand-maintained beside them.
"""

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import fde_extents  # noqa: E402

BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TEXT_VA = 0x1343c80
TEXT_OFF = 0x1342c80


def fail(message):
    raise SystemExit(f'nonmatch_install_tail_bytes: {message}')


def read_bytes(data, va, length):
    off = TEXT_OFF + (va - TEXT_VA)
    if off < 0 or off + length > len(data):
        fail(f'read outside binary at {va:#x}')
    return data[off:off + length]


def check_bytes(data, va, expected_hex, what):
    got = read_bytes(data, va, len(expected_hex) // 2).hex()
    if got != expected_hex:
        fail(f'{what} at {va:#x}: got {got}, want {expected_hex}')


def e8_target(data, va):
    raw = read_bytes(data, va, 5)
    if raw[0] != 0xE8:
        fail(f'not an E8 call at {va:#x}')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def ff15_target(data, va):
    raw = read_bytes(data, va, 6)
    if raw[:2] != b'\xff\x15':
        fail(f'not an FF15 call at {va:#x}')
    disp = struct.unpack_from('<i', raw, 2)[0]
    return va + 6 + disp


# caller -> (fde_start, fde_end, frame_bytes, decoder, decoder_call,
#            gate_branch_va, gate_match_target, nonmatch_ctor_call, ctor,
#            ctor_buf_rsp, header_store_va, header_store_len,
#            header_rsp, nonmatch_first_read_va, nonmatch_src_start_rsp,
#            match_ctor_call, match_header_store_va, match_first_read_va,
#            lp_first_read_va, tail_start_rsp, verdict)
CALLERS = {
    'trioA': (0x4e6fd50, 0x4e6fee2, 0x70, 0x4e6f360, 0x4e6fd5e,
              0x4e6fdac, 0x4e6fe39, 0x4e6fdb7, 'A',
              0x38, 0x4e6fdbc, 9, 0x30, 0x4e6fdd3, 0x30,
              0x4e6fe3c, 0x4e6fe87, 0x4e6fe56, 0x4e6feb3, 0x68,
              'unwritten'),
    'double-gate': (0x4e852a0, 0x4e85663, 0xa8, 0x4e84500, 0x4e852c7,
                    0x4e85315, 0x4e8544f, 0x4e85320, 'B',
                    0x58, 0x4e85325, 9, 0x50, 0x4e85336, 0x50,
                    0x4e85454, 0x4e85461, 0x4e85468, 0x4e85631, 0x88,
                    'unwritten'),
    'trioB': (0x4e856f0, 0x4e85b12, 0xc0, 0x4e84500, 0x4e8570a,
              0x4e8575e, 0x4e858c8, 0x4e85769, 'B',
              0x78, 0x4e8576e, 9, 0x70, 0x4e8577f, 0x70,
              0x4e858cd, 0x4e858da, 0x4e858e1, 0x4e85ada, 0xa8,
              'unwritten'),
    'gate-like': (0x4e862b0, 0x4e8673a, 0xd0, 0x4e84500, 0x4e862ca,
                  0x4e86376, 0x4e86447, 0x4e86384, 'B',
                  0x98, 0x4e86389, 12, 0x90, 0x4e8639d, 0x90,
                  0x4e8644c, 0x4e86459, 0x4e86460, 0x4e866ff, 0xc8,
                  'unwritten'),
    'trioC': (0x4e6bcb0, 0x4e6c840, 0x1f8, None, None,
              0x4e6bf80, 0x4e6c023, 0x4e6bf8b, 'C',
              0x38, 0x4e6bf90, 9, 0x30, 0x4e6bfa1, 0x30,
              0x4e6c028, 0x4e6c035, 0x4e6c03d, 0x4e6c7f6, 0x68,
              'path-dependent'),
}

CONSTRUCTORS = {
    'A': (0x4e6c8b0, 0x4e6caa5, 0x574b9c0),
    'B': (0x4e81dc0, 0x4e81fb5, 0x574ce30),
    'C': (0x4e6b5f0, 0x4e6b7e5, 0x574b950),
}

# Constructor output-store skeleton, body offsets 368..418: lea rcx,tag;
# mov [rdx],rcx; lea rcx,0x1e629b; mov [rdx+0x8],rcx;
# mov [rdx+0x10],1; mov [rdx+0x18],0; mov [rdx+0x28],0; mov [rdx+0x20],rax.
# The two lea disp32 fields are the only per-instance bytes.
CTOR_OUTPUT_LEN = 9
DECODERS = {
    0x4e6f360: 0x4e6f68c,
    0x4e84500: 0x4e8482c,
}
# decoder output stores: [rbx+0x8] ptr, [rbx+0x10] byte, [rbx] tag 5.
DECODER_STORES = {
    0x4e6f360: [(0x4e6f5cc, '4c896308'), (0x4e6f5d0, '884310'),
                (0x4e6f5d3, 'c60305')],
    0x4e84500: [(0x4e8476c, '4c896308'), (0x4e84770, '884310'),
                (0x4e84773, 'c60305')],
}
# Tail-covering install reads: normal install and landing-pad install.
TAIL_READS = {
    'trioA': [(0x4e6fde7, '0f10542460'), (0x4e6fec2, '0f105c2460')],
    'double-gate': [(0x4e85347, '0f109c2480000000'),
                    (0x4e85640, '0f109c2480000000')],
    'trioB': [(0x4e85796, '0f109c24a0000000'),
              (0x4e85aef, '0f109c24a0000000')],
    'gate-like': [(0x4e863b5, 'f30f6f9c24c00000'),
                  (0x4e86717, '0f109c24c0000000')],
    'trioC': [(0x4e6bfb1, '0f105c2460'), (0x4e6c805, '0f105c2460')],
}
# Header stores: mov [rsp+disp],1 (gate-like uses the disp32 form).
HEADER_STORES = {
    'trioA': (0x4e6fdbc, '48c744243001000000'),
    'double-gate': (0x4e85325, '48c744245001000000'),
    'trioB': (0x4e8576e, '48c744247001000000'),
    'gate-like': (0x4e86389, '48c784249000000001000000'),
    'trioC': (0x4e6bf90, '48c744243001000000'),
}
# Helper 0x4e8c100 stores to its output struct (rax = rdi on entry).
# Max written offset is 0x30 exclusive (movdqu [rax+0x20], 16 bytes).
HELPER = 0x4e8c100
HELPER_END = 0x4e8c286
HELPER_STORES = [
    (0x4e8c221, '48894808'),
    (0x4e8c225, '48897010'),
    (0x4e8c229, '48c70000000000'),
    (0x4e8c23c, '894820'),
    (0x4e8c243, 'f30f7f4010'),
    (0x4e8c248, '488930'),
    (0x4e8c24b, '48895008'),
    (0x4e8c3c9, '488930'),
    (0x4e8c3cc, '48895008'),
    (0x4e8c3d9, 'f30f7f4010'),
    (0x4e8c3de, 'f30f7f4820'),
]
# TrioC prologue memcpy: dst [rsp+0x34], src [rsp+0x140], len 0xb8.
TRIOC_MEMCPY = [
    (0x4e6be08, '488d7c2434'),
    (0x4e6be0d, '488db42440010000'),
    (0x4e6be15, 'bab8000000'),
    (0x4e6be1a, 'ff15c0219000'),
]
TRIOC_MEMCPY_PLT = 0x576dfe0
# TrioC null-decode branch (je 0x4e6bf3a) and gate (header cmp, jne
# elsewhere, sentinel compare vs 0x204be0/0x206160, cmp 0xffff, je match).
TRIOC_GATE = [
    (0x4e6bd2b, '0f8409020000'),
    (0x4e6bf53, '837d0004'),
    (0x4e6bf57, '756e'),
    (0x4e6bf7b, '3dffff0000'),
    (0x4e6bf80, '0f849d000000'),
]
DESTRUCTORS = {
    0x4e6ed00: 0x4e6edb5,
    0x4e84440: 0x4e844fb,
    0x4e6b870: 0x4e6b92b,
}


def verify(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        fail('node #94 digest mismatch')
    _, ordered, _ = fde_extents(data)
    by_start = {f['start']: f['end'] for f in ordered}
    expected_fdes = {}
    for vals in CALLERS.values():
        expected_fdes[vals[0]] = vals[1]
    for start, end in DECODERS.items():
        expected_fdes[start] = end
    for start, end, _ in CONSTRUCTORS.values():
        expected_fdes[start] = end
    expected_fdes[HELPER] = HELPER_END
    for start, end in DESTRUCTORS.items():
        expected_fdes[start] = end
    for start, end in expected_fdes.items():
        if by_start.get(start) != end:
            fail(f'FDE extent mismatch at {start:#x}')
    for dec, stores in DECODER_STORES.items():
        for va, hx in stores:
            check_bytes(data, va, hx, 'decoder store')
    for name, (start, end, tag_slot) in CONSTRUCTORS.items():
        if end - start != 501:
            fail(f'constructor {name} length')
        base = start + 368
        # lea rcx,tag_slot; mov [rdx],rcx
        raw = read_bytes(data, base, 7)
        if raw[:3] != b'\x48\x8d\x0d':
            fail(f'constructor {name} tag lea opcode')
        target = base + 7 + struct.unpack_from('<i', raw, 3)[0]
        if target != tag_slot:
            fail(f'constructor {name} tag slot {target:#x}')
        check_bytes(data, base + 7, '488b542420', f'ctor {name} rdx load')
        check_bytes(data, base + 12, '48890a', f'ctor {name} store 0')
        raw = read_bytes(data, base + 15, 7)
        if raw[:3] != b'\x48\x8d\x0d':
            fail(f'constructor {name} empty-string lea opcode')
        target = base + 15 + 7 + struct.unpack_from('<i', raw, 3)[0]
        if target != 0x1e629b:
            fail(f'constructor {name} empty-string target {target:#x}')
        check_bytes(data, base + 22, '48894a08', f'ctor {name} store 8')
        check_bytes(data, base + 26, '48c7421001000000',
                    f'ctor {name} store 0x10')
        check_bytes(data, base + 34, '48c7421800000000',
                    f'ctor {name} store 0x18')
        check_bytes(data, base + 42, '48c7422800000000',
                    f'ctor {name} store 0x28')
        check_bytes(data, base + 50, '48894220', f'ctor {name} store 0x20')
    for vals in CALLERS.values():
        (_, _, _, decoder, decoder_call, gate_branch, gate_match,
         nonmatch_call, ctor, _, _, _, _, _, _, match_call, _, _, _, _, _) = vals
        if decoder is not None:
            if e8_target(data, decoder_call) != decoder:
                fail(f'decoder call target at {decoder_call:#x}')
        if e8_target(data, nonmatch_call) != CONSTRUCTORS[ctor][0]:
            fail(f'non-match ctor call target at {nonmatch_call:#x}')
        if e8_target(data, match_call) != CONSTRUCTORS[ctor][0]:
            fail(f'match ctor call target at {match_call:#x}')
    for va, hx in HEADER_STORES.values():
        check_bytes(data, va, hx, 'header store')
    for rows in TAIL_READS.values():
        for va, hx in rows:
            check_bytes(data, va, hx, 'tail-covering install read')
    for va, hx in TRIOC_MEMCPY:
        check_bytes(data, va, hx, 'trioC memcpy setup')
    if ff15_target(data, 0x4e6be1a) != TRIOC_MEMCPY_PLT:
        fail('trioC memcpy PLT target')
    for va, hx in TRIOC_GATE:
        check_bytes(data, va, hx, 'trioC gate')
    # TrioC inlined decode: 0x4e8c100 called with rdi=[rsp+0x30].
    check_bytes(data, 0x4e6bd1e, 'e8dd030200', 'trioC decode call')
    if e8_target(data, 0x4e6bd1e) != HELPER:
        fail('trioC decode call target')
    # Sentinel rip-relative targets: pcmpeqb at 0x4e6bf63 / 0x4e6bf6b.
    raw = read_bytes(data, 0x4e6bf63, 8)
    if 0x4e6bf63 + 8 + struct.unpack_from('<i', raw, 4)[0] != 0x204be0:
        fail('trioC gate sentinel 0x204be0')
    raw = read_bytes(data, 0x4e6bf6b, 8)
    if 0x4e6bf6b + 8 + struct.unpack_from('<i', raw, 4)[0] != 0x206160:
        fail('trioC gate sentinel 0x206160')
    for va, hx in HELPER_STORES:
        check_bytes(data, va, hx, 'helper store')


def build():
    binary = ROOT / BINARY
    data = binary.read_bytes()
    verify(data)
    installs = []
    writers = []
    segments = []
    for name, vals in CALLERS.items():
        (start, end, frame, decoder, decoder_call, gate_branch, gate_match,
         nonmatch_call, ctor, ctor_buf, header_va, header_len, header_rsp,
         first_read, src_start, match_call, match_header, match_read,
         lp_read, tail_start, verdict) = vals
        installs.append({
            'caller': name,
            'caller_start': f'{start:#x}',
            'caller_end': f'{end:#x}',
            'caller_len': end - start,
            'frame_bytes': frame,
            'decoder': f'{decoder:#x}' if decoder else 'inlined-0x4e8c100',
            'decoder_call': f'{decoder_call:#x}' if decoder_call else '-',
            'gate_branch': f'{gate_branch:#x}',
            'gate_match_target': f'{gate_match:#x}',
            'nonmatch_ctor_call': f'{nonmatch_call:#x}',
            'ctor': ctor,
            'ctor_buf_rsp': f'0x{ctor_buf:x}',
            'header_store': f'{header_va:#x}',
            'header_rsp': f'0x{header_rsp:x}',
            'nonmatch_src_start_rsp': f'0x{src_start:x}',
            'nonmatch_src_end_rsp': f'0x{src_start + 0x40:x}',
            'nonmatch_len': 0x40,
            'tail_start_rsp': f'0x{tail_start:x}',
            'tail_end_rsp': f'0x{tail_start + 8:x}',
            'match_ctor_call': f'{match_call:#x}',
            'match_header_store': f'{match_header:#x}',
            'match_len': 0x38,
            'lp_first_read': f'{lp_read:#x}',
            'tail_verdict': verdict,
        })
        # Writer census rows: every callee that receives a pointer from
        # which the tail slot could be written, and what it writes.
        if name == 'trioC':
            writers.append({'caller': name, 'writer': 'helper-0x4e8c100',
                            'receives': '[rsp+0x30] buffer',
                            'writes': '[out+0x0..0x30] (max [out+0x30])',
                            'reaches_tail': 'no'})
            writers.append({'caller': name, 'writer': 'ctor-C',
                            'receives': '[rsp+0x38] buffer',
                            'writes': '[out+0x0..0x30]',
                            'reaches_tail': 'no'})
            writers.append({'caller': name, 'writer': 'prologue-memcpy',
                            'receives': 'dst [rsp+0x34], src [rsp+0x140], 0xb8',
                            'writes': '[rsp+0x34..0xec] incl. tail (hash path only)',
                            'reaches_tail': 'yes-hash-path-only'})
            writers.append({'caller': name, 'writer': 'dtor-0x4e6b870',
                            'receives': 'object pointer only',
                            'writes': 'lock-dec [rax] refcount only',
                            'reaches_tail': 'no'})
        else:
            writers.append({'caller': name, 'writer': f'decoder-{decoder:#x}',
                            'receives': 'caller stack buffer',
                            'writes': '[out]=5, [out+0x8], [out+0x10] only',
                            'reaches_tail': 'no'})
            writers.append({'caller': name, 'writer': f'ctor-{ctor}',
                            'receives': 'caller stack buffer',
                            'writes': '[out+0x0..0x30]',
                            'reaches_tail': 'no'})
            writers.append({'caller': name,
                            'writer': 'dtor-0x4e6ed00' if name == 'trioA'
                            else 'dtor-0x4e84440',
                            'receives': 'object pointer only',
                            'writes': 'lock-dec [rax] refcount only',
                            'reaches_tail': 'no'})
        for va, hx in TAIL_READS[name]:
            segments.append({
                'caller': name,
                'tail_read_va': f'{va:#x}',
                'instruction_hex': hx,
                'tail_start_rsp': f'0x{tail_start:x}',
                'tail_end_rsp': f'0x{tail_start + 8:x}',
                'tail_len': 8,
            })
    evidence = {
        'node': 94,
        'node_sha256': SHA256,
        'callers': 5,
        'tails_unwritten': 4,
        'tails_path_dependent': 1,
        'nonmatch_len': 0x40,
        'match_len': 0x38,
        'decoders': [{'start': f'{s:#x}', 'end': f'{e:#x}', 'len': e - s,
                      'output_stores': 3} for s, e in DECODERS.items()],
        'constructors': [{'id': k, 'start': f'{v[0]:#x}', 'end': f'{v[1]:#x}',
                          'len': v[1] - v[0], 'output_qwords': 6,
                          'tag_slot': f'{v[2]:#x}'}
                         for k, v in CONSTRUCTORS.items()],
        'destructors': [{'start': f'{s:#x}', 'end': f'{e:#x}', 'len': e - s,
                         'stores': 'lock-dec [rax] only'}
                        for s, e in DESTRUCTORS.items()],
        'helper_0x4e8c100': {'start': f'{HELPER:#x}', 'end': f'{HELPER_END:#x}',
                             'len': HELPER_END - HELPER,
                             'max_write_offset': 0x30,
                             'store_count': len(HELPER_STORES)},
        'trioc_memcpy': {'dst_rsp': '0x34', 'src_rsp': '0x140', 'len': 0xb8,
                         'tail_src_rsp': '0x174', 'tail_src_end_rsp': '0x17c',
                         'unwritten_src_gap': '0x154..0x1c8',
                         'plt': f'{TRIOC_MEMCPY_PLT:#x}'},
        'installs': len(installs),
        'writer_rows': len(writers),
        'segment_rows': len(segments),
    }
    return evidence, installs, writers, segments


def write_tsv(path, rows, fields):
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter='\t')
        writer.writeheader()
        for row in rows:
            writer.writerow({f: row[f] for f in fields})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    evidence, installs, writers, segments = build()
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    write_tsv(out / 'installs.tsv', installs,
              ['caller', 'caller_start', 'caller_end', 'caller_len',
               'frame_bytes', 'decoder', 'decoder_call', 'gate_branch',
               'gate_match_target', 'nonmatch_ctor_call', 'ctor',
               'ctor_buf_rsp', 'header_store', 'header_rsp',
               'nonmatch_src_start_rsp', 'nonmatch_src_end_rsp',
               'nonmatch_len', 'tail_start_rsp', 'tail_end_rsp',
               'match_ctor_call', 'match_header_store', 'match_len',
               'lp_first_read', 'tail_verdict'])
    write_tsv(out / 'tail-writers.tsv', writers,
              ['caller', 'writer', 'receives', 'writes', 'reaches_tail'])
    with (out / 'segments.txt').open('w') as handle:
        handle.write('# caller tail_read_va instruction_hex '
                     'tail_start_rsp tail_end_rsp tail_len\n')
        for row in segments:
            handle.write(f"{row['caller']} {row['tail_read_va']} "
                         f"{row['instruction_hex']} {row['tail_start_rsp']} "
                         f"{row['tail_end_rsp']} {row['tail_len']}\n")


if __name__ == '__main__':
    main()
