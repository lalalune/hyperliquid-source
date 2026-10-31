#!/usr/bin/env python3
"""Independent byte-level check of RE-009-D. Imports nothing from tools/.

Reads the node #94 binary directly, maps each pinned virtual address through the
ELF PT_LOAD headers, and compares the bytes there to the pinned hex. Each key is
PASS (bytes equal), FAIL (bytes differ) or INCONCLUSIVE (binary missing, wrong
sha256, or address not file-backed). It also checks that the committed packet
JSON states the same lane, field and caller facts that these bytes encode.
Exit 0 only when every key is PASS and the packet agrees.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
PACKET = HERE / 'lattice-digest.json'
BINARY_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_SHA256 = '53d36b84f3f5cca3821964e1670abdf38ff389d2b62a5b4e75d6f993f74860a0'
SHA256_IV = '67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b'

KEYS = [
    (0x32699db, '4889fb', 'writer: rbx = state (rdi)'),
    (0x32699de, '4889742420', 'writer: dir ptr (rsi)'),
    (0x32699e3, '4889542428', 'writer: dir len (rdx)'),
    (0x32699fe, '488d355e84f9fc', 'writer: path template 0x201e63'),
    (0x3269a0f, 'ff152b465002', 'writer: format call [0x576e040]'),
    (0x3269a15, '488db3f8000000', 'writer: copy state+0xf8'),
    (0x3269a28, 'ba10080000', 'writer: copy len 0x810'),
    (0x3269a33, '488db3000a0000', 'writer: copy state+0xa00'),
    (0x3269a4a, '4881c308130000', 'writer: copy state+0x1308'),
    (0x3269a6e, '488d0db3604702', 'writer: save record 0x56dfb28'),
    (0x3269a7b, 'e890cd9a00', 'writer: call save helper 0x3c16810'),
    (0x326aef0, '8b05a2fc5002', 'caller A: once flag 0x577ab98'),
    (0x326aefe, '498db7f8000000', 'caller A: copy src r15+0xf8'),
    (0x326af05, '488dac2498000000', 'caller A: copy dst rsp+0x98'),
    (0x326af14, 'ba10080000', 'caller A: copy len 0x810'),
    (0x326af1f, '498db7000a0000', 'caller A: copy src r15+0xa00'),
    (0x326af36, '498db708130000', 'caller A: copy src r15+0x1308'),
    (0x326af4d, '488d7c2408', 'caller A: digest out rsp+0x8'),
    (0x326af52, '4889ee', 'caller A: digest input = first copy'),
    (0x326af55, 'e8b6765700', 'caller A: call 0x37e2610'),
    (0x326af5a, '498bb7181b0000', 'caller A: dir base [r15+0x1b18]'),
    (0x326afea, '4c89ff', 'caller A: writer rdi = state'),
    (0x326aff3, 'e8c8e9ffff', 'caller A: call writer 0x32699c0'),
    (0x32fc1bf, '8b05d3e94702', 'caller B: once flag 0x577ab98'),
    (0x32fc1cd, '498db424f8000000', 'caller B: copy src r12+0xf8'),
    (0x32fc1d5, '4c8dac2410010000', 'caller B: copy dst rsp+0x110'),
    (0x32fc1e4, 'ba10080000', 'caller B: copy len 0x810'),
    (0x32fc1ee, '498db424000a0000', 'caller B: copy src r12+0xa00'),
    (0x32fc205, '498db42408130000', 'caller B: copy src r12+0x1308'),
    (0x32fc21c, '488d7c2420', 'caller B: digest out rsp+0x20'),
    (0x32fc221, '4c89ee', 'caller B: digest input = first copy'),
    (0x32fc224, 'e8e7634e00', 'caller B: call 0x37e2610'),
    (0x32fc229, '4d8bac24181b0000', 'caller B: dir base [r12+0x1b18]'),
    (0x32fc261, '4c89e7', 'caller B: writer rdi = state'),
    (0x32fc267, 'e854d7f6ff', 'caller B: call writer 0x32699c0'),
    (0x37e2621, '4989f7', 'digest: r15 = input (rsi)'),
    (0x37e2624, '4889fb', 'digest: rbx = output struct (rdi)'),
    (0x37e2627, '488d8610080000', 'digest: lane1 base rsi+0x810'),
    (0x37e2633, '488d8620100000', 'digest: lane2 base rsi+0x1020'),
    (0x37e263f, '4c8b357adaf801', 'digest: load platform slot 0x57700c0'),
    (0x37e2646, '41ffd6', 'digest: lane0 platform call'),
    (0x37e265f, '0f100dba99a2fc', 'digest: lane0 IV[0:16] from 0x20c020'),
    (0x37e266b, '0f1015be99a2fc', 'digest: lane0 IV[16:32] from 0x20c030'),
    (0x37e26a7, '0f298c2420010000', 'digest: lane0 hasher cv[0:16] = IV'),
    (0x37e26af, '0f29942430010000', 'digest: lane0 hasher cv[16:32] = IV'),
    (0x37e26e0, '410f108700080000', 'digest: lane0 trailer load [r15+0x800]'),
    (0x37e26e8, '0f29842490000000', 'digest: lane0 trailer to rsp+0x90'),
    (0x37e26f0, '488b2dd1d9f801', 'digest: load update slot 0x57700c8'),
    (0x37e26ff, 'ba00080000', 'digest: lane0 update len 0x800'),
    (0x37e2707, '4c89fe', 'digest: lane0 update input = r15'),
    (0x37e270a, 'ffd5', 'digest: lane0 update call'),
    (0x37e270c, '4c8b25bdd9f801', 'digest: load finalize slot 0x57700d0'),
    (0x37e2713, '4889e7', 'digest: lane0 finalize out = rsp'),
    (0x37e2719, '41ffd4', 'digest: lane0 finalize call'),
    (0x37e271c, '0f100424', 'digest: lane0 digest[0:16]'),
    (0x37e2720, '0f104c2410', 'digest: lane0 digest[16:32]'),
    (0x37e2725, '0f298c24b0000000', 'digest: lane0 digest hi to rsp+0xb0'),
    (0x37e272d, '0f298424a0000000', 'digest: lane0 digest lo to rsp+0xa0'),
    (0x37e2735, '41ffd6', 'digest: lane1 platform call'),
    (0x37e274e, '0f100dcb98a2fc', 'digest: lane1 IV[0:16]'),
    (0x37e275a, '0f1015cf98a2fc', 'digest: lane1 IV[16:32]'),
    (0x37e27cf, '410f108710100000', 'digest: lane1 trailer load [r15+0x1010]'),
    (0x37e27d7, '0f29842480000000', 'digest: lane1 trailer to rsp+0x80'),
    (0x37e27e7, 'ba00080000', 'digest: lane1 update len 0x800'),
    (0x37e27ef, '488b742460', 'digest: lane1 update input = rsi+0x810'),
    (0x37e27f4, 'ffd5', 'digest: lane1 update call'),
    (0x37e27fc, '41ffd4', 'digest: lane1 finalize call'),
    (0x37e2808, '0f298c24d0000000', 'digest: lane1 digest hi to rsp+0xd0'),
    (0x37e2810, '0f298424c0000000', 'digest: lane1 digest lo to rsp+0xc0'),
    (0x37e2818, '41ffd6', 'digest: lane2 platform call'),
    (0x37e2831, '0f100de897a2fc', 'digest: lane2 IV[0:16]'),
    (0x37e283d, '0f1015ec97a2fc', 'digest: lane2 IV[16:32]'),
    (0x37e28b2, '410f108720180000', 'digest: lane2 trailer load [r15+0x1820]'),
    (0x37e28ba, '0f29442460', 'digest: lane2 trailer to rsp+0x60'),
    (0x37e28c7, 'ba00080000', 'digest: lane2 update len 0x800'),
    (0x37e28cf, '488b742478', 'digest: lane2 update input = rsi+0x1020'),
    (0x37e28d4, 'ffd5', 'digest: lane2 update call'),
    (0x37e28dc, '41ffd4', 'digest: lane2 finalize call'),
    (0x37e28e8, '0f114b70', 'digest: out+0x70 = lane2 digest[16:32]'),
    (0x37e28ec, '0f114360', 'digest: out+0x60 = lane2 digest[0:16]'),
    (0x37e2900, '0f114b10', 'digest: out+0x10 = lane0 digest[16:32]'),
    (0x37e2904, '0f1103', 'digest: out+0x00 = lane0 digest[0:16]'),
    (0x37e290f, '0f114320', 'digest: out+0x20 = lane0 trailer'),
    (0x37e2923, '0f114330', 'digest: out+0x30 = lane1 digest[0:16]'),
    (0x37e2927, '0f114b40', 'digest: out+0x40 = lane1 digest[16:32]'),
    (0x37e2933, '0f114350', 'digest: out+0x50 = lane1 trailer'),
    (0x37e293c, '0f118380000000', 'digest: out+0x80 = lane2 trailer'),
    (0x37e2943, '4889d8', 'digest: return rbx'),
    (0x37e2957, 'c3', 'digest: ret'),
    (0x326b006, '4881c4c8180000', 'post A: frame free add rsp,0x18c8'),
    (0x32fc33a, '4889442438', 'post B: overwrite store [rsp+0x38]'),
    (0x32fc345, '0f11442428', 'post B: overwrite store [rsp+0x28]'),
    (0x32fc34a, '4c89642420', 'post B: overwrite store [rsp+0x20]'),
    (0x32fc429, '488b7c2428', 'post B: header-free load [rsp+0x28]'),
    (0x32fc43c, '4881c448190000', 'post B: frame free add rsp,0x1948'),
    (0x14f940d, '483d01040000', 'blake3 update target: cmp rax,0x401'),
    (0x14f9419, '41be00040000', 'blake3 update target: mov r14d,0x400 (chunk size)'),
    (0x14fa020, 'e85bebffff', 'blake3 finalize target: call 0x14f8b80'),
    (0x14fa048, '0c08', 'blake3 finalize target: or al,0x8 (ROOT flag)'),
    (0x201e63, 'c00f2f6c745f6861736865732e6a736f6e00', 'writer path template ("/lt_hashes.json")'),
    (0x20c020, SHA256_IV, 'IV: SHA-256 initial words = BLAKE3 IV'),
]

EXPECT_PACKET = {
    'hashed_input_ranges': [['0x0', '0x800'], ['0x810', '0x1010'], ['0x1020', '0x1820']],
    'fields': [('0x0', 'lane0 digest[0x0:0x10]'), ('0x10', 'lane0 digest[0x10:0x20]'),
               ('0x20', 'lane0 input[0x800:0x810] (copied, not hashed)'),
               ('0x30', 'lane1 digest[0x0:0x10]'), ('0x40', 'lane1 digest[0x10:0x20]'),
               ('0x50', 'lane1 input[0x800:0x810] (copied, not hashed)'),
               ('0x60', 'lane2 digest[0x0:0x10]'), ('0x70', 'lane2 digest[0x10:0x20]'),
               ('0x80', 'lane2 input[0x800:0x810] (copied, not hashed)')],
    'callers': [('0x326aec0', '0x326af55', '0x326aff3'), ('0x32fc190', '0x32fc224', '0x32fc267')],
    'writer_args': ['rdi', 'rsi', 'rdx'],
    'writer_offsets': ['0xf8', '0xa00', '0x1308'],
    'post_digest': {
        'A': {'digest_content_reads': 0, 'frame_free': {'va': '0x326b006', 'size': '0x18c8'},
              'overwrite_stores': [], 'write_struct_offsets': [], 'header_free_load': None},
        'B': {'digest_content_reads': 0, 'frame_free': {'va': '0x32fc43c', 'size': '0x1948'},
              'overwrite_stores': ['0x32fc33a', '0x32fc345', '0x32fc34a'],
              'write_struct_offsets': ['0x18', '0x8', '0x0'], 'header_free_load': '0x32fc429'},
    },
}


def segments(data):
    phoff, = struct.unpack_from('<Q', data, 0x20)
    phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
    segs = []
    for i in range(phnum):
        t, _f, off, va, _p, fsz, _m, _a = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
        if t == 1:
            segs.append((va, off, fsz))
    return segs


def check_keys(data, keys=KEYS, check_sha=True):
    """Return [(status, va, role, detail)] for every key."""
    if data is None:
        return [('INCONCLUSIVE', va, role, 'binary missing') for va, _h, role in keys]
    if check_sha and hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        return [('INCONCLUSIVE', va, role, 'binary sha256 mismatch') for va, _h, role in keys]
    segs = segments(data)
    out = []
    for va, hexs, role in keys:
        n = len(hexs) // 2
        hit = [(b, o) for b, o, s in segs if b <= va and va + n <= b + s]
        if not hit:
            out.append(('INCONCLUSIVE', va, role, 'not file-backed'))
            continue
        b, o = hit[0]
        got = data[o + va - b: o + va - b + n].hex()
        out.append(('PASS' if got == hexs else 'FAIL', va, role, got))
    return out


def check_packet(packet):
    errs = []
    d = packet['digest_function']
    if d['hashed_input_ranges'] != EXPECT_PACKET['hashed_input_ranges']:
        errs.append('hashed input ranges')
    if [(f['offset'], f['value']) for f in d['output_fields']] != EXPECT_PACKET['fields']:
        errs.append('output field map')
    if d['output_size'] != '0x90' or d['output_bytes_written_once'] is not True:
        errs.append('output size / coverage')
    if [r['len'] for r in d['hasher_runs']] != ['0x800'] * 3:
        errs.append('update lengths')
    if [r['cv_init'] for r in d['hasher_runs']] != [['0x20c020', '0x20c030']] * 3:
        errs.append('hasher cv init')
    if [(c['function'], c['digest_call'], c['writer_call']) for c in packet['callers']] != EXPECT_PACKET['callers']:
        errs.append('callers')
    if not all(c['digest_before_writer'] and c['digest_in_is_first_copy'] and c['writer_rdi_is_state']
               for c in packet['callers']):
        errs.append('caller ordering / dataflow')
    w = packet['writer']
    if w['arguments_read'] != EXPECT_PACKET['writer_args'] or w['state_offsets_copied'] != EXPECT_PACKET['writer_offsets']:
        errs.append('writer arguments / offsets')
    if packet['iv']['bytes'] != SHA256_IV or packet['iv']['equals_sha256_initial_words'] is not True:
        errs.append('iv')
    pd = packet.get('post_digest')
    if not pd:
        errs.append('post_digest missing')
    else:
        for name, want in EXPECT_PACKET['post_digest'].items():
            got = pd.get(name, {})
            have = {k: got.get(k) for k in ('digest_content_reads', 'frame_free', 'overwrite_stores',
                                               'write_struct_offsets', 'header_free_load')}
            if have != want:
                errs.append(f'post_digest {name} no-consumer pins')
            if got.get('claim', '').startswith('dead') is False:
                errs.append(f'post_digest {name} claim not dead')
    return errs


def main():
    data = BINARY.read_bytes() if BINARY.exists() else None
    rows = check_keys(data)
    for st, va, role, det in rows:
        if st != 'PASS':
            print(st, f'{va:#x}', role, det)
    text = PACKET.read_text()
    errs = []
    if hashlib.sha256(text.encode()).hexdigest() != JSON_SHA256:
        errs.append('packet json sha256 mismatch')
    errs += check_packet(json.loads(text))
    for e in errs:
        print('FAIL packet:', e)
    n = {s: sum(r[0] == s for r in rows) for s in ('PASS', 'FAIL', 'INCONCLUSIVE')}
    print(f"independent_verify: {len(rows)} key VAs: PASS={n['PASS']} FAIL={n['FAIL']} "
          f"INCONCLUSIVE={n['INCONCLUSIVE']}; packet checks errors={len(errs)}")
    if n['FAIL'] or errs:
        return 1
    return 2 if n['INCONCLUSIVE'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
