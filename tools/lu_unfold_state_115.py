#!/usr/bin/env python3
"""Bind the node #115 lu.rs unfold seed, its tick, and what a tick does (28th stage).

Continues the 27th stage, which found the lu.rs unfold poll 0x2cf08b0 as one
branch of a random-start two-way select 0x2ce0de0 but not who builds the
unfold state. This tool binds:

1. the unfold poll's seed layout (state tag 0): +0x8 a byte read as an
   index toggle, +0x10 an f64, +0xd0 an f64, +0xd8 a qword, +0xe0 a byte;
   the poll copies them into the running future (+0x8, +0x10, +0x18, +0x20,
   +0x30) and sleeps the f64 at +0x10 + 8 * (byte ^ 1), through 0x2d4f8b0
   when the +0x30 byte is set and 0x2d4f790 otherwise; on completion it
   zeroes the first 16 bytes (tag 0, byte 0) and returns 1;
2. the two seed builders, in 0x2accee0 and 0x2ad0db0 (the two callers of
   the select): a 16-byte zero at seed +0x0, 10.0 at +0xd0, the result of
   slot 0x64e11d8 (0x1564620) at +0xd8, 0 at +0xe0, boxed in 0xe8 bytes
   and stored at state +0x1248; +0x10 is not written there;
3. 0x1564620 hashes with the SipHash initial constants
   ("somepseudorandomlygeneratedbytes") a string formatted from slot
   0x64e0978 (0x1501360, which reads the thread RNG block);
4. the select wiring in 0x2accee0: [r15+0x30] resolves to state +0x1248;
   select outputs are tag 0 + message (receive), word 0x101 (tick),
   2 (all branches done) and 3 (pending);
5. on tag 1 the caller calls 0x2ae0920, which builds a request with the
   11-byte name at 0x605ad5 ("verify_peer") and the word 0xfa1 (4001) at
   +0x26, and refers to the "lu::timeout" template at 0x4326d0.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-lu-unfold-state-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

UNFOLD = 0x2cf08b0
SELECT = 0x2ce0de0
BUILDERS = (0x2accee0, 0x2ad0db0)
SEED_SLOT, SEED_FN = 0x64e11d8, 0x1564620
RNG_SLOT, RNG_FN = 0x64e0978, 0x1501360
JUMP_TABLE = 0x60fa24
JUMP_TARGETS = (0x2cf0959, 0x2cf0a80, 0x2cf0a73, 0x2cf097f, 0x2cf09c0)
NAME = (0x605ad5, b'verify_peer')
TIMEOUT_TEMPLATE = (0x4326d0, b'\x0clu::timeout ')
SIP_IV = b'somepseudorandomlygeneratedbytes'

FIXED = {
    0x2acf35e: 'ff15741ea103',            # call   QWORD PTR [rip+0x3a11e74]
    0x2acf364: '48b90000000000002440',    # movabs rcx,0x4024000000000000
    0x2acf36e: '48898c24a0030000',        # mov    QWORD PTR [rsp+0x3a0],rcx
    0x2acf376: '48898424a8030000',        # mov    QWORD PTR [rsp+0x3a8],rax
    0x2acf37e: 'c68424b003000000',        # mov    BYTE PTR [rsp+0x3b0],0x0
    0x2acf386: '660f57c0',                # xorpd  xmm0,xmm0
    0x2acf38a: '660f298424d0020000',      # movapd XMMWORD PTR [rsp+0x2d0],xmm0
    0x2acf393: 'bfe8000000',              # mov    edi,0xe8
    0x2acf398: 'ff15e200a103',            # call   QWORD PTR [rip+0x3a100e2]
    0x2acf39e: '4885c0',                  # test   rax,rax
    0x2acf3a1: '0f84ea010000',            # je     2acf591 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3278e9f>
    0x2acf3a7: '4989c6',                  # mov    r14,rax
    0x2acf3aa: '488db424d0020000',        # lea    rsi,[rsp+0x2d0]
    0x2acf3b2: 'bae8000000',              # mov    edx,0xe8
    0x2acf3b7: '4889c7',                  # mov    rdi,rax
    0x2acf3ba: 'ff154801a103',            # call   QWORD PTR [rip+0x3a10148]
    0x2acf3c0: '4c89b348120000',          # mov    QWORD PTR [rbx+0x1248],r14
    0x2ad332b: 'ff15a7dea003',            # call   QWORD PTR [rip+0x3a0dea7]
    0x2ad3331: '48b90000000000002440',    # movabs rcx,0x4024000000000000
    0x2ad333b: '48898c2470030000',        # mov    QWORD PTR [rsp+0x370],rcx
    0x2ad3343: '4889842478030000',        # mov    QWORD PTR [rsp+0x378],rax
    0x2ad334b: 'c684248003000000',        # mov    BYTE PTR [rsp+0x380],0x0
    0x2ad3353: '660f57c0',                # xorpd  xmm0,xmm0
    0x2ad3357: '660f298424a0020000',      # movapd XMMWORD PTR [rsp+0x2a0],xmm0
    0x2ad3360: 'bfe8000000',              # mov    edi,0xe8
    0x2ad3365: 'ff1515c1a003',            # call   QWORD PTR [rip+0x3a0c115]
    0x2ad336b: '4885c0',                  # test   rax,rax
    0x2ad336e: '0f84ea010000',            # je     2ad355e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3274ed2>
    0x2ad3374: '4989c6',                  # mov    r14,rax
    0x2ad3377: '488db424a0020000',        # lea    rsi,[rsp+0x2a0]
    0x2ad337f: 'bae8000000',              # mov    edx,0xe8
    0x2ad3384: '4889c7',                  # mov    rdi,rax
    0x2ad3387: 'ff157bc1a003',            # call   QWORD PTR [rip+0x3a0c17b]
    0x2ad338d: '4c89b348120000',          # mov    QWORD PTR [rbx+0x1248],r14
    0x2cf08bf: '488b07',                  # mov    rax,QWORD PTR [rdi]
    0x2cf08c2: '4885c0',                  # test   rax,rax
    0x2cf08c5: '7571',                    # jne    2cf0938 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3057af8>
    0x2cf08c7: '4989f6',                  # mov    r14,rsi
    0x2cf08ca: '4c8b6308',                # mov    r12,QWORD PTR [rbx+0x8]
    0x2cf08ce: 'f20f104310',              # movsd  xmm0,QWORD PTR [rbx+0x10]
    0x2cf08d3: 'f20f11442408',            # movsd  QWORD PTR [rsp+0x8],xmm0
    0x2cf08d9: '48c70302000000',          # mov    QWORD PTR [rbx],0x2
    0x2cf08e0: 'f20f1083d0000000',        # movsd  xmm0,QWORD PTR [rbx+0xd0]
    0x2cf08e8: 'f20f110424',              # movsd  QWORD PTR [rsp],xmm0
    0x2cf08ed: '0fb6abe0000000',          # movzx  ebp,BYTE PTR [rbx+0xe0]
    0x2cf0959: '0fb64308',                # movzx  eax,BYTE PTR [rbx+0x8]
    0x2cf095d: '3401',                    # xor    al,0x1
    0x2cf095f: '0fb6c0',                  # movzx  eax,al
    0x2cf0962: 'f20f1044c310',            # movsd  xmm0,QWORD PTR [rbx+rax*8+0x10]
    0x2cf0968: 'f20f114328',              # movsd  QWORD PTR [rbx+0x28],xmm0
    0x2cf096d: 'f20f114338',              # movsd  QWORD PTR [rbx+0x38],xmm0
    0x2cf0972: '807b3000',                # cmp    BYTE PTR [rbx+0x30],0x0
    0x2cf0986: 'e825ef0500',              # call   2d4f8b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2ff8b80>
    0x2cf09c7: 'e8c4ed0500',              # call   2d4f790 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2ff8ca0>
    0x2cf09d2: '41880c24',                # mov    BYTE PTR [r12],cl
    0x2cf09d6: 'b002',                    # mov    al,0x2
    0x2cf0a39: 'c6433101',                # mov    BYTE PTR [rbx+0x31],0x1
    0x2cf0a3d: '4889df',                  # mov    rdi,rbx
    0x2cf0a40: 'e8abc30f00',              # call   2decdf0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f5b640>
    0x2cf0a45: '0f57c0',                  # xorps  xmm0,xmm0
    0x2cf0a48: '0f1103',                  # movups XMMWORD PTR [rbx],xmm0
    0x2cf0a4b: 'b001',                    # mov    al,0x1
    0x2ce0e53: 'c744240402000000',        # mov    DWORD PTR [rsp+0x4],0x2
    0x2ce0e5b: '488d3dce587e03',          # lea    rdi,[rip+0x37e58ce]
    0x2ce0e62: '488d742404',              # lea    rsi,[rsp+0x4]
    0x2ce0e67: 'e814120003',              # call   5ce2080 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x663b0>
    0x2ce0e7a: '498b4730',                # mov    rax,QWORD PTR [r15+0x30]
    0x2ce0e7e: '488b38',                  # mov    rdi,QWORD PTR [rax]
    0x2ce0e81: '4c89f6',                  # mov    rsi,r14
    0x2ce0eea: 'c60300',                  # mov    BYTE PTR [rbx],0x0
    0x2ce0eed: '48895308',                # mov    QWORD PTR [rbx+0x8],rdx
    0x2ce0f16: '66c7030101',              # mov    WORD PTR [rbx],0x101
    0x2ce0f1b: 'eb0d',                    # jmp    2ce0f2a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3067506>
    0x2ce0f1d: '4084ed',                  # test   bpl,bpl
    0x2ce0f20: '7405',                    # je     2ce0f27 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3067509>
    0x2ce0f22: 'c60303',                  # mov    BYTE PTR [rbx],0x3
    0x2ce0f25: 'eb03',                    # jmp    2ce0f2a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3067506>
    0x2ce0f27: 'c60302',                  # mov    BYTE PTR [rbx],0x2
    0x2ad01ab: '488d8be0110000',          # lea    rcx,[rbx+0x11e0]
    0x2ad01b2: '488d9348120000',          # lea    rdx,[rbx+0x1248]
    0x2ad01b9: '488db380120000',          # lea    rsi,[rbx+0x1280]
    0x2ad01c0: '48898b80120000',          # mov    QWORD PTR [rbx+0x1280],rcx
    0x2ad01c7: 'c683a812000000',          # mov    BYTE PTR [rbx+0x12a8],0x0
    0x2ad01ce: '488993b0120000',          # mov    QWORD PTR [rbx+0x12b0],rdx
    0x2ad01d5: '488983b8120000',          # mov    QWORD PTR [rbx+0x12b8],rax
    0x2ad01dc: '4889b3c0120000',          # mov    QWORD PTR [rbx+0x12c0],rsi
    0x2ad01e3: '488db3b8120000',          # lea    rsi,[rbx+0x12b8]
    0x2ad01ea: '488dbc2490010000',        # lea    rdi,[rsp+0x190]
    0x2ad01f2: '4c89e2',                  # mov    rdx,r12
    0x2ad022f: '83f801',                  # cmp    eax,0x1
    0x2ad0232: '0f85da070000',            # jne    2ad0a12 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3277a1e>
    0x2ad028b: 'e890060100',              # call   2ae0920 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3267b10>
    0x2ae0b4f: '4c8d257f4fb2fd',          # lea    r12,[rip+0xfffffffffdb24f7f]
    0x2ae0b56: '4c896310',                # mov    QWORD PTR [rbx+0x10],r12
    0x2ae0b5a: '48c743180b000000',        # mov    QWORD PTR [rbx+0x18],0xb
    0x2ae0b62: '66c743200000',            # mov    WORD PTR [rbx+0x20],0x0
    0x2ae0b68: '894322',                  # mov    DWORD PTR [rbx+0x22],eax
    0x2ae0b6b: '66c74326a10f',            # mov    WORD PTR [rbx+0x26],0xfa1
    0x2ae0f2e: '488d3d9b1795fd',          # lea    rdi,[rip+0xfffffffffd95179b]
    0x1564667: '48b875657370656d6f73',    # movabs rax,0x736f6d6570736575
    0x1564671: '4889442410',              # mov    QWORD PTR [rsp+0x10],rax
    0x1564676: '48b86172656e6567796c',    # movabs rax,0x6c7967656e657261
    0x1564680: '4889442418',              # mov    QWORD PTR [rsp+0x18],rax
    0x1564685: '48b86d6f646e61726f64',    # movabs rax,0x646f72616e646f6d
    0x156468f: '4889442420',              # mov    QWORD PTR [rsp+0x20],rax
    0x1564694: '48b87365747962646574',     # movabs rax,0x7465646279746573
}
RIP_REFS = (
    # (instruction va, prefix, length, target)
    (0x2acf35e, b'\xff\x15', 6, SEED_SLOT),
    (0x2ad332b, b'\xff\x15', 6, SEED_SLOT),
    (0x2acf398, b'\xff\x15', 6, 0x64df480),   # allocate
    (0x2ad3365, b'\xff\x15', 6, 0x64df480),
    (0x2acf3ba, b'\xff\x15', 6, 0x64df508),   # memcpy
    (0x2ad3387, b'\xff\x15', 6, 0x64df508),
    (0x1564639, b'\xff\x15', 6, RNG_SLOT),
    (0x2ae0b4f, b'\x4c\x8d\x25', 7, NAME[0]),
    (0x2ae0f2e, b'\x48\x8d\x3d', 7, TIMEOUT_TEMPLATE[0]),
)
DIRECT_CALLS = (
    # (call va, target)
    (0x2cf0986, 0x2d4f8b0),
    (0x2cf09c7, 0x2d4f790),
    (0x2ad01f5, SELECT),
    (0x2ad421d, SELECT),
    (0x2ce0e67, 0x5ce2080),
    (0x2ce0e84, UNFOLD),
    (0x2ad028b, 0x2ae0920),
)
SIP_MOVABS = (0x1564667, 0x1564676, 0x1564685, 0x1564694)  # v0, v2, v1, v3


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def relative_relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def bind(data):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, prefix, length, target in RIP_REFS:
        raw = read_va(data, va, length)
        if raw[:len(prefix)] != prefix or va + length + struct.unpack_from('<i', raw, len(prefix))[0] != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, target in DIRECT_CALLS:
        raw = read_va(data, va, 5)
        if raw[0] != 0xe8 or va + 5 + struct.unpack_from('<i', raw, 1)[0] != target:
            raise ValueError(f'call at {va:#x} changed')
    rel = relative_relocations(data)
    if rel.get(SEED_SLOT) != SEED_FN or rel.get(RNG_SLOT) != RNG_FN:
        raise ValueError('slot relocation changed')
    table = read_va(data, JUMP_TABLE, 4 * len(JUMP_TARGETS))
    targets = tuple(JUMP_TABLE + struct.unpack_from('<i', table, 4 * i)[0] for i in range(len(JUMP_TARGETS)))
    if targets != JUMP_TARGETS:
        raise ValueError('unfold resume table changed')
    if read_va(data, NAME[0], len(NAME[1])) != NAME[1]:
        raise ValueError('request name changed')
    if read_va(data, TIMEOUT_TEMPLATE[0], len(TIMEOUT_TEMPLATE[1])) != TIMEOUT_TEMPLATE[1]:
        raise ValueError('timeout template changed')
    words = [struct.pack('>Q', struct.unpack_from('<Q', read_va(data, va + 2, 8))[0]) for va in SIP_MOVABS]
    # stored as v0, v2, v1, v3 of the SipHash state
    if b''.join(words[i] for i in (0, 2, 1, 3)) != SIP_IV:
        raise ValueError('SipHash constants changed')
    interval = struct.unpack('<d', read_va(data, 0x2acf366, 8))[0]
    if interval != struct.unpack('<d', read_va(data, 0x2ad3333, 8))[0]:
        raise ValueError('builders disagree on the interval')
    port = struct.unpack('<H', read_va(data, 0x2ae0b6f, 2))[0]

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'transport',
        'unfold_poll': {
            'fn': hex(UNFOLD),
            'seed_layout': {'+0x8': 'byte (index toggle)', '+0x10': 'f64', '+0xd0': 'f64',
                            '+0xd8': 'qword', '+0xe0': 'byte (sleep path)'},
            'future_layout': {'+0x8': 'seed +0x8', '+0x10': 'seed +0x10', '+0x18': 'seed +0xd0',
                              '+0x20': 'seed +0xd8', '+0x30': 'seed +0xe0'},
            'delay': 'f64 at future +0x10 + 8 * (byte +0x8 ^ 1), copied to +0x28 and +0x38',
            'sleep': {'+0x30 set': hex(0x2d4f8b0) + ' (no zero check)',
                      '+0x30 clear': hex(0x2d4f790) + ' (0.0 returns at once)'},
            'on_complete': hex(0x2cf0a39) + ': state byte +0x31 = 1, drop, 16 zero bytes at +0x0, return 1',
            'pending': hex(0x2cf09d6) + ': return 2',
            'resume_table': {hex(JUMP_TABLE): [hex(t) for t in targets]},
        },
        'seed_builders': {
            hex(BUILDERS[0]): 'seed at rsp+0x2d0, box stored at state +0x1248 (' + hex(0x2acf3c0) + ')',
            hex(BUILDERS[1]): 'seed at rsp+0x2a0, box stored at state +0x1248 (' + hex(0x2ad338d) + ')',
            'seed_values': {'+0x0..+0x10': 'zero (tag 0, byte 0)', '+0xd0': interval,
                            '+0xd8': 'slot %s -> %s result' % (hex(SEED_SLOT), hex(SEED_FN)),
                            '+0xe0': 0, '+0x10': 'not written by the builders'},
            'box_size': 0xe8,
        },
        'seed_qword': {
            'fn': hex(SEED_FN),
            'string_source': 'slot %s -> %s' % (hex(RNG_SLOT), hex(RNG_FN)),
            'hash_constants': SIP_IV.decode(),
        },
        'select': {
            'fn': hex(SELECT),
            'random_start': hex(0x2ce0e53) + ' bound 2 -> ' + hex(0x5ce2080),
            'unfold_ref': '[r15+0x30] = state +0x12b0 = &state +0x1248 (' + hex(0x2ad01ce) + ')',
            'outputs': {'0': 'message (receive branch), pointer at +0x8', '0x101': 'tick (unfold)',
                        '2': 'all branches done', '3': 'pending'},
        },
        'tick_action': {
            'caller_check': hex(0x2ad022f) + ' cmp eax, 1',
            'callee': hex(0x2ae0920),
            'request_name': NAME[1].decode(),
            'word_at_plus_0x26': port,
            'timeout_template': TIMEOUT_TEMPLATE[1][1:].decode(),
        },
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    result = bind(binary.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(f"interval={result['seed_builders']['seed_values']['+0xd0']} port={result['tick_action']['word_at_plus_0x26']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
