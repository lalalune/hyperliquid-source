#!/usr/bin/env python3
"""Census the 51 direct calls of the node #115 move_token step 0x5580d10 (stage 101).

Continues #6212 (stage 99) and #6213 (stage 100). 0x5580d10 saves r8 in r15
and r9 in rbp, then returns tag 0x1a2 before either move_token leg when
r8 == stack argument 0 ([rsp+0x1b0] after its 0x30-byte push block and
0x178-byte frame) and either r8 == 0 or r9 == stack argument 1
([rsp+0x1b8]). This tool binds, for every direct call:

1. the instruction that last sets r8 (and r9 where present) before the call;
2. the stack store (mov [rsp] / mov [rsp+0x8] / movups/movdqu [rsp+0x8]) or
   push that supplies stack arguments 0 and 1;
3. a class derived from those pinned bytes:
   - 'early-exit': r8 and argument 0 are both the constant 0;
   - 'can-move': r8 and argument 0 are constants that differ, or r8 is a
     sete result (0 or 1) and argument 0 is a constant 1, so at least one
     value of r8 skips the early exit;
   - 'unresolved': r8 or argument 0 is a register or memory value.

'Move' means the leg calls run; whether a leg changes a balance also depends
on the amount and the checks bound in #6213. Labels are inferences. The
captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import struct
from collections import Counter
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import RELATIVE, TARGET, direct_calls, fixed, frame, read_va

PACKET = ROOT / 'research/work-items/RE-008-move-token-callers-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

MOVE = 0x5580d10
STAGE100_SITE = 0x5581c1c   # in 0x55817e0; #6213 binds argument 0 = caller rcx = 0

FIXED = {
    0x5580d1a: '4881ec78010000',        # sub rsp, 0x178
    0x5580d21: '4c89cd',                # mov rbp, r9
    0x5580d24: '4d89c7',                # mov r15, r8
    0x5580d7e: '4c3bbc24b0010000',      # cmp r15, [rsp+0x1b0]      (stack argument 0)
    0x5580d86: '7517',                  # jne -> legs
    0x5580d88: '4d85ff',                # test r15, r15
    0x5580d8b: '0f84da050000',          # je 0x558136b              (early exit)
    0x5580d91: '483bac24b8010000',      # cmp rbp, [rsp+0x1b8]      (stack argument 1)
    0x5580d99: '0f84cc050000',          # je 0x558136b
}

SITES = {
    0x54d72f2: (('r8', 0x54d72d1, '41b801000000'), ('r9', 0x54d72ef, '4989e9'), ('a0', 0x54d72c9, '48c7042400000000')),
    0x54d760a: (('r8', 0x54d75e9, '41b801000000'), ('r9', 0x54d7607, '4989e9'), ('a0', 0x54d75e1, '48c7042400000000')),
    0x54d78f5: (('r8', 0x54d78c3, '410f94c0'), ('r9', 0x54d78f2, '4531c9'), ('a0', 0x54d78d5, '48c7042401000000'), ('a1', 0x54d78c7, '48896c2408')),
    0x54d7a22: (('r8', 0x54d7a04, '41b801000000'), ('r9', 0x54d7a1f, '4989e9'), ('a0', 0x54d7a00, '48890424'), ('a1', 0x54d79fa, 'f30f7f442408')),
    0x556ae0f: (('r8', 0x556adfe, '41b801000000'), ('r9', 0x556ae0a, '4c8b4c2438'), ('a0', 0x556ade6, '48c7042400000000')),
    0x556b0c2: (('r8', 0x556b092, '410f94c0'), ('r9', 0x556b0bf, '4531c9'), ('a0', 0x556b0a4, '48c7042401000000'), ('a1', 0x556b096, '4c896c2408')),
    0x556b1f5: (('r8', 0x556b1e9, '41b801000000'), ('r9', 0x556b1f2, '4d89e9'), ('a0', 0x556b1d5, '48890424'), ('a1', 0x556b1d0, '0f11442408')),
    0x556b67d: (('r8', 0x556b66e, '41b801000000'), ('r9', 0x556b67a, '4989d9'), ('a0', 0x556b656, '48c7042400000000')),
    0x556b929: (('r8', 0x556b8f9, '410f94c0'), ('r9', 0x556b926, '4531c9'), ('a0', 0x556b90b, '48c7042401000000'), ('a1', 0x556b8fd, '4c896c2408')),
    0x556ba56: (('r8', 0x556ba4a, '41b801000000'), ('r9', 0x556ba53, '4d89e9'), ('a0', 0x556ba36, '48890424'), ('a1', 0x556ba31, '0f11442408')),
    0x55700de: (('r8', 0x55700cf, '41b801000000'), ('r9', 0x55700db, '4989d9'), ('a0', 0x55700b7, '48c7042400000000')),
    0x557038d: (('r8', 0x557035d, '410f94c0'), ('r9', 0x557038a, '4531c9'), ('a0', 0x557036f, '48c7042401000000'), ('a1', 0x5570361, '4c897c2408')),
    0x55704bd: (('r8', 0x55704b1, '41b801000000'), ('r9', 0x55704ba, '4d89f9'), ('a0', 0x557049d, '48890424'), ('a1', 0x5570498, '0f11442408')),
    0x557c492: (('r8', 0x557c48c, '4531c0'), ('r9', 0x557c48f, '4d89e9'), ('a0', 0x557c46e, '48c7042400000000')),
    0x557c5c3: (('r8', 0x557c5bd, '4531c0'), ('r9', 0x557c5c0, '4989c9'), ('a0', 0x557c59d, '48c7042400000000')),
    0x5581c1c: (('r8', 0x5581c19, '4531c0'), ('a0', 0x5581bfe, '4c892424'), ('a1', 0x5581bf9, '4c896c2408')),
    0x55825d5: (('r8', 0x55825ba, '41b801000000'), ('r9', 0x55825d2, '4d89f9'), ('a0', 0x55825b2, '48c7042400000000')),
    0x558314a: (('r8', 0x558313f, '4531c0'), ('a3', 0x5583142, '4155'), ('a2', 0x5583144, '6a01'), ('a1', 0x5583146, '4156'), ('a0', 0x5583148, '6a01')),
    0x5584a5c: (('r8', 0x5584a51, '4531c0'), ('r9', 0x55849fc, '4989c1'), ('a3', 0x5584a54, '4151'), ('a2', 0x5584a56, '6a01'), ('a1', 0x5584a58, '4155'), ('a0', 0x5584a5a, '6a01')),
    0x55886ac: (('r8', 0x5588681, '4989c8'), ('r9', 0x558867e, '4d89c1'), ('a0', 0x5588696, '48c7042400000000')),
    0x5588e9a: (('r8', 0x5588e92, '4531c0'), ('a2', 0x5588e95, '6a00'), ('a1', 0x5588e97, '4156'), ('a0', 0x5588e99, '53')),
    0x558923f: (('r8', 0x5589226, '41b801000000'), ('r9', 0x558923c, '4d89f9'), ('a0', 0x558921e, '48c7042400000000')),
    0x558aad2: (('r8', 0x558aab7, '41b801000000'), ('r9', 0x558aacf, '4d89e9'), ('a0', 0x558aab3, '48890424'), ('a1', 0x558aaae, '0f11442408')),
    0x558ae39: (('r8', 0x558ae33, '4d89f8'), ('r9', 0x558ae36, '4d89e1'), ('a0', 0x558ae1b, '48c7042400000000')),
    0x558af61: (('r8', 0x558af48, '41b801000000'), ('r9', 0x558af5e, '4989e9'), ('a0', 0x558af44, '48890424'), ('a1', 0x558af3f, '0f11442408')),
    0x558d886: (('r8', 0x558d87e, '4c8b442430'), ('r9', 0x558d883, '4989d9'), ('a0', 0x558d86b, '48c7042400000000')),
    0x558dba5: (('r8', 0x558db75, '410f94c0'), ('r9', 0x558dba2, '4531c9'), ('a0', 0x558db8c, '48c7042401000000'), ('a1', 0x558db7e, '4c897c2408')),
    0x558de33: (('r8', 0x558de24, '41b801000000'), ('r9', 0x558de30, '4989d9'), ('a0', 0x558de18, '48890424'), ('a1', 0x558de13, '0f11442408')),
    0x558ea04: (('r8', 0x558e9d7, '410f94c0'), ('r9', 0x558ea01, '4531c9'), ('a0', 0x558e9e9, '48c7042401000000'), ('a1', 0x558e9db, '4889542408')),
    0x558eb2f: (('r8', 0x558eb1e, '41b801000000'), ('r9', 0x558eb2c, '4989d9'), ('a0', 0x558eb12, '48890424'), ('a1', 0x558eb0d, '0f11442408')),
    0x558ebe7: (('r8', 0x558ebd3, '41b801000000'), ('r9', 0x558ebe4, '4989d9'), ('a0', 0x558ebc3, '48c7042400000000')),
    0x558fc6e: (('r8', 0x558fc5c, '41b801000000'), ('r9', 0x558fc6b, '4531c9'), ('a0', 0x558fc4c, '48c7042400000000')),
    0x558ffd8: (('r8', 0x558ffd0, '4989e8'), ('r9', 0x558ffd3, '4c8b4c2420'), ('a0', 0x558ffb7, '48c7042400000000')),
    0x559013e: (('r8', 0x5590113, '410f94c0'), ('r9', 0x559013b, '4531c9'), ('a0', 0x5590125, '48c7042401000000'), ('a1', 0x5590117, '4c89742408')),
    0x559021b: (('r8', 0x559020c, '41b801000000'), ('r9', 0x5590218, '4d89f1'), ('a0', 0x5590200, '48890424'), ('a1', 0x55901fb, '0f11442408')),
    0x559071c: (('r8', 0x5590714, '4989e8'), ('r9', 0x5590717, '4c8b4c2420'), ('a0', 0x55906fb, '48c7042400000000')),
    0x559088a: (('r8', 0x559085f, '410f94c0'), ('r9', 0x5590887, '4531c9'), ('a0', 0x5590871, '48c7042401000000'), ('a1', 0x5590863, '48896c2408')),
    0x5590a4a: (('r8', 0x5590a3b, '41b801000000'), ('r9', 0x5590a47, '4989e9'), ('a0', 0x5590a2f, '48890424'), ('a1', 0x5590a2a, '0f11442408')),
    0x5590e8b: (('r8', 0x5590e5b, '410f94c0'), ('r9', 0x5590e88, '4531c9'), ('a0', 0x5590e70, '48c7042401000000'), ('a1', 0x5590e62, '4c89642408')),
    0x5590f71: (('r8', 0x5590f62, '41b801000000'), ('r9', 0x5590f6e, '4989d9'), ('a0', 0x5590f59, '48890424'), ('a1', 0x5590f54, '0f11442408')),
    0x5591020: (('r8', 0x559101a, '4d89f0'), ('r9', 0x559101d, '4d89e9'), ('a0', 0x5591002, '48c7042400000000')),
    0x55921fa: (('r8', 0x55921cb, '410f94c0'), ('r9', 0x55921f7, '4531c9'), ('a0', 0x55921e2, '48c7042401000000'), ('a1', 0x55921d4, '4889442408')),
    0x55923cd: (('r8', 0x55923bc, '41b801000000'), ('r9', 0x55923ca, '4d89f9'), ('a0', 0x55923b0, '48890424'), ('a1', 0x55923ab, '0f11442408')),
    0x5592481: (('r8', 0x5592479, '4d89e0'), ('r9', 0x559247c, '4c8b4c2428'), ('a0', 0x559245e, '48c7042400000000')),
    0x559349b: (('r8', 0x559346b, '410f94c0'), ('r9', 0x5593498, '4531c9'), ('a0', 0x5593480, '48c7042401000000'), ('a1', 0x5593472, '4c89642408')),
    0x5593581: (('r8', 0x5593572, '41b801000000'), ('r9', 0x559357e, '4989d9'), ('a0', 0x5593569, '48890424'), ('a1', 0x5593564, '0f11442408')),
    0x5593630: (('r8', 0x559362a, '4d89f0'), ('r9', 0x559362d, '4d89e9'), ('a0', 0x5593612, '48c7042400000000')),
    0x5593b3a: (('r8', 0x5593b08, '410f94c0'), ('r9', 0x5593b37, '4531c9'), ('a0', 0x5593b1f, '48c7042401000000'), ('a1', 0x5593b11, '4889442408')),
    0x5593c22: (('r8', 0x5593c11, '41b801000000'), ('r9', 0x5593c1f, '4d89f1'), ('a0', 0x5593c05, '48890424'), ('a1', 0x5593c00, '0f11442408')),
    0x5593ce5: (('r8', 0x5593cdd, '4d89f8'), ('r9', 0x5593ce0, '4c8b4c2428'), ('a0', 0x5593cc2, '48c7042400000000')),
    0x560abd9: (('r8', 0x560abd3, '4531c0'), ('r9', 0x560abd6, '4d89e1'), ('a0', 0x560abb8, '48c7042400000000')),
}


def decode_r8(raw):
    if raw[:2] == b'\x41\xb8' and len(raw) == 6:
        return ('const', struct.unpack_from('<I', raw, 2)[0])
    if raw == b'\x45\x31\xc0':
        return ('const', 0)
    if raw == b'\x41\x0f\x94\xc0':
        return ('sete', (0, 1))
    return ('value', None)


def decode_arg(raw):
    if raw[:4] == b'\x48\xc7\x04\x24' and len(raw) == 8:
        return ('const', struct.unpack_from('<i', raw, 4)[0])
    if raw[:1] == b'\x6a' and len(raw) == 2:
        return ('const', struct.unpack_from('<b', raw, 1)[0])
    return ('value', None)


def classify(r8, a0):
    if r8[0] == 'const' and a0[0] == 'const':
        if r8[1] != a0[1]:
            return 'can-move'
        return 'early-exit' if r8[1] == 0 else 'unresolved'
    if r8[0] == 'sete' and a0[0] == 'const':
        return 'can-move' if any(v != a0[1] for v in r8[1]) else 'unresolved'
    return 'unresolved'


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    calls = direct_calls(data, MOVE)
    if calls != sorted(SITES):
        raise ValueError('move_token call census changed')
    rows = []
    for site, pins in sorted(SITES.items()):
        if read_va(data, site, 1) != b'\xe8':
            raise ValueError(f'call at {site:#x} changed')
        roles = {}
        for role, va, expect in pins:
            fixed(data, va, expect)
            if not 0 < site - va <= 0x120:
                raise ValueError(f'pin {va:#x} is not just before {site:#x}')
            roles[role] = (va, bytes.fromhex(expect))
        r8 = decode_r8(roles['r8'][1])
        a0 = decode_arg(roles['a0'][1]) if 'a0' in roles else ('value', None)
        cls = classify(r8, a0)
        if site == STAGE100_SITE:
            cls = 'early-exit (via #6213 caller)'
        rows.append({
            'site': hex(site),
            'function': hex(frame(fdes, site)),
            'r8': r8[0] if r8[0] != 'const' else r8[1],
            'arg0': a0[0] if a0[0] != 'const' else a0[1],
            'pins': {role: hex(va) for role, (va, _) in sorted(roles.items())},
            'class': cls,
        })
    totals = Counter(r['class'] for r in rows)
    by_fn = {}
    for r in rows:
        by_fn.setdefault(r['function'], Counter())[r['class']] += 1
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'exchange',
        'move_token': {'fn': hex(MOVE), 'early_exit': 'r8 == [rsp+0x1b0] and (r8 == 0 or r9 == [rsp+0x1b8])',
                       'calls': len(calls), 'functions': len(by_fn)},
        'sites': rows,
        'totals': dict(sorted(totals.items())),
        'by_function': {k: dict(sorted(v.items())) for k, v in sorted(by_fn.items())},
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
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
    print('calls=%d totals=%s' % (result['move_token']['calls'], result['totals']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
