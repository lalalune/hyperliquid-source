#!/usr/bin/env python3
"""Optional native cross-check for RE-001-consumer-call-closure-94.

Decodes the pinned extent with Capstone 5.0.6 (not the project runtime) and
checks instruction-boundary claims that the stdlib byte scan cannot establish:
complete contiguous coverage of the 909 bytes, the caller sites as decoded
``call`` instructions, and the raw ``E8`` candidates that are not calls.

Usage:
    python verify_native.py [--listing PATH]
"""
import argparse
import bisect
import json
from pathlib import Path
import struct
import sys

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'tools'))
import bincode_varint as bv
import consumer_call_closure as cc

EXPECTED_INSTRUCTIONS = 218
EXPECTED_INTERNAL_CALLS = ((0x1455C50, 0x13F2570), (0x1455EAA, 0x13EDC40),
                           (0x1455F1D, 0x13EDC40), (0x1455F6B, 0x14540B0),
                           (0x1455F73, 0x5660110), (0x1455F80, 0x14540B0),
                           (0x1455F88, 0x5660110))
EXPECTED_BYTE_SCAN_NON_CALLS = (0x1455D61, 0x1455E2D)


def disassemble(code, start):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return list(md.disasm(code, start))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=bv.TARGET)
    parser.add_argument('--listing', type=Path)
    args = parser.parse_args()
    if capstone.__version__ != '5.0.6':
        raise SystemExit(f'capstone 5.0.6 required, found {capstone.__version__}')

    data = args.binary.read_bytes()
    secs = bv.sections(data)
    fdes = bv.fde_extents(data, secs)
    start = cc.TARGET
    end = fdes[start]
    body = data[bv.va_to_off(secs, start):bv.va_to_off(secs, start) + (end - start)]
    instructions = disassemble(body, start)
    covered = sum(ins.size for ins in instructions)
    if len(instructions) != EXPECTED_INSTRUCTIONS or covered != end - start:
        raise SystemExit(f'decode covers {covered} bytes in {len(instructions)} instructions')
    if instructions[-1].address + instructions[-1].size != end:
        raise SystemExit('decoded extent does not end at the FDE end')

    internal = [(ins.address, ins.operands[0].imm) for ins in instructions
                if ins.mnemonic == 'call' and ins.operands and ins.operands[0].type == X86_OP_IMM]
    if tuple(internal) != EXPECTED_INTERNAL_CALLS:
        raise SystemExit(f'decoded internal calls changed: {[hex(a) for a, _ in internal]}')

    byte_sites = [start + index for index, byte in enumerate(body) if byte == 0xE8]
    decoded_sites = {site for site, _ in internal}
    non_calls = tuple(site for site in byte_sites if site not in decoded_sites)
    if non_calls != EXPECTED_BYTE_SCAN_NON_CALLS:
        raise SystemExit(f'byte-scan false positives changed: {[hex(x) for x in non_calls]}')

    text = secs['.text']
    text_bytes = data[text['offset']:text['offset'] + text['size']]
    for row in cc.scan(data)['direct_callers']:
        site = int(row['site_va'], 16)
        fde_start = int(row['fde_start_va'], 16)
        fde_end = int(row['fde_end_va'], 16)
        decoded = disassemble(text_bytes[fde_start - text['addr']:fde_end - text['addr']], fde_start)
        starts = {ins.address for ins in decoded}
        if site not in starts:
            raise SystemExit(f'caller {site:#x} is not a decoded instruction start')
        if sum(ins.size for ins in decoded) != fde_end - fde_start:
            raise SystemExit(f'caller FDE {fde_start:#x} does not decode contiguously')
        match = [ins for ins in decoded if ins.address == site]
        if len(match) != 1 or match[0].mnemonic != 'call' or match[0].operands[0].imm != cc.TARGET:
            raise SystemExit(f'caller {site:#x} is not a decoded call to 0x{cc.TARGET:x}')

    operand_sites = {int(row['site_va'], 16) for row in cc.scan(data)['indirect_operands']}
    if not operand_sites <= {ins.address for ins in instructions}:
        raise SystemExit('an indirect operand site is not an instruction start')

    listing = ''.join(f'{ins.address:x}: {ins.bytes.hex()}  {ins.mnemonic} {ins.op_str}\n'.rstrip() + '\n'
                      for ins in instructions)
    if args.listing:
        args.listing.write_bytes(listing.encode())
    print(json.dumps({
        'capstone': capstone.__version__,
        'instructions': len(instructions),
        'decoded_bytes': covered,
        'internal_calls': [hex(site) for site, _ in internal],
        'byte_scan_sites': [hex(site) for site in byte_sites],
        'byte_scan_non_calls': [hex(x) for x in non_calls],
        'caller_sites_decoded': 6,
        'listing_sha256': __import__('hashlib').sha256(listing.encode()).hexdigest(),
    }, indent=2))


if __name__ == '__main__':
    main()
