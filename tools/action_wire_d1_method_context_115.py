#!/usr/bin/env python3
"""Trace the node #115 d1 action-method dispatch and its signing-wrapper handoff."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SLOT_TARGETS = {
    0x64e8e48: 0x442d000,
    0x64ea978: 0x4428520,
    0x64ea980: 0x44290c0,
}
EXPECTED_FDES = {
    0x36c3180: 0x36c5348,
    0x442d000: 0x442d480,
    0x46e6d30: 0x46e6f78,
    0x4433f90: 0x443431f,
}
WITNESSES = {
    # Variant index 75 / nominal tag 0xd1 arm: preserve arg7, narrow edx,
    # advance the payload pointer and call slot 0x64e8e48.
    0x36c3696: '4883c6084c8934240fb6d2488d7c24204989cd4d89c44d89cfff159357e202',
    # Caller checks the target method's 16-bit result discriminator against 0x1a2.
    0x36c36b5: '0fb74424200f104424220f29842490020000',
    0x442d000: '554157415641554154534881ec9801',
    # Load the nested dynamic-call operands from the method input and call its first slot.
    0x442d179: '498b442460498b542468498d742478498b4c2470488d7c2450ff10',
    # Copy the dynamic call's two 16-byte output lanes into a 32-byte local record.
    0x442d194: '0f104424500f104c24600f118c24280100000f11842418010000',
    # Forward incoming arg7 as RSI, the local record as RDX, then direct-call 0x46e6d30.
    0x442d30a: '488bb424d0010000488d7c2450488d9424b8000000e80c9a2b00',
    # Branch on the wrapper tag and materialize the successful 0x1a2 result form.
    0x442d324: '807c245001750f488b4424584889430866b97e00eb550fb74424556689442474',
    # The intermediate caller forwards its result record to wrapper 0x4433f90.
    0x46e6d30: '415741564154534881ec380100004989f64889fb488d7c24604889d6e8',
    0x46e6d4c: 'e83fd2d4ff',
    # Wrapper reaches the relocated digest helper; its relocation reaches builder 0x44290c0.
    0x44340ef: '4c89f6ff1580680b02',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_offset(data, sec, va, size):
    require(sec['address'] <= va and va + size <= sec['address'] + sec['size'],
            f'{va:#x}: span is outside {sec["name"]}')
    offset = sec['offset'] + va - sec['address']
    require(offset + size <= len(data), f'{va:#x}: span is outside the file')
    return offset


def relocation_targets(data, secs, wanted):
    matches = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    require(len(matches) == 1, 'expected one file-backed .rela.dyn')
    section = matches[0]
    entry_size = 24
    require(section['size'] % entry_size == 0, '.rela.dyn size is not a multiple of Elf64_Rela')
    found = {}
    for pos in range(section['offset'], section['offset'] + section['size'], entry_size):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot not in wanted:
            continue
        require(slot not in found, f'duplicate relocation at {slot:#x}')
        require((info & 0xffffffff) == 8 and (info >> 32) == 0,
                f'{slot:#x}: expected symbol-free R_X86_64_RELATIVE')
        found[slot] = addend
    require(found == wanted, f'relocation target mismatch: {found!r}')
    return [{'slot': hex(slot), 'relocation_type': 'R_X86_64_RELATIVE', 'addend': hex(target)}
            for slot, target in sorted(found.items())]


def extract(data, *, expected_digest=TARGET_SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if expected_digest is not None:
        require(len(data) == TARGET_SIZE and digest == expected_digest,
                f'target size/SHA-256 mismatch: size={len(data)}, sha256={digest}')

    secs = sections(data)
    text_sections = [s for s in secs if s['name'] == '.text' and s['type'] != 8]
    require(len(text_sections) == 1, 'expected one file-backed .text section')
    text = text_sections[0]
    fde_map = {fde['start']: fde['end'] for _, fdes in [eh_frame_records(data, secs)] for fde in fdes}
    for start, end in EXPECTED_FDES.items():
        require(fde_map.get(start) == end,
                f'FDE mismatch at {start:#x}: observed {fde_map.get(start)!r}, expected {end:#x}')

    observed = {}
    for va, expected_hex in WITNESSES.items():
        raw = data[file_offset(data, text, va, len(bytes.fromhex(expected_hex))):
                   file_offset(data, text, va, len(bytes.fromhex(expected_hex))) + len(bytes.fromhex(expected_hex))]
        require(raw.hex() == expected_hex, f'instruction witness mismatch at {va:#x}: {raw.hex()}')
        observed[hex(va)] = raw.hex()

    relocations = relocation_targets(data, secs, SLOT_TARGETS)
    return {
        'target': {'release': 115, 'size': len(data), 'sha256': digest,
                   'coordinate': 'ELF virtual address'},
        'scope': 'one d1 action-method dispatch, its nested callback boundary, and the digest-wrapper handoff',
        'text': {'address': hex(text['address']), 'file_offset': hex(text['offset']), 'size': text['size']},
        'fdes': [{'start': hex(start), 'end': hex(end), 'bytes': end - start}
                 for start, end in sorted(EXPECTED_FDES.items())],
        'reused_action_binding': {
            'index': 75, 'nominal_tag': '0xd1', 'rust_variant': 'SendToEvmWithData',
            'wire_name': 'sendToEvmWithData', 'source_file': 'RE-017-node115-action-admission-binding/bindings.tsv',
            'dispatch_arm_source': 'PR #7082, action-wire-variant-methods-115/arms.tsv',
        },
        'dispatch': {
            'call_site': '0x36c36af', 'slot': '0x64e8e48', 'relocated_target': '0x442d000',
            'register_arguments': {
                'rdi': 'address of local 16-bit-result/record output at caller rsp+0x20',
                'rsi': 'incoming payload pointer advanced by 8 bytes',
                'rdx': 'zero-extended incoming dl',
                'rcx': 'incoming rcx preserved', 'r8': 'incoming r8 preserved', 'r9': 'incoming r9 preserved',
            },
            'stack_argument_7': 'incoming r14 stored at caller rsp before the indirect call',
            'post_call': 'reads a 16-bit result at caller rsp+0x20 and compares it with 0x1a2',
        },
        'method': {
            'entry': '0x442d000',
            'nested_indirect_call': {
                'site': '0x442d192', 'target': 'first qword loaded from input+0x60',
                'arguments': {
                    'rdi': 'local output at method rsp+0x50',
                    'rsi': 'address input+0x78', 'rdx': 'qword input+0x68', 'rcx': 'qword input+0x70',
                },
                'output': 'copies 32 bytes from local rsp+0x50..0x70 to local rsp+0x118..0x138',
            },
            'intermediate_call': {
                'site': '0x442d31f', 'target': '0x46e6d30',
                'arguments': {
                    'rdi': 'local 16-bit-result/record output at method rsp+0x50',
                    'rsi': 'incoming stack argument 7 (loaded from method rsp+0x1d0)',
                    'rdx': 'address of local record at method rsp+0xb8',
                },
            },
            'wrapper_result': {
                'wrapper': '0x4433f90', 'caller': '0x46e6d4c',
                'tag_branch': 'tag 1 follows the 0x7e result path; any other tag follows the 0x1a2 record path',
            },
            'digest_chain': [
                {'slot': '0x64ea978', 'target': '0x4428520'},
                {'slot': '0x64ea980', 'target': '0x44290c0'},
                {'builder_type': 'HyperliquidTransaction:SendToEvmWithData(string hyperliquidChain,address payload_multi_sig_user,address outer_signer,string token,string amount,string source_dex,string destination_recipient,string address_encoding,uint32 destination_chain_id,uint64 gas_limit,bytes data,uint64 nonce)',
                 'source_file': 'action-wire-typed-data-structs-115/eip712.tsv'},
            ],
        },
        'instruction_witnesses': observed,
        'relocations': relocations,
        'claim_boundary': {
            'observed': [
                'the d1 arm calls the relocated method target 0x442d000',
                'the method reads a callback pointer from input+0x60 and calls it with the recorded operands',
                'the method forwards a local record and incoming stack argument 7 into 0x46e6d30',
                '0x46e6d30 calls wrapper 0x4433f90, which reaches the mapped digest helper and builder',
            ],
            'unresolved': [
                'concrete nested callback target and source object producer',
                'meaning of the callback-produced 32-byte object',
                'actual runtime field values and production digest',
                'signature verification and replay/nonce behavior',
            ],
        },
        'limitations': [
            'FDE extents are unwind ranges and do not prove source-level function identity.',
            'This is static byte/relocation evidence; the captured executable was not run or emulated.',
            'No signature, production digest, or private-key behavior is claimed.',
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args(argv)
    report = extract(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f"verified tag=0xd1 method=0x442d000 callback=unresolved digest-wrapper=0x4433f90")


if __name__ == '__main__':
    main()
