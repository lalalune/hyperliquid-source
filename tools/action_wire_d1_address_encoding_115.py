#!/usr/bin/env python3
"""Bind the node #115 d1 signing callback slot to the address-encoding field."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
EXPECTED_FDES = {
    0x240eef0: 0x240f26a,
    0x24580c0: 0x245812b,
    0x442d000: 0x442d480,
    0x4428520: 0x44290b4,
    0x4433f90: 0x443431f,
    0x46e6d30: 0x46e6f78,
}
TEXT_WITNESSES = {
    # The SendToEvmWithData payload serializer emits the field before the
    # address-encoding enum using its explicit camel-case name and length 20.
    0x240f185: '4d8b4424504d8b4c2458488d1584e41dfe488d7c2408b9140000004c89f6e868a00400',
    # Its next value serializer receives a field-context pointer at context+0x60.
    0x240f20b: '498d542460488d7c24084c89f6e8a38e0400',
    # Both dispatch arms remove the 8-byte Action tag; serializer arm then calls 0x240eef0.
    0x2bced39: '4883c608',
    0x2bced9e: 'e84d0184ff',
    # The d1 method arm removes the same tag before calling its method slot.
    0x36c3696: '4883c6084c8934240fb6d2488d7c24204989cd4d89c44d89cfff159357e202',
    # The field serializer handles the UnvalidatedBridgeEpoch enum spelling.
    0x24580c0: '41574156534889d3807e0b007429488d05832000feba040000004989fe4889f74989f74889c6e8650619004c89fe4c89f74883f8027519488d154f9619feb90b0000004989d85b415e415fe9a035e1ff48b9000000000000008048890f48894708488957105b415e415fc3',
    # The signing method calls the object stored at +0x60 and passes the
    # adjacent metadata/data fields; its 32-byte return enters the typed record.
    0x442d179: '498b442460498b542468498d742478498b4c2470488d7c2450ff10',
    0x442d194: '0f104424500f104c24600f118c24280100000f11842418010000',
    # The method passes the record whose +0x60 slot holds those 32 returned bytes.
    0x442d30a: '48 8b b4 24 d0 01 00 00 48 8d 7c 24 50 48 8d 94 24 b8 00 00 00 e8 0c 9a 2b 00'.replace(' ', ''),
    # The bridge wrapper forwards the same record pointer to the typed-data wrapper.
    0x46e6d44: '48 8d 7c 24 60 48 89 d6 e8 3f d2 d4 ff'.replace(' ', ''),
    # The typed-data wrapper preserves its input record, then calls the mapped hash helper.
    0x4433fa0: '4989f6',
    0x44340ef: '4c89f6ff1580680b02',
    # The hash helper preserves the record base and dispatches through its +0x60 object.
    0x4428531: '4989f7',
    0x44289b2: '498b4760498b5768498d7778498b4f70488dbc24a0010000ff10',
    # After the indirect callback returns, it reads a pointer/length pair and rejects negative lengths.
    0x44289cc: '4c8bac24a80100004c8ba424b00100004d85e47910',
    # It then invokes the returned object's method at +0x20 with that pointer/length pair.
    0x4428a32: '488b8424a0010000488dbc24b80100004c89ee4c89e2ff5020',
}
RODATA_WITNESSES = {
    0x5ed61a: b'destinationRecipientaddressEncoding',
    0x5f174d: b'UnvalidatedBridgeEpoch',
}
EIP712_TYPE = ('HyperliquidTransaction:SendToEvmWithData('
               'string hyperliquidChain,address payload_multi_sig_user,address outer_signer,'
               'string token,string amount,string source_dex,string destination_recipient,'
               'string address_encoding,uint32 destination_chain_id,uint64 gas_limit,bytes data,uint64 nonce)')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_at(data, section, va, size):
    require(section['address'] <= va and va + size <= section['address'] + section['size'],
            f'{va:#x}: span is outside {section["name"]}')
    offset = section['offset'] + va - section['address']
    require(offset + size <= len(data), f'{va:#x}: span is outside file')
    return data[offset:offset + size]


def extract(data, *, expected_digest=TARGET_SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if expected_digest is not None:
        require(len(data) == TARGET_SIZE and digest == expected_digest,
                f'target size/SHA-256 mismatch: size={len(data)}, sha256={digest}')
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text' and s['type'] != 8)
    rodata = next(s for s in secs if s['name'] == '.rodata' and s['type'] != 8)
    fdes = {fde['start']: fde['end'] for _, rows in [eh_frame_records(data, secs)] for fde in rows}
    for start, end in EXPECTED_FDES.items():
        require(fdes.get(start) == end,
                f'FDE mismatch at {start:#x}: observed {fdes.get(start)!r}, expected {end:#x}')

    instruction_evidence = {}
    for va, witness in TEXT_WITNESSES.items():
        raw = read_at(data, text, va, len(bytes.fromhex(witness)))
        require(raw.hex() == witness, f'instruction witness mismatch at {va:#x}: {raw.hex()}')
        instruction_evidence[hex(va)] = raw.hex()
    literal_evidence = {}
    for va, expected in RODATA_WITNESSES.items():
        raw = read_at(data, rodata, va, len(expected))
        require(raw == expected, f'rodata witness mismatch at {va:#x}: {raw!r}')
        literal_evidence[hex(va)] = raw.decode('ascii')

    schema_path = ROOT / 'research/work-items/action-wire-typed-data-structs-115/eip712.tsv'
    schema_rows = [line.split('\t') for line in schema_path.read_text(encoding='utf-8').splitlines()]
    require(any(len(row) >= 2 and row[0] == '0x44290c0' and row[1] == EIP712_TYPE
                for row in schema_rows), 'existing typed-data evidence lacks the exact d1 builder schema')
    arms_path = ROOT / 'research/work-items/RE-010-action-serialize-tag-dispatch-115/arms.tsv'
    arm_rows = [line.split('\t') for line in arms_path.read_text(encoding='utf-8').splitlines()]
    require(any(len(row) == 11 and row[0] == '0x2bce570' and row[1] == '75'
                and row[4] == 'SendToEvmWithData' and row[9] == '0x240eef0'
                for row in arm_rows), 'existing action serializer evidence lacks the d1 payload serializer binding')

    return {
        'target': {'release': 115, 'size': len(data), 'sha256': digest,
                   'coordinate': 'ELF virtual address'},
        'scope': 'field identity and typed-data handoff for the unresolved d1 action-method callback at variant-input+0x60',
        'fdes': [{'start': hex(a), 'end': hex(b), 'bytes': b - a}
                 for a, b in sorted(EXPECTED_FDES.items())],
        'observations': [
            {'address': '0x240f185', 'fact': 'the serializer context supplies the next field call with 20-byte name at 0x5ed61a and value words from context+0x50/+0x58; the bytes spell destinationRecipient'},
            {'address': '0x240f20b', 'fact': 'the next field-value call passes the serializer-context pointer context+0x60 to 0x24580c0; the adjacent 15 target bytes at 0x5ed61a+20 spell addressEncoding'},
            {'address': '0x2bced39', 'fact': 'the index-75 SendToEvmWithData serializer arm advances RSI by 8 bytes to the variant payload and calls 0x240eef0'},
            {'address': '0x36c3696', 'fact': 'the index-75 d1 method arm also advances RSI by 8 bytes before calling the method slot relocated to 0x442d000'},
            {'address': '0x24580c0', 'fact': 'the selected enum serializer branch passes the 11-byte variant label UnvalidatedBridgeEpoch to its serializer helper'},
            {'address': '0x442d192', 'fact': 'after the d1 arm advances the enum pointer by 8 bytes, the signing method invokes the first function pointer at variant-input+0x60, passing variant-input+0x78 and qwords at +0x68/+0x70; it copies 32 returned bytes into its local typed-data record'},
            {'address': '0x442d30a', 'fact': 'the method passes a local record based at rsp+0xb8 to 0x46e6d30; the 32-byte callback return stored at rsp+0x118 is record+0x60'},
            {'address': '0x46e6d44', 'fact': 'the bridge wrapper passes that record pointer to 0x4433f90'},
            {'address': '0x44340f2', 'fact': '0x4433f90 forwards the unchanged record pointer through relocation slot 0x64ea978 to typed-data hash helper 0x4428520'},
            {'address': '0x44289ca', 'fact': '0x4428520 loads qwords from record+0x60/+0x68/+0x70, passes record+0x78, and invokes the function pointer at the object stored in record+0x60'},
            {'address': '0x44289cc', 'fact': 'after that call, the helper reads qwords from callback-result rsp+0x1a8 and rsp+0x1b0; it sign-checks the latter and routes negative values to an error path'},
            {'address': '0x4428a32', 'fact': 'on the nonnegative path, the helper allocates/copies using the returned pointer and length, then invokes the method at the callback result first-qword object base +0x20 with that pointer and length'},
            {'address': '0x44290c0', 'fact': 'the existing target-bound EIP-712 builder schema orders address_encoding:string immediately after destination_recipient:string and before destination_chain_id:uint32'},
        ],
        'inference': [
            'The serializer and d1 method dispatch tables both bind index 75 to SendToEvmWithData and each arm advances the enum pointer by 8 bytes. Serializer field-name/order evidence places addressEncoding immediately after destinationRecipient; the existing EIP-712 schema places address_encoding in the same relative order. Together these support identifying variant-input+0x60 as the addressEncoding/address_encoding callback field. This is an explicit crosswalk inference: the serializer context pointer at its own +0x60 is not asserted to be the same memory address as the method input.',
            'The 32-byte return from the d1 method callback occupies the address_encoding field slot in the typed-data record and is later consumed as a callable field object by the hash helper. It is not established as a final string hash; the concrete callable target and its output semantics remain unknown.',
            'The hash helper consumes the callback-produced result as an object with a pointer/length pair and a method dispatched at object-base+0x20. This records the observed ABI flow only; it does not establish a Rust-level type or which bytes the callback produces.',
        ],
        'unresolved': [
            'concrete callback/vtable target and the producer that populates variant-input+0x60',
            'the concrete function pointer and behavior of the field object returned by the d1 callback',
            "the returned object's concrete method implementation and the bytes emitted for each address-encoding variant",
            'runtime enum values, production digest, signature verification, replay checks, and error ordering',
        ],
        'instruction_witnesses': instruction_evidence,
        'literal_witnesses': literal_evidence,
        'typed_data_schema': EIP712_TYPE,
        'serializer_binding': {'enum_fde': '0x2bce570', 'variant_index': 75,
                               'variant': 'SendToEvmWithData', 'serializer': '0x240eef0',
                               'evidence': 'RE-010-action-serialize-tag-dispatch-115/arms.tsv'},
        'limitations': [
            'FDE extents are unwind ranges, not source-level function boundaries.',
            'The executable was read statically and was not run or emulated.',
            'The relationship from serializer field order and typed-data field order to the method variant-input offset is an explicit crosswalk inference; serializer-context offsets are a separate base, and no production callback result is claimed.',
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
    print('verified node115 d1 addressEncoding field object handoff into typed-data callback; concrete output remains unresolved')


if __name__ == '__main__':
    main()
