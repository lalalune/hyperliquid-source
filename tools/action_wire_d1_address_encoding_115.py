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
}
TEXT_WITNESSES = {
    # The SendToEvmWithData payload serializer emits the field before the
    # address-encoding enum using its explicit camel-case name and length 20.
    0x240f185: '4d8b4424504d8b4c2458488d1584e41dfe488d7c2408b9140000004c89f6e868a00400',
    # Its next value serializer receives &payload+0x60 and is 0x24580c0.
    0x240f20b: '498d542460488d7c24084c89f6e8a38e0400',
    # The field serializer handles the UnvalidatedBridgeEpoch enum spelling.
    0x24580c0: '41574156534889d3807e0b007429488d05832000feba040000004989fe4889f74989f74889c6e8650619004c89fe4c89f74883f8027519488d154f9619feb90b0000004989d85b415e415fe9a035e1ff48b9000000000000008048890f48894708488957105b415e415fc3',
    # The signing method calls the object stored at +0x60 and passes the
    # adjacent metadata/data fields; its 32-byte return enters the typed record.
    0x442d179: '498b442460498b542468498d742478498b4c2470488d7c2450ff10',
    0x442d194: '0f104424500f104c24600f118c24280100000f11842418010000',
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
        'scope': 'field identity for the unresolved d1 action-method callback at payload+0x60',
        'fdes': [{'start': hex(a), 'end': hex(b), 'bytes': b - a}
                 for a, b in sorted(EXPECTED_FDES.items())],
        'observations': [
            {'address': '0x240f185', 'fact': 'payload serializer passes name bytes at 0x5ed61a with length 20 and value words from payload+0x50/+0x58; the bytes spell destinationRecipient'},
            {'address': '0x240f20b', 'fact': 'the immediately following serializer call passes payload+0x60 to 0x24580c0; the adjacent 15 target bytes at 0x5ed61a+20 spell addressEncoding'},
            {'address': '0x2bced39', 'fact': 'the action enum record at 0x2bce570 binds variant index 75 / SendToEvmWithData to payload serializer 0x240eef0'},
            {'address': '0x24580c0', 'fact': 'the selected enum serializer branch passes the 11-byte variant label UnvalidatedBridgeEpoch to its serializer helper'},
            {'address': '0x442d192', 'fact': 'the d1 signing method invokes the first function pointer stored at payload+0x60, passing payload+0x78 and qwords at +0x68/+0x70; it copies 32 returned bytes into its local typed-data record'},
            {'address': '0x44290c0', 'fact': 'the existing target-bound EIP-712 builder schema orders address_encoding:string immediately after destination_recipient:string and before destination_chain_id:uint32'},
        ],
        'inference': [
            'The serializer call order, contiguous field-name bytes, enum variant serializer, and EIP-712 field order identify the payload+0x60 value as the addressEncoding/address_encoding field.',
            'The callback in the signing method is associated with that field. The schema type string makes a 32-byte string-hash interpretation plausible, but the concrete callback target and output meaning are not established here.',
        ],
        'unresolved': [
            'concrete callback/vtable target and the producer that populates payload+0x60',
            'whether the callback output equals the EIP-712 string hash of the selected variant',
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
            'The relationship from serializer order to the named field is an explicit inference; no production callback result is claimed.',
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
    print('verified node115 d1 payload+0x60 => addressEncoding enum; callback output remains unresolved')


if __name__ == '__main__':
    main()
