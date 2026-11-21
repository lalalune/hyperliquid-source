#!/usr/bin/env python3
"""Bind one node #115 hyperliquidChain map value to its codec tag byte source."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CALLER_FDE = (0x2406120, 0x24064e4)
CALL_SITE = 0x24062c7
CODEC = 0x2674b80
KEY_VA = 0x455a90
KEY = b'hyperliquidChain'
VALUE_FLOW = (0x2406277, 0x24062cc)
VALUE_FLOW_HEX = (
    '498d773041807e1b01753f498b0e498b46104839c10f84ae010000'
    '498b5608c60402b048ffc0498946104829c14883f90f0f86bf010000'
    '0f1005dbf704fe0f1104024883c010498946104889e74c89f2e8b4e82600'
)
KEY_PATH_EDGES = (
    # (instruction VA, instruction bytes, displacement offset, length, target)
    (0x2406280, '753f', 1, 2, 0x24062c1),
    (0x240628c, '0f84ae010000', 2, 6, 0x2406440),
    (0x24062a8, '0f86bf010000', 2, 6, 0x240646d),
)
CAPACITY_PATHS = {
    0x2406440: {
        'end': 0x240646d,
        'bytes': 'ba01000000b90100000041b8010000004c89f74989f54889c6'
                 'e8f27bf1ff4c89ee498b0e498b4610e925feffff',
        'call': 0x2406459,
        'rejoin': 0x2406468,
        'expected_rejoin': 0x2406292,
        'save_rsi': 0x2406453,
        'restore_rsi': 0x240645e,
    },
    0x240646d: {
        'end': 0x240649b,
        'bytes': 'ba10000000b90100000041b8010000004c89f74989f54889c6'
                 'e8c57bf1ff4c89ee498b5608498b4610e913feffff',
        'call': 0x2406486,
        'rejoin': 0x2406496,
        'expected_rejoin': 0x24062ae,
        'save_rsi': 0x2406480,
        'restore_rsi': 0x240648b,
    },
}
TEXT = {
    0x2406277: '498d7730',          # rsi = caller field base + 0x30
    0x240627b: '41807e1b01',        # cmp byte [r14+0x1b], 1
    0x2406280: '753f',              # skip key prefix and join serializer call
    0x2406296: 'c60402b0',          # append fixstr(16)
    0x24062ae: '0f1005dbf704fe',    # load key bytes
    0x24062b5: '0f110402',          # append key bytes
    0x24062c1: '4889e7',            # codec arg 1: scratch result
    0x24062c4: '4c89f2',            # codec arg 3: output vector
    0x24062c7: 'e8b4e82600',         # direct serializer call
    0x2674b87: '0fb60e',             # codec reads byte [rsi] as tag
}


def load_codec():
    path = ROOT / 'tools/re015_chain_codec_115.py'
    spec = importlib.util.spec_from_file_location('chain_codec_115', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extract(data, authenticate=True):
    digest = hashlib.sha256(data).hexdigest()
    if authenticate and digest != TARGET_SHA256:
        raise ValueError(f'target digest mismatch: {digest}')
    secs = sections(data)

    def read_va(va, size, section_name):
        matches = [s for s in secs if s['name'] == section_name and s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError(f'{va:#x}: no unique file-backed {section_name} mapping')
        sec = matches[0]
        off = sec['offset'] + va - sec['address']
        return data[off:off + size]

    observed = {}
    for va, hx in TEXT.items():
        raw = read_va(va, len(bytes.fromhex(hx)), '.text')
        if raw.hex() != hx:
            raise ValueError(f'{va:#x}: instruction bytes changed ({raw.hex()})')
        observed[va] = raw
    flow = read_va(VALUE_FLOW[0], len(bytes.fromhex(VALUE_FLOW_HEX)), '.text')
    if flow.hex() != VALUE_FLOW_HEX:
        raise ValueError('value-source-to-call instruction span changed')
    key_path_edges = []
    for va, hx, disp_offset, insn_len, expected_target in KEY_PATH_EDGES:
        raw = flow[va - VALUE_FLOW[0]:va - VALUE_FLOW[0] + insn_len]
        if raw.hex() != hx:
            raise ValueError(f'{va:#x}: key-path branch bytes changed')
        branch_target = va + insn_len + int.from_bytes(raw[disp_offset:], 'little', signed=True)
        if branch_target != expected_target:
            raise ValueError(f'{va:#x}: key-path branch target changed: {branch_target:#x}')
        key_path_edges.append({'instruction': va, 'bytes_hex': raw.hex(),
                               'target': branch_target})
    capacity_paths = []
    for start, spec in CAPACITY_PATHS.items():
        path_bytes = read_va(start, len(bytes.fromhex(spec['bytes'])), '.text')
        if path_bytes.hex() != spec['bytes']:
            raise ValueError(f'{start:#x}: capacity-fallback instruction span changed')
        save_offset = spec['save_rsi'] - start
        restore_offset = spec['restore_rsi'] - start
        if path_bytes[save_offset:save_offset + 3].hex() != '4989f5':
            raise ValueError(f'{spec["save_rsi"]:#x}: source pointer is not saved in r13')
        if path_bytes[restore_offset:restore_offset + 3].hex() != '4c89ee':
            raise ValueError(f'{spec["restore_rsi"]:#x}: source pointer is not restored from r13')
        call_offset = spec['call'] - start
        call_bytes = path_bytes[call_offset:call_offset + 5]
        call_target = spec['call'] + 5 + struct.unpack('<i', call_bytes[1:])[0]
        if call_target != 0x231e050:
            raise ValueError(f'{spec["call"]:#x}: capacity helper target changed: {call_target:#x}')
        branch_offset = spec['rejoin'] - start
        branch = path_bytes[branch_offset:branch_offset + 5]
        rejoin_target = spec['rejoin'] + 5 + struct.unpack('<i', branch[1:])[0]
        if rejoin_target != spec['expected_rejoin']:
            raise ValueError(f'{spec["rejoin"]:#x}: capacity path rejoin changed: {rejoin_target:#x}')
        capacity_paths.append({'start': start, 'end': spec['end'],
                               'bytes_hex': path_bytes.hex(),
                               'sha256': hashlib.sha256(path_bytes).hexdigest(),
                               'save_rsi': spec['save_rsi'], 'save_rsi_bytes': '4989f5',
                               'restore_rsi': spec['restore_rsi'], 'restore_rsi_bytes': '4c89ee',
                               'call_site': spec['call'], 'call_target': call_target,
                               'rejoin_site': spec['rejoin'],
                               'rejoin_target': rejoin_target})

    call = observed[CALL_SITE]
    target = CALL_SITE + len(call) + struct.unpack('<i', call[1:])[0]
    if target != CODEC:
        raise ValueError(f'call target changed: {target:#x}')
    branch = observed[0x2406280]
    branch_target = 0x2406280 + len(branch) + int.from_bytes(branch[1:], 'little', signed=True)
    if branch_target != 0x24062c1:
        raise ValueError(f'nonmatching path no longer joins serializer call: {branch_target:#x}')
    key_load = observed[0x24062ae]
    key_target = 0x24062ae + len(key_load) + struct.unpack('<i', key_load[3:])[0]
    if key_target != KEY_VA:
        raise ValueError(f'key address changed: {key_target:#x}')
    if read_va(KEY_VA, len(KEY), '.rodata') != KEY:
        raise ValueError('key bytes changed')

    _, fdes = eh_frame_records(data, secs)
    owner = [f for f in fdes if f['start'] <= CALL_SITE < f['end']]
    if len(owner) != 1 or (owner[0]['start'], owner[0]['end']) != CALLER_FDE:
        raise ValueError('caller FDE changed or ambiguous')

    codec = load_codec()
    native = codec.build(data)
    if not native['summary']['reconstruction_matches_all']:
        raise ValueError('chain codec reconstruction does not match target')
    names = [codec.recon_serialize(tag, 64, 0)[0].decode('latin1')
             for tag in range(4)]
    expected_names = ['\xa5Local', '\xa7Sandbox', '\xa7Testnet', '\xa7Mainnet']
    if names != expected_names:
        raise ValueError(f'codec values differ: {names!r}')

    return {
        'target': {'release': 115, 'sha256': digest,
                   'coordinate': 'ELF virtual address'},
        'caller': {'fde': {'start': owner[0]['start'], 'end': owner[0]['end']},
                   'serializer_call_site': CALL_SITE, 'call_target': target},
        'key_prefix_gate': {'compare_instruction': 0x240627b,
                            'tested_byte_offset': 0x1b,
                            'writes_key_prefix_if_byte_equals': 1,
                            'branch_instruction': 0x2406280,
                            'unequal_target': branch_target,
                            'both_paths_reach_serializer_call': True},
        'key_path_edges': key_path_edges,
        'map_entry': {'key': KEY.decode(), 'key_va': KEY_VA,
                      'fixstr_marker_site': 0x2406296,
                      'fixstr_marker': 0xb0,
                      'value_source': {'base_register_at_call': 'r15',
                                       'byte_offset': 0x30,
                                       'pointer_setup_site': 0x2406277,
                                       'codec_input': 'first byte at [rsi]'},
                      'codec_entry': CODEC,
                      'tag_values': [{'tag': tag, 'wire_bytes_hex': names[tag][1:].encode('ascii').hex(),
                                      'wire_name': names[tag][1:]}
                                     for tag in range(4)]},
        'value_flow_span': {'start': VALUE_FLOW[0], 'end': VALUE_FLOW[1],
                            'bytes_hex': flow.hex(),
                            'sha256': hashlib.sha256(flow).hexdigest()},
        'capacity_fallback_paths': capacity_paths,
        'limits': ['The containing FDE is not claimed to be a complete source-function boundary.',
                   'The caller record owner and origin of r15+0x30 are unresolved.',
                   'The byte at r14+0x1b is recorded as a branch predicate only; its source-level meaning is unknown.',
                   'The tag-to-name mapping is inherited from the separately verified chain-codec packet; this packet does not connect it to the global chain selector or a live network.',
                   'Tag bytes outside 0 through 3 are not modeled or claimed.'],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args(argv)
    report = extract(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"verified key={report['map_entry']['key']} source=r15+0x30 tags=4")


if __name__ == '__main__':
    main()
