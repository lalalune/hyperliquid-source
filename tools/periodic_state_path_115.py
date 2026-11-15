#!/usr/bin/env python3
"""Bind the node #115 periodic abci state paths and the blocking wrapper (33rd stage).

Continues the linked abci state step 0x5485f80 (open PR #5999). That step reads
the height at [[rsi]+0x28], builds two paths with 0x38d8240 (slot 0x64e4f30),
builds an abci_state path with 0x5942870, and calls 0x4e45a30 with edx = 1.
This tool binds:

1. 0x38d8240: date = now (0x1629690 via slot 0x64e0990) converted by 0x1629fb0
   (slot 0x64e0ab8, edx = 0); a zero date panics with the 43-byte message
   "Local time out of range for `NaiveDateTime`" (Location 0x63fc160, chrono
   datetime/mod.rs 579:14). It returns two Strings:
   +0x0  from 0x38d8100 (slot 0x64e9568): {root}/data/periodic_abci_states then
         template 0x432d1a "{}/{}/{}.rmp" with (dir, date, height);
   +0x18 {root}/data/periodic_abci_state_statuses then template 0x440e47
         "{}/{}/{}" with (dir, date, height).
   The date is displayed by 0x150ce90 with the 6-byte chrono format "%Y%m%d"
   (0x465bc9); the height by 0x1689420 (slot 0x64e0a98).
2. 0x5942870: extension "rmp" (0x9382b9, 3 bytes) only when the name is the
   10 bytes "abci_state", else "json" (0x459f60, 4 bytes); file = "{}.{}"
   (0x43d024); path = "{}/hyperliquid_data/{}" (0x44f615) with the root.
3. 0x4e45a30: edx == 0 calls 0x4e363c0 directly; otherwise it first calls
   0x5aa1020 (Location base/src/u.rs:531:9) and runs 0x4e363c0 between
   thread-local runtime context changes whose panics name the vendored
   tokio/src/runtime/context/runtime_mt.rs (28:9 and 17:17).

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (SHA256, RELATIVE, TARGET, direct_calls, fixed, frame, read_va,
                                 relative_relocations, rip_target, text)

PACKET = ROOT / 'research/work-items/RE-008-periodic-state-path-115'

STEP, PATHS, RMP_PATH, STATE_PATH, WRAPPER, INNER = 0x5485f80, 0x38d8240, 0x38d8100, 0x5942870, 0x4e45a30, 0x4e363c0
DATE_FMT, BLOCKING = 0x150ce90, 0x5aa1020

FIXED = {
    # 0x5485f80: height, paths, abci_state path, wrapper with edx = 1
    0x5485faa: '488b7028',              # mov rsi, [rax+0x28]           (height)
    0x5485fbb: 'ff156fef0501',          # call [slot 0x64e4f30]         (0x38d8240)
    0x5486000: 'e86bc84b00',            # call 0x5942870
    0x5486046: 'ba01000000',            # mov edx, 1
    0x548604b: 'e8e0f99bff',            # call 0x4e45a30
    # 0x38d8240: date, zero check, height string
    0x38d8274: 'ff153e88c002',          # call [slot 0x64e0ab8]         (date of now)
    0x38d827a: '8b542408',              # mov edx, [rsp+8]
    0x38d827e: '85d2',                  # test edx, edx
    0x38d8280: '0f8408010000',          # je 0x38d838e                  (panic)
    0x38d828f: '4c89fe',                # mov rsi, r15                  (height)
    0x38d8292: 'ff15d012c102',          # call [slot 0x64e9568]         (0x38d8100)
    0x38d839c: 'be2b000000',            # mov esi, 43
    # 0x38d8240 second format: (dir, date, height)
    0x38d8306: '488b055b88c002',        # mov rax, [slot 0x64e0b68]     (date Display)
    0x38d831c: '488b057587c002',        # mov rax, [slot 0x64e0a98]     (u64 Display)
    # 0x5942870: name == "abci_state" -> rmp, else json
    0x594288d: '48837e080a',            # cmp qword [rsi+8], 10
    0x5942892: '7576',                  # jne 0x594290a                 (json)
    0x5942897: '48b9616263695f737461', # movabs rcx, "abci_sta"
    0x59428a8: '4881f274650000',        # xor rdx, "te"
    0x59428c2: '480f44ca',              # cmove rcx, rdx                (rmp)
    0x59428c9: '4883c003',              # add rax, 3                    (len 3 or 4)
    0x594290a: 'b804000000',            # mov eax, 4
    # 0x150ce90: chrono format items "%Y%m%d"
    0x150cebe: '48c744243806000000',    # mov qword [rsp+0x38], 6
    # 0x4e45a30: flag test
    0x4e45a3f: '85d2',                  # test edx, edx
    0x4e45a41: '747b',                  # je 0x4e45abe                  (direct)
    0x4e45ac9: 'e8f208ffff',            # call 0x4e363c0
}
REFERENCES = (
    (0x5485fee, b'\x48\x8d\x35', 7, 0x64aa220),    # &"abci_state"
    (0x38d82c0, b'\x48\x8d\x05', 7, 0x646ea00),    # &"periodic_abci_state_statuses"
    (0x38d82d8, b'\x48\x8d\x35', 7, 0x448b77),     # "{}/data/{}"
    (0x38d8328, b'\x48\x8d\x35', 7, 0x440e47),     # "{}/{}/{}"
    (0x38d838e, b'\x48\x8d\x3d', 7, 0x465ab7),     # NaiveDateTime message
    (0x38d8395, b'\x48\x8d\x15', 7, 0x63fc160),    # chrono Location
    (0x38d813f, b'\x48\x8d\x05', 7, 0x646e9f0),    # &"periodic_abci_states"
    (0x38d81ab, b'\x48\x8d\x35', 7, 0x432d1a),     # "{}/{}/{}.rmp"
    (0x59428b4, b'\x48\x8d\x15', 7, 0x9382b9),     # "rmp"
    (0x59428bb, b'\x48\x8d\x0d', 7, 0x459f60),     # "json"
    (0x594290f, b'\x48\x8d\x0d', 7, 0x459f60),     # "json"
    (0x594293f, b'\x48\x8d\x35', 7, 0x43d024),     # "{}.{}"
    (0x5942979, b'\x48\x8d\x35', 7, 0x44f615),     # "{}/hyperliquid_data/{}"
    (0x150ceb2, b'\x48\x8d\x05', 7, 0x465bc9),     # "%Y%m%d"
    (0x4e45a50, b'\x48\x8d\x15', 7, 0x649db00),    # base/src/u.rs:531:9
    (0x4e45bdc, b'\x48\x8d\x15', 7, 0x649fc78),    # runtime_mt.rs:28:9
    (0x4e45bf1, b'\x48\x8d\x15', 7, 0x64c5bc0),    # runtime_mt.rs:17:17
)
RELOCATIONS = {
    0x64e4f30: PATHS, 0x64e9568: RMP_PATH, 0x64e0990: 0x1629690, 0x64e0ab8: 0x1629fb0,
    0x64e0b68: DATE_FMT, 0x64e0a98: 0x1689420, 0x64aa220: 0x929ae3, 0x646ea00: 0x7a1586,
    0x646e9f0: 0x7a1572, 0x63fc160: 0x448b23, 0x649db00: 0x442e9e, 0x649fc78: 0x43499d,
    0x64c5bc0: 0x43499d,
}
STRINGS = {
    0x929ae3: b'abci_state', 0x7a1586: b'periodic_abci_state_statuses', 0x7a1572: b'periodic_abci_states',
    0x448b77: b'\xc0\x06/data/\xc0\x00', 0x440e47: b'\xc0\x01/\xc0\x01/\xc0\x00',
    0x432d1a: b'\xc0\x01/\xc0\x01/\xc0\x04.rmp', 0x43d024: b'\xc0\x01.\xc0\x00',
    0x44f615: b'\xc0\x12/hyperliquid_data/\xc0\x00', 0x9382b9: b'rmp', 0x459f60: b'json',
    0x465bc9: b'%Y%m%d', 0x465ab7: b'Local time out of range for `NaiveDateTime`',
    0x442e9e: b'base/src/u.rs', 0x43499d: b'/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/context/runtime_mt.rs',
}
LOCATIONS = {  # va: (file string, length, line, column)
    0x649db00: (0x442e9e, 13, 531, 9),
    0x649fc78: (0x43499d, 77, 28, 9),
    0x64c5bc0: (0x43499d, 77, 17, 17),
    0x63fc160: (0x448b23, 64, 579, 14),
}


def slot_calls(data, slot):
    base, code = text(data)
    return [base + m.start() for m in re.finditer(rb'\xff\x15', code)
            if m.start() + 6 <= len(code)
            and base + m.start() + 6 + struct.unpack_from('<i', code, m.start() + 2)[0] == slot]


def str_name(data, rel, ref):
    ptr = rel[ref]
    length = struct.unpack('<Q', read_va(data, ref + 8, 8))[0]
    return read_va(data, ptr, length)


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    for va, (file_va, length, line, col) in LOCATIONS.items():
        raw = read_va(data, va, 24)
        _, flen, fline, fcol = struct.unpack('<QQII', raw)
        if (rel.get(va), flen, fline, fcol) != (file_va, length, line, col):
            raise ValueError(f'Location at {va:#x} changed')
    names = {va: str_name(data, rel, ref).decode() for va, ref in ((0x5485fee, 0x64aa220),
                                                                   (0x38d82c0, 0x646ea00),
                                                                   (0x38d813f, 0x646e9f0))}
    if names[0x5485fee] != 'abci_state' or names[0x38d82c0] != 'periodic_abci_state_statuses' \
            or names[0x38d813f] != 'periodic_abci_states':
        raise ValueError('path names changed')
    census = {
        '0x38d8240 via slot 0x64e4f30': len(slot_calls(data, 0x64e4f30)),
        '0x38d8100 via slot 0x64e9568': len(slot_calls(data, 0x64e9568)),
        '0x5942870 direct': [hex(v) for v in direct_calls(data, STATE_PATH)],
        '0x4e45a30 direct': [hex(v) for v in direct_calls(data, WRAPPER)],
        '0x4e363c0 direct': [hex(v) for v in direct_calls(data, INNER)],
    }
    if census['0x4e45a30 direct'] != ['0x548604b'] or census['0x4e363c0 direct'] != ['0x4e45ac9', '0x4e45b69']:
        raise ValueError('wrapper call census changed')
    extents = {hex(a): hex(frame(fdes, a)) for a in (STEP, PATHS, RMP_PATH, STATE_PATH, WRAPPER, INNER)}
    for a, start in extents.items():
        if a != start:
            raise ValueError(f'{a} is not an FDE start')

    def ext(name):
        return 'rmp' if name == 'abci_state' else 'json'

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'fde_starts': sorted(extents),
        'periodic_paths': {
            'builder': hex(PATHS) + ' (slot 0x64e4f30)',
            'date': 'now via slot 0x64e0990 -> 0x1629690; date via slot 0x64e0ab8 -> 0x1629fb0 (edx 0); '
                    'zero -> panic "Local time out of range for `NaiveDateTime`" (chrono datetime/mod.rs:579:14)',
            'date_format': '0x150ce90 chrono items "%Y%m%d" (6 bytes at 0x465bc9)',
            'height_format': 'slot 0x64e0a98 -> 0x1689420',
            'result_plus_0x0': '{root}/data/periodic_abci_states/{%Y%m%d}/{height}.rmp (0x38d8100, slot 0x64e9568)',
            'result_plus_0x18': '{root}/data/periodic_abci_state_statuses/{%Y%m%d}/{height}',
        },
        'state_path': {
            'builder': hex(STATE_PATH),
            'rule': 'name length 10 and bytes "abci_state" -> rmp (3 bytes); else json (4 bytes)',
            'file': '{name}.{ext} (0x43d024)',
            'path': '{root}/hyperliquid_data/{file} (0x44f615)',
            'from_step': 'abci_state -> {root}/hyperliquid_data/abci_state.' + ext('abci_state'),
            'samples': {n: ext(n) for n in ('abci_state', 'abci_states', 'visor_abci_state', '')},
        },
        'wrapper': {
            'fn': hex(WRAPPER),
            'flag_0': 'call 0x4e363c0 directly (0x4e45a41 je)',
            'flag_nonzero': 'call 0x5aa1020 (base/src/u.rs:531:9), then run 0x4e363c0 between thread-local '
                            'runtime context changes; panic Locations name tokio runtime/context/runtime_mt.rs '
                            '(28:9, 17:17)',
            'step_passes': 'edx = 1 (0x5486046)',
        },
        'census': census,
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
    print('state_path:', result['state_path']['from_step'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
