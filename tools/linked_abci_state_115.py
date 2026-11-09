#!/usr/bin/env python3
"""Bind the node #115 linked abci state step after the snapshot label (32nd stage).

Continues RE-008-freeze-snapshot-115 (#5970) and RE-008-fast-abci-engine-115
(#5925). After 0x5a08720 picks its snapshot label it calls 0x5485f80 at
0x5a0887e. This tool binds:

1. the label argument: r13b set selects `freeze` (0x93a687, 6 bytes), clear
   selects `periodic` (0x458f30, 8 bytes); the length is (r13b ^ 1) * 2 + 6;
2. in 0x5485f80: the label is stored at rsp+0x160/0x168, the height is
   [[rsi]+0x28], and the function calls in order
   - 0x38d8240 (slot 0x64e4f30) with the height: it formats `{}/data/{}`
     with `periodic_abci_state_statuses` and `{}/{}/{}`;
   - 0x5942870 with `abci_state` (10 bytes): it formats
     `{}/hyperliquid_data/{}` and `{}.{}` with `rmp` or `json`;
   - 0x4e45a30 with edx = 1; its 0x38-byte result is what 0x5485f80 returns;
   - 0x1505a50 (slot 0x64e09e0) with Location l1/src/abci/state.rs:201:9;
     a non-zero result panics with Result::unwrap at state.rs:201:32;
   - 0x38d7f20 (slot 0x64e4f38) with the periodic path and the abci_state
     path; it formats `utils_hard_link_and_replace/{}`; a returned boxed
     error is dropped through its vtable, not reported;
   - the WARN template 0x448ef9 through slot 0x64e0ae8, whose [desc: ]
     argument is the label, [periodic_fln: ] the 0x38d8240 path, [fln: ] the
     abci_state path and [height: ] the height.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, frame, read_va, relative_relocations, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-linked-abci-state-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

STEP = 0x5a08720
LINKED = 0x5485f80
PERIODIC_PATH = 0x38d8240
DATA_PATH = 0x5942870
BLOCKING = 0x4e45a30
STATE_CALL = 0x1505a50
HARD_LINK = 0x38d7f20
LOGGER = 0x5c9b830

LABELS = {'freeze': 0x93a687, 'periodic': 0x458f30}
STRINGS = {
    0x929ae3: b'abci_state',
    0x929aed: b'%Y-%m-%dT%H:%M:%S%.3fZ',
    0x929b03: b'linked abci stateassertion failed: ',  # one 0x23-byte slice
    0x7a1586: b'periodic_abci_state_statuses',
    0x9382b9: b'rmp',
    0x459f60: b'json',
}
TEMPLATES = {
    0x448b77: b'\xc0\x06/data/\xc0\x00',
    0x440e47: b'\xc0\x01/\xc0\x01/\xc0\x00',
    0x44f615: b'\xc0\x12/hyperliquid_data/\xc0\x00',
    0x43d024: b'\xc0\x01.\xc0\x00',
    0x439e43: b'\x1cutils_hard_link_and_replace/\xc0\x00',
    0x448ef9: (b'\xc0\n WARN >>> \xc0\x04 @@ \xc0\x0b @@ [desc: \xc0\x13] @ [periodic_fln: \xc0\n]'
               b' @ [fln: \xc0\r] @ [height: \xc0\x03]\n\n'),
}
STATE_RS = 0x443168
LOCATIONS = {0x64aa230: (201, 9), 0x64aa248: (201, 32)}
SLOTS = {0x64e4f30: PERIODIC_PATH, 0x64e09e0: STATE_CALL, 0x64e4f38: HARD_LINK, 0x64e0ae8: LOGGER,
         0x646ea00: 0x7a1586, 0x64aa220: 0x929ae3, 0x64aa230: STATE_RS, 0x64aa248: STATE_RS}

FIXED = {
    # caller 0x5a08720: label choice
    0x5a08853: '4489e8',                # mov eax, r13d
    0x5a08856: '3401',                  # xor al, 1
    0x5a08858: '0fb6c0',                # movzx eax, al
    0x5a0885b: '488d0c4506000000',      # lea rcx, [rax*2+6]            (len 6 or 8)
    0x5a08871: '4584ed',                # test r13b, r13b
    0x5a08874: '480f45d0',              # cmovne rdx, rax               (set -> freeze)
    0x5a08878: '4889e7',                # mov rdi, rsp                  (out)
    0x5a0887b: '4c89e6',                # mov rsi, r12
    # 0x5485f80: label, height
    0x5485f97: '4889942460010000',      # mov [rsp+0x160], rdx          (label ptr)
    0x5485f9f: '48898c2468010000',      # mov [rsp+0x168], rcx          (label len)
    0x5485fa7: '488b06',                # mov rax, [rsi]
    0x5485faa: '488b7028',              # mov rsi, [rax+0x28]           (height)
    0x5485fae: '4889b424e8000000',      # mov [rsp+0xe8], rsi
    0x5486046: 'ba01000000',            # mov edx, 1
    0x54860a6: '4885c0',                # test rax, rax
    0x54860a9: '0f857f020000',          # jne 0x548632e                 (unwrap panic)
    0x54860af: '488b7c2428',            # mov rdi, [rsp+0x28]           (periodic path ptr)
    0x54860b4: '488b742430',            # mov rsi, [rsp+0x30]           (len)
    0x54860b9: '488b9424d8000000',      # mov rdx, [rsp+0xd8]           (abci_state path ptr)
    0x54860c1: '488b8c24e0000000',      # mov rcx, [rsp+0xe0]
    0x54860cf: '4885c0',                # test rax, rax
    0x54860d2: '7408',                  # je 0x54860dc
    0x54860d4: '488b08',                # mov rcx, [rax]
    0x54860d7: '4889c7',                # mov rdi, rax
    0x54860da: 'ff11',                  # call [rcx]                    (drop boxed error)
    0x548612b: '48c784243801000016000000',  # len 0x16 of the time format
    0x548617b: '48c78424c800000023000000',  # len 0x23 of the 0x929b03 slice
    0x5486187: '488d842460010000',      # lea rax, [rsp+0x160]          (label)
    0x548618f: '48898424f0000000',      # mov [rsp+0xf0], rax           (desc arg)
    0x5486197: '4889ac24f8000000',      # mov [rsp+0xf8], rbp           (periodic_fln arg)
    0x548619f: '48899c2400010000',      # mov [rsp+0x100], rbx          (fln arg)
    0x54861a7: '488d8424e8000000',      # lea rax, [rsp+0xe8]           (height)
    0x54861af: '4889842408010000',      # mov [rsp+0x108], rax          (height arg)
    0x548634d: 'be2b000000',            # mov esi, 0x2b                 (unwrap message len)
    # return: the 0x38-byte result of 0x4e45a30
    0x548629b: '488b0424',
    0x548629f: '498907',
    0x54862a7: '49894708',
    0x54862b3: '410f114710',
    0x54862bd: '49894720',
    0x54862c9: '410f114728',
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x5a08863, b'\x48\x8d\x05', 7, LABELS['freeze']),
    (0x5a0886a, b'\x48\x8d\x15', 7, LABELS['periodic']),
    (0x5a0887e, b'\xe8', 5, LINKED),
    (0x5485fbb, b'\xff\x15', 6, 0x64e4f30),
    (0x5485fee, b'\x48\x8d\x35', 7, 0x64aa220),
    (0x5486000, b'\xe8', 5, DATA_PATH),
    (0x548604b, b'\xe8', 5, BLOCKING),
    (0x5486091, b'\x48\x8d\x15', 7, 0x64aa230),
    (0x54860a0, b'\xff\x15', 6, 0x64e09e0),
    (0x54860c9, b'\xff\x15', 6, 0x64e4f38),
    (0x548611c, b'\x48\x8d\x05', 7, 0x929aed),
    (0x548616c, b'\x48\x8d\x05', 7, 0x929b03),
    (0x5486267, b'\x48\x8d\x3d', 7, 0x448ef9),
    (0x5486273, b'\xff\x15', 6, 0x64e0ae8),
    (0x5486341, b'\x4c\x8d\x05', 7, 0x64aa248),
    (0x38d82c0, b'\x48\x8d\x05', 7, 0x646ea00),
    (0x38d82d8, b'\x48\x8d\x35', 7, 0x448b77),
    (0x38d8328, b'\x48\x8d\x35', 7, 0x440e47),
    (0x38d7fc7, b'\x48\x8d\x35', 7, 0x439e43),
    (0x59428b4, b'\x48\x8d\x15', 7, 0x9382b9),
    (0x59428bb, b'\x48\x8d\x0d', 7, 0x459f60),
    (0x594293f, b'\x48\x8d\x35', 7, 0x43d024),
    (0x5942979, b'\x48\x8d\x35', 7, 0x44f615),
)


def location(data, va):
    """Rust core::panic::Location: (&'static str file, line u32, col u32); file pointer by relocation."""
    raw = read_va(data, va, 24)
    length = int.from_bytes(raw[8:16], 'little')
    line = int.from_bytes(raw[16:20], 'little')
    col = int.from_bytes(raw[20:24], 'little')
    return length, line, col


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, text in {**STRINGS, **TEMPLATES}.items():
        if read_va(data, va, len(text)) != text:
            raise ValueError(f'string at {va:#x} changed')
    for name, va in LABELS.items():
        if read_va(data, va, len(name)) != name.encode():
            raise ValueError(f'label {name} changed')
    if read_va(data, STATE_RS, 20) != b'l1/src/abci/state.rs':
        raise ValueError('state.rs path changed')
    for va, (line, col) in LOCATIONS.items():
        if location(data, va) != (20, line, col):
            raise ValueError(f'Location {va:#x} changed')
    # &str lengths stored beside the two relocated string pointers
    if int.from_bytes(read_va(data, 0x64aa228, 8), 'little') != 10:
        raise ValueError('abci_state length changed')
    if int.from_bytes(read_va(data, 0x646ea08, 8), 'little') != 28:
        raise ValueError('periodic_abci_state_statuses length changed')
    for va, fn in ((0x5a0887e, STEP), (0x5486000, LINKED), (0x38d82d8, PERIODIC_PATH),
                   (0x38d7fc7, HARD_LINK), (0x5942979, DATA_PATH)):
        if frame(fdes, va) != fn:
            raise ValueError(f'{va:#x} left its function')
    callers = direct_calls(data, LINKED)

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'label_choice': {
            'site': hex(0x5a0887e),
            'freeze': '%s (6 bytes) when r13b != 0' % hex(LABELS['freeze']),
            'periodic': '%s (8 bytes) when r13b == 0' % hex(LABELS['periodic']),
            'length': 'rcx = (r13b ^ 1) * 2 + 6',
        },
        'linked_state_fn': {
            'fn': hex(LINKED),
            'direct_callers': [hex(v) for v in callers],
            'args': 'rdi = 0x38-byte result, rsi = holder whose [0] is the box, (rdx, rcx) = label',
            'height': '[[rsi]+0x28] at 0x5485faa, kept at rsp+0xe8',
            'calls_in_order': [
                '%s slot 0x64e4f30 (height): {}/data/{} with periodic_abci_state_statuses, then {}/{}/{}'
                % hex(PERIODIC_PATH),
                '%s (abci_state): {}/hyperliquid_data/{} and {}.{} with rmp or json' % hex(DATA_PATH),
                '%s (edx = 1): its 0x38-byte result is returned at 0x548629b..0x54862cd' % hex(BLOCKING),
                '%s slot 0x64e09e0, Location state.rs:201:9; non-zero -> Result::unwrap panic state.rs:201:32'
                % hex(STATE_CALL),
                '%s slot 0x64e4f38 (periodic path, abci_state path): utils_hard_link_and_replace/{}; '
                'a returned boxed error is dropped via its vtable at 0x54860da' % hex(HARD_LINK),
                '%s slot 0x64e0ae8 with WARN template 0x448ef9' % hex(LOGGER),
            ],
            'warn_args': {
                'desc': 'label (rsp+0x160)',
                'periodic_fln': 'rsp+0x20, the 0x38d8240 path',
                'fln': 'rsp+0xd0, the abci_state path',
                'height': 'rsp+0xe8',
                'time_format': '0x929aed %Y-%m-%dT%H:%M:%S%.3fZ (0x16 bytes)',
                'slice_0x929b03': '0x23 bytes: "linked abci state" then "assertion failed: "',
            },
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
    print('linked callers=%s' % result['linked_state_fn']['direct_callers'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
