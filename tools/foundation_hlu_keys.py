#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 HLP validator-key loader evidence packet.

This checks retained bytes, relocations and data relationships. It never
executes target code, never reads an operator key file, never decodes a general
function inventory, and makes no reconstruction claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280

# Loader and collector windows are complete FDE extents; the shim is the
# Display callback passed in the loader's format argument.
LOADER = (0x13d2620, 0x13d27c2)
COLLECTOR = (0x13e0720, 0x13e08b3)
SHIM = (0x13da090, 0x13da0a4)
FDES = {  # name: (FDE record VA, CIE VA)
    'loader': (0xfc65ec, 0xfbdc2c),
    'collector': (0xfc70e0, 0xfbdc2c),
    'shim': (0xce6cd4, 0xce1518),
}

# Window SHA-256 values lock every byte; individual operands are decoded below.
WINDOW_SHA256 = {
    'loader': 'e1121208efb5e8d2b69667db7636c16d23f28a36829f9190b3c1bac1bcb0a765',
    'collector': '58abfba0a7ce7e91a5929e51c1e2566a494c64bb67492c6409e9adb6b7aca91e',
    'shim': 'fdec3f6a5bc235a2510c81cd2a260691870eadb6a349f4426077cc56c73fdba7',
}

# R_X86_64_RELATIVE slot -> addend, with all-zero pre-relocation bytes.
RELATIVE = {
    0x577ab08: 0x13d2620,  # .data lazy storage whose initializer is the loader
    0x576ea08: 0x577ab08,  # GOT slot holding that storage address
    0x576e928: 0x577b288,  # GOT slot of the lazy static formatted into the path
    0x577b288: 0x164ff00,  # that static's stored initializer
    0x576e040: 0x1344760,  # formatter called with the template + argument array
    0x576e010: 0x54c8cb0,  # deallocation call used on path/key buffers
    0x576e048: 0x157aa10,  # Result::unwrap failure arm (shared with other packets)
    0x576e108: 0x157b7f0,  # assertion failure arm (shared with other packets)
    0x576e8b8: 0x4ee3b20,  # Once slow path taken when the static is not ready
    0x576e848: 0x13d1960,  # per-key constructor called by the collector
    0x576e000: 0x1573450,  # tail-call target of the Display shim
}

LOCATIONS = [  # record VA, path VA, path, line, column
    (0x5666ce8, 0x1ecb91, b'/home/ubuntu/hl/code_Mainnet/base/src/hlu.rs', 57, 13),
    (0x5666d00, 0x1ecb91, b'/home/ubuntu/hl/code_Mainnet/base/src/hlu.rs', 58, 18),
    (0x5666d18, 0x1ecb91, b'/home/ubuntu/hl/code_Mainnet/base/src/hlu.rs', 61, 13),
    (0x5666a68, 0x1f87cf,
     b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sync/once.rs', 219, 20),
]

MESSAGES = [
    (0x216e5d, b'assertion failed: keys.len() >= N_HLP_REQUIRED_VALIDATORS'),
    (0x216f9d, b'called `Result::unwrap()` on an `Err` value'),
]
TEMPLATE_VA = 0x1f881c
PATH_LITERAL = b'/hyperliquid_data/main_validator_keys.json'

# Instruction byte locks at validated instruction starts (see boundaries.json).
INSTRUCTIONS = {
    0x13d2630: '4c8b35f1c23904',            # mov r14, [rip -> 0x576e928]
    0x13d2637: '418b4650',                  # mov eax, [r14+0x50]
    0x13d2643: '4983c618',                  # add r14, 0x18 (argument = static+0x18)
    0x13d264b: '488d053e7a0000',            # lea rax, Display shim 0x13da090
    0x13d2657: '488d35be61e2fe',            # lea rsi, template 0x1f881c
    0x13d2676: '488d0d6b462904',            # lea rcx, location hlu.rs:57:13
    0x13d2683: 'e8c8bb0700',                # call reader 0x144e250
    0x13d268f: '48f7d8',                    # neg rax (rax = returned capacity)
    0x13d2692: '0f8095000000',              # jo unwrap arm
    0x13d26b7: '4983fd01',                  # cmp r13, 1 (r13 = returned length)
    0x13d26bb: '0f869d000000',              # jbe assertion arm
    0x13d26c1: '49c1e505',                  # shl r13, 5
    0x13d26e4: 'e837e00000',                # call collector 0x13e0720
    0x13d271d: 'be01000000',                # esi = 1 for the Once slow path
    0x13d2737: '488d3d5f48e4fe',            # lea rdi, unwrap message
    0x13d2751: 'be2b000000',                # message length 43
    0x13d275e: '488d3df846e4fe',            # lea rdi, assertion message
    0x13d2765: '488d15ac452904',            # lea rdx, location hlu.rs:61:13
    0x13d276c: 'be39000000',                # message length 57
    0x13e0742: '48b86028afa1bc86f21a',      # capacity guard immediate
    0x13e0763: '48c1eb05',                  # shr rbx, 5 (input stride)
    0x13e0767: '4c69e398000000',            # imul r12, rbx, 0x98 (output stride)
    0x13e07da: 'ff1568e03804',              # call [rip -> 0x576e848]
    0x13e07e0: '4883c520',                  # add rbp, 0x20
    0x13e07e4: 'ba98000000',                # copy size 0x98
    0x13e07f5: '4981c798000000',            # add r15, 0x98
}

# Code sites loading the lazy-storage GOT slot. A REX.W 8b/8d rip-relative
# byte-pattern scan, validated by disassembly; not a complete xref census.
STORAGE_SLOT_LOADS = [0x13cd07d, 0x14b1501]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rip_target(va, raw, disp_offset):
    return va + len(raw) + struct.unpack_from('<i', raw, disp_offset)[0]


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'Ambiguous or unmapped VA {va:#x}')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    windows = {}
    for name, (start, end) in [('loader', LOADER), ('collector', COLLECTOR), ('shim', SHIM)]:
        body = read(start, end - start)
        windows[name] = dict(start_va=hex(start), end_va_exclusive=hex(end), bytes=len(body),
                             sha256=hashlib.sha256(body).hexdigest())
        require(windows[name]['sha256'] == WINDOW_SHA256[name], f'{name} instruction window changed')

    for va, raw in INSTRUCTIONS.items():
        require(read(va, len(raw) // 2).hex() == raw, f'Instruction at {va:#x} changed')

    # FDE records: pcrel/sdata4 initial PC and range must equal the windows.
    for name, (fde_va, cie_va) in FDES.items():
        start, end = dict(loader=LOADER, collector=COLLECTOR, shim=SHIM)[name]
        length, cie_pointer = struct.unpack('<II', read(fde_va, 8))
        require(length not in (0, 0xffffffff), 'Unexpected FDE length form')
        require(fde_va + 4 - cie_pointer == cie_va, f'{name} FDE CIE pointer changed')
        pc = fde_va + 8 + struct.unpack('<i', read(fde_va + 8, 4))[0]
        extent = struct.unpack('<I', read(fde_va + 12, 4))[0]
        require((pc, pc + extent) == (start, end), f'{name} FDE PC/range changed')

    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    raw = read(relsec['address'], relsec['size'])
    rels, by_addend = {}, {}
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
        if info == 8:
            by_addend.setdefault(addend, []).append(address)
    for slot, target in RELATIVE.items():
        require(rels.get(slot) == (8, target), f'Relative relocation at {slot:#x} changed')
        require(read(slot, 8) == b'\0' * 8, 'Unexpected pre-relocation pointer')
    require(by_addend.get(LOADER[0]) == [0x577ab08], 'Relative references to the loader changed')
    require(by_addend.get(0x577ab08) == [0x576ea08], 'Relative references to the lazy storage changed')

    # RIP-relative operands decoded from the locked instruction bytes.
    def target(va, disp_offset):
        raw = bytes.fromhex(INSTRUCTIONS[va])
        return rip_target(va, raw, disp_offset)

    require(target(0x13d2630, 3) == 0x576e928, 'Static slot operand changed')
    require(target(0x13d264b, 3) == SHIM[0], 'Display shim operand changed')
    require(target(0x13d2657, 3) == TEMPLATE_VA, 'Template operand changed')
    require(target(0x13d2676, 3) == 0x5666ce8, 'Reader location operand changed')
    require(target(0x13d2683, 1) == 0x144e250, 'Reader call target changed')
    require(target(0x13d26e4, 1) == COLLECTOR[0], 'Collector call target changed')
    require(target(0x13d2737, 3) == 0x216f9d, 'Unwrap message operand changed')
    require(target(0x13d275e, 3) == 0x216e5d, 'Assertion message operand changed')
    require(target(0x13d2765, 3) == 0x5666d18, 'Assertion location operand changed')
    require(target(0x13e07da, 2) == 0x576e848, 'Per-key constructor slot changed')
    require(target(0x13d26bb, 2) == 0x13d275e, 'Assertion branch target changed')

    locations = []
    for address, string_va, path, line, column in LOCATIONS:
        require(rels.get(address) == (8, string_va), 'Location path relocation changed')
        length, actual_line, actual_column = struct.unpack('<QII', read(address + 8, 16))
        require((length, actual_line, actual_column) == (len(path), line, column), 'Location layout changed')
        require(read(string_va, length) == path, 'Location path changed')
        locations.append(dict(location_va=hex(address), path_va=hex(string_va),
                              path=path.decode(), line=line, column=column))
    for va, message in MESSAGES:
        require(read(va, len(message)) == message, 'Error message changed')
    lengths = {0x216f9d: INSTRUCTIONS[0x13d2751], 0x216e5d: INSTRUCTIONS[0x13d276c]}
    for va, message in MESSAGES:
        require(struct.unpack('<I', bytes.fromhex(lengths[va])[1:])[0] == len(message),
                'Message length operand changed')
    template = read(TEMPLATE_VA, 2 + len(PATH_LITERAL))
    require(template[0] == 0xc0 and template[1] == len(PATH_LITERAL) and template[2:] == PATH_LITERAL,
            'Format template changed')

    # Operands that carry the claimed numeric facts.
    threshold = bytes.fromhex(INSTRUCTIONS[0x13d26b7])[3]
    key_shift = bytes.fromhex(INSTRUCTIONS[0x13d26c1])[3]
    input_shift = bytes.fromhex(INSTRUCTIONS[0x13e0763])[3]
    output_stride = struct.unpack('<I', bytes.fromhex(INSTRUCTIONS[0x13e0767])[3:])[0]
    guard = struct.unpack('<Q', bytes.fromhex(INSTRUCTIONS[0x13e0742])[2:])[0]
    require(threshold == 1 and key_shift == 5 and input_shift == 5, 'Length/stride operands changed')
    require(output_stride == 0x98, 'Output element stride changed')
    require(guard == ((1 << 63) - 1) // output_stride << input_shift, 'Capacity guard relation changed')
    once_flag = struct.unpack('<I', bytes.fromhex(INSTRUCTIONS[0x13d271d])[1:])[0]
    require(once_flag == 1, 'Once slow-path flag changed')

    # Byte-pattern scans of .text. Explicitly NOT a complete xref census.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct, loads = [], []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code) and text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0] == LOADER[0]:
            direct.append(text['address'] + pos)
        pos += 1
    for i in range(len(code) - 7):
        if code[i] in (0x48, 0x4c) and code[i + 1] in (0x8b, 0x8d) and code[i + 2] & 0xc7 == 0x05:
            if text['address'] + i + 7 + struct.unpack_from('<i', code, i + 3)[0] == 0x576ea08:
                loads.append(text['address'] + i)
    require(direct == [], 'Direct call candidates to the loader changed')
    require(loads == STORAGE_SLOT_LOADS, 'Lazy-storage slot load candidates changed')

    return dict(
        target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
        windows=windows,
        fde_records={k: dict(fde_va=hex(v[0]), cie_va=hex(v[1])) for k, v in FDES.items()},
        loader=dict(
            inferred_label='HLP validator wallet loader (lazy initializer)',
            lazy_storage_va='0x577ab08', storage_got_slot='0x576ea08',
            path_format=dict(template_va=hex(TEMPLATE_VA), template_prefix_bytes=['0xc0', hex(len(PATH_LITERAL))],
                             literal=PATH_LITERAL.decode(), argument='String at static 0x577b288 + 0x18',
                             argument_display_shim=hex(SHIM[0]), argument_static_initializer='0x164ff00',
                             argument_contents='not established'),
            reader_call=dict(target='0x144e250', track_caller_location='hlu.rs:57:13'),
            err_test='neg/jo on returned capacity: Err iff capacity == i64::MIN',
            assertion=dict(compare='unsigned len <= 1 panics', minimum_len=threshold + 1),
            key_stride_bytes=1 << key_shift,
            collector=dict(target=hex(COLLECTOR[0]), input_stride_bytes=1 << input_shift,
                           output_stride_bytes=output_stride, capacity_guard=hex(guard),
                           per_key_constructor_slot='0x576e848', per_key_constructor='0x13d1960'),
            once_slow_path=dict(target='0x4ee3b20', esi=once_flag, location='once.rs:219:20'),
        ),
        relative_relocations={hex(k): hex(v) for k, v in RELATIVE.items()},
        source_locations=locations,
        incoming_pattern_scan=dict(section='.text', byte_count=len(code), e8_candidates=direct,
                                   relative_addends_to_loader=['0x577ab08'],
                                   storage_slot_load_candidates=list(map(hex, loads)),
                                   complete_xref_census=False),
        captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256, 'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        require(result == json.loads(args.check.read_text()), 'Retained evidence differs')
        print('Foundation HLU validator-key evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
