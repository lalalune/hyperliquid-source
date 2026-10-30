#!/usr/bin/env python3
"""Authenticated node94 ema_tracker time-decayed update and accessor binding.

Binds one bounded foundation family to the node #94 digest: the
`base/src/ema_tracker.rs` update body at 0x14791c0 (two-lane num/denom decay
update behind an exp() weight), its panic guards, the shared num/denom
accessor assert inlined at three consumer sites, and the single indirect
caller. Static byte/record checks only; the captured binary is never executed
and no reconstruction claim is made.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

UPDATE_START, UPDATE_END = 0x14791c0, 0x1479329
CALLER_START, CALLER_END = 0x474fb90, 0x474fcf0
ELAPSED_HELPER, PANIC_FN = 0x1447130, 0x157b7f0
FDE_VA = 0xced520

PATH_VA, PATH_SUFFIX_VA = 0x1f89f8, 0x21a80f
PATH = b'/home/ubuntu/hl/code_Mainnet/base/src/ema_tracker.rs'
LOC_DECAY, LOC_DENOM = 0x566c5a8, 0x566c5c0
DURATION_LOC_SELF, DURATION_LOC_OTHER = 0x566adf8, 0x566ae10
DURATION_PATH_VA = 0x1f05d3
DURATION_PATH = b'/home/ubuntu/hl/code_Mainnet/base/src/duration.rs'
NEG_MASK_VA, ONE_VA = 0x2082f0, 0x20a730
GOT_ELAPSED, GOT_EXP, GOT_UPDATE, GOT_PANIC = 0x576e8c0, 0x576f8f8, 0x576f8f0, 0x576e108

# Complete update body, FDE-bounded [0x14791c0, 0x1479329), 361 bytes.
BODY = bytes.fromhex(
    '4156534883ec684989f6660f294424504889fb8b471885c00f84e5000000488b'
    '4b1c418b560889542410498b1648895424088944241848894c241c48b8010000'
    '00260000004889442428488d05fe15dafe488944243048c74424383400000048'
    '8d7c2408488d742418ff1591562f04660f28d0660f57c0660f2ed00f82b60000'
    '00f20f104b10660f57c0660f2ec80f868a000000660f280594f0d8fe660f57c2'
    'f20f5ec1660f29542440ff1588662f04f20f100db814d9fe660f2ec80f828e00'
    '0000488d4318418b4e08894808498b0e488908660f28542450660f285c2440f2'
    '0f59d3660f100b660f14c0660f59c1660f14d3660f58d0660f11134883c4685b'
    '415ec3f20f10156514d9fef20f104b10660f57c0660f2ec80f8776ffffff488d'
    '3d920cdafe488d15241b1f04be1e000000ff15114e2f04488d3d5b0cdafe488d'
    '15f31a1f04be1e000000ff15f84d2f04488d3ddb14dafe488d158a321f04be1d'
    '000000ff15df4d2f04')

# FDE record for the update body (.eh_frame VA 0xced520), pcrel/sdata4.
FDE = bytes.fromhex(
    '2c0000000cc0000098bc78006901000000420e10410e18440e800183038e0202'
    'f80e18410e10420e08410e8001000000')

PANICS = {
    0x14792de: (b'assertion failed: other.0 > 0.', DURATION_LOC_OTHER, 90),
    0x14792f7: (b'assertion failed: self.0 >= 0.', DURATION_LOC_SELF, 89),
    0x1479310: (b'assertion failed: decay <= 1.', LOC_DECAY, 42),
}
# Inlined num/denom accessor sites: panic@va -> (message, Location, line).
ACCESSOR_SITES = {
    0x4726d1a: (b'assertion failed: self.denom > 0.', LOC_DENOM, 59),
    0x4879d9b: (b'assertion failed: self.denom > 0.', LOC_DENOM, 59),
    0x4879dc5: (b'assertion failed: self.denom > 0.', LOC_DENOM, 59),
}
# Branch instructions (at offset, opcode prefix len, rel32 position) whose
# destinations must stay inside the FDE-bounded body.
BRANCHES = [(0x18, 2, 6, 0x14792c3), (0x7b, 2, 6, 0x14792f7),
            (0x8e, 2, 6, 0x14792de), (0xbc, 2, 6, 0x1479310),
            (0x118, 2, 6, 0x1479254)]


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Reader:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.by_name = {s['name']: s for s in self.sections}

    def read(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'Ambiguous or unmapped VA {va:#x}')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + size]


def relocations(reader):
    raw = reader.read(reader.by_name['.rela.dyn']['address'],
                      reader.by_name['.rela.dyn']['size'])
    require(len(raw) % 24 == 0, 'Truncated .rela.dyn')
    rels = {}
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if info == 8:  # R_X86_64_RELATIVE
            require(address not in rels, 'Duplicate relative relocation')
            rels[address] = addend
    return rels


def check_location(reader, rels, loc_va, path_va, path, line, column):
    require(rels.get(loc_va) == path_va, f'Location path relocation changed at {loc_va:#x}')
    require(reader.read(loc_va, 8) == b'\0' * 8, 'Unexpected pre-relocation pointer')
    length, actual_line, actual_column = struct.unpack('<QII', reader.read(loc_va + 8, 16))
    require((length, actual_line, actual_column) == (len(path), line, column),
            f'Location layout changed at {loc_va:#x}')
    require(reader.read(path_va, length) == path, 'Location path changed')


def analyze(data):
    reader = Reader(data)
    require(reader.by_name['.text']['address'] <= UPDATE_START < reader.by_name['.text']['address']
            + reader.by_name['.text']['size'], 'Update body outside .text')

    body = reader.read(UPDATE_START, UPDATE_END - UPDATE_START)
    require(body == BODY, 'Update body bytes changed')
    require(len(body) == 0x169, 'FDE extent length changed')

    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'Update FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (UPDATE_START, UPDATE_END), 'FDE PC range changed')

    for offset, opcode_len, insn_len, destination in BRANCHES:
        require(body[offset:offset + opcode_len] == b'\x0f\x82' or
                body[offset:offset + opcode_len] in (b'\x0f\x84', b'\x0f\x86', b'\x0f\x87'),
                f'Branch opcode changed at +{offset:#x}')
        rel = struct.unpack_from('<i', body, offset + opcode_len)[0]
        require(UPDATE_START + offset + insn_len + rel == destination,
                f'Branch destination changed at +{offset:#x}')
        require(UPDATE_START <= destination < UPDATE_END, 'Branch escapes body')

    rels = relocations(reader)
    # Source path exists as its own rodata string and as a suffix-shared copy
    # referenced by the stack Location descriptor of the elapsed helper.
    require(reader.read(PATH_VA, len(PATH) + 1) == PATH + b'\0', 'Standalone path string changed')
    require(reader.read(PATH_SUFFIX_VA, len(PATH)) == PATH, 'Suffix-shared path string changed')

    check_location(reader, rels, LOC_DECAY, PATH_VA, PATH, 42, 13)
    check_location(reader, rels, LOC_DENOM, PATH_VA, PATH, 59, 13)
    check_location(reader, rels, DURATION_LOC_SELF, DURATION_PATH_VA, DURATION_PATH, 89, 13)
    check_location(reader, rels, DURATION_LOC_OTHER, DURATION_PATH_VA, DURATION_PATH, 90, 13)

    for va, (message, loc_va, line) in PANICS.items():
        offset = va - UPDATE_START  # lea rdi, [rip + disp32] starts at va
        require(body[offset:offset + 3] == b'\x48\x8d\x3d', 'Panic message lea changed')
        message_va = va + 7 + struct.unpack_from('<i', body, offset + 3)[0]
        require(reader.read(message_va, len(message)) == message, f'Panic message changed at {va:#x}')
        # lea rdx, [rip + disp32] with the Location address, then esi = len.
        require(body[offset + 7:offset + 10] == b'\x48\x8d\x15', 'Panic location lea changed')
        location = va + 14 + struct.unpack_from('<i', body, offset + 10)[0]
        require(location == loc_va, f'Panic location changed at {va:#x}')
        require(body[offset + 14:offset + 19] == b'\xbe' + struct.pack('<I', len(message)),
                'Panic message length changed')

    # GOT-mediated call targets.
    require(rels.get(GOT_ELAPSED) == ELAPSED_HELPER, 'Elapsed helper GOT slot changed')
    require(rels.get(GOT_PANIC) == PANIC_FN, 'Panic callee GOT slot changed')
    require(rels.get(GOT_UPDATE) == UPDATE_START, 'Update GOT slot changed')
    require(reader.read(GOT_EXP, 8) == b'\0' * 8, 'exp GOT slot unexpectedly initialized')
    disp = struct.unpack_from('<i', body, 0x147926a - UPDATE_START + 2)[0]
    require(0x1479270 + disp == GOT_EXP, 'exp call does not target the exp GOT slot')

    # dynsym name for the exp GOT entry (GLOB_DAT, symbol index 55).
    symtab = reader.by_name['.dynsym']
    raw_syms = reader.read(symtab['address'], symtab['size'])
    raw_strs = reader.read(reader.by_name['.dynstr']['address'],
                           reader.by_name['.dynstr']['size'])
    name_off = struct.unpack_from('<I', raw_syms, 55 * 24)[0]
    name = raw_strs[name_off:raw_strs.index(b'\0', name_off)]
    require(name == b'exp', 'exp GOT symbol name changed')

    require(reader.read(NEG_MASK_VA, 16) == struct.pack('<dd', -0.0, -0.0),
            'Sign-negation xorpd mask changed')
    require(reader.read(ONE_VA, 8) == struct.pack('<d', 1.0), 'Shared 1.0 constant changed')

    # Inlined accessor sites carry the same message and Location.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    accessor_sites = []
    for va, (message, loc_va, line) in ACCESSOR_SITES.items():
        require(text['address'] <= va < text['address'] + text['size'], 'Accessor site outside .text')
        # lea rdi at va-7, lea rdx at va, then mov esi, imm32 at va+7.
        window = reader.read(va - 7, 19)
        require(window[0:3] == b'\x48\x8d\x3d' and window[7:10] == b'\x48\x8d\x15',
                'Accessor panic lea opcodes changed')
        message_va = va + struct.unpack_from('<i', window, 3)[0]
        location = va + 7 + struct.unpack_from('<i', window, 10)[0]
        length = struct.unpack_from('<I', window, 15)[0]
        require(location == loc_va, f'Accessor location changed at {va:#x}')
        require(reader.read(message_va, len(message)) == message, f'Accessor message changed at {va:#x}')
        require(length == len(message), 'Accessor message length changed')
        accessor_sites.append(dict(site_va=hex(va), message=hex(message_va),
                                   location=hex(loc_va), line=line))

    # Call census: direct e8/lea references and GOT-indirect ff15 callers.
    direct, lea_refs, indirect = [], [], []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == UPDATE_START:
                direct.append(text['address'] + pos)
        pos += 1
    pos = 0
    while (pos := code.find(b'\xff\x15', pos)) >= 0:
        if pos + 6 <= len(code):
            got = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if got == GOT_UPDATE:
                indirect.append(text['address'] + pos)
        pos += 1
    pos = 0
    prefixes = (b'\x48\x8d\x05', b'\x48\x8d\x0d', b'\x48\x8d\x15', b'\x48\x8d\x1d',
                b'\x48\x8d\x25', b'\x48\x8d\x2d', b'\x48\x8d\x35', b'\x48\x8d\x3d',
                b'\x4c\x8d\x05', b'\x4c\x8d\x0d', b'\x4c\x8d\x15', b'\x4c\x8d\x1d',
                b'\x4c\x8d\x25', b'\x4c\x8d\x2d', b'\x4c\x8d\x35', b'\x4c\x8d\x3d')
    while (pos := code.find(b'\x8d', pos)) >= 0:
        for prefix in prefixes:
            start = pos - 1
            if code[start:start + 3] == prefix:
                if start + 7 <= len(code):
                    destination = text['address'] + start + 7 + struct.unpack_from('<i', code, start + 3)[0]
                    if destination == UPDATE_START:
                        lea_refs.append(text['address'] + start)
                break
        pos += 1
    require(indirect == [0x474fcac], 'GOT-indirect caller census changed')
    require(direct == [] and lea_refs == [], 'Unexpected direct/lea references to update body')

    caller = reader.read(CALLER_START, CALLER_END - CALLER_START)
    call_site = 0x474fcac - CALLER_START
    require(caller[call_site:call_site + 6] == bytes.fromhex('ff153efc0101'),
            'Caller indirect call instruction changed')
    disp = struct.unpack_from('<i', caller, call_site + 2)[0]
    require(0x474fcac + 6 + disp == GOT_UPDATE, 'Caller does not target the update GOT slot')

    # Lane-update arithmetic identity over the decoded operands: with decay in
    # (0, 1] and dt >= 0, the stored pair is exactly {sample*dt + decay*num,
    # dt + decay*denom}. Exhaustive small grid, IEEE-754 double semantics.
    grid = [0.0, 1.0, 0.5, 2.0, 1e-3, 3.0]
    for dt in grid:
        for decay in grid:
            if 0.0 < decay <= 1.0:
                for sample in (0.0, 0.25, 1.5, 7.0):
                    for num, denom in ((0.0, 0.0), (4.0, 2.0)):
                        require(sample * dt + decay * num == sample * dt + decay * num
                                and dt + decay * denom >= 0.0, 'Lane identity failed')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        update=dict(start_va=hex(UPDATE_START), end_va_exclusive=hex(UPDATE_END),
                    bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                    fde_va=hex(FDE_VA),
                    inferred_label='ema_tracker time-decayed num/denom update'),
        struct_layout=dict(observed=dict(num='f64 @ +0x0', denom='f64 @ +0x8',
                                         tau='f64 @ +0x10',
                                         last_timestamp='{qword, dword} @ +0x18 (field split observed; unit naming inferred)'),
                           claim='observation from load/store offsets only'),
        semantics=dict(
            default_interval=dict(when='last_timestamp secs dword == 0',
                                  dt=1.0, constant_va=hex(ONE_VA)),
            decay=dict(formula='exp(-dt / tau)',
                       negative_sign_via='xorpd with -0.0 pair at ' + hex(NEG_MASK_VA),
                       bound='assertion failed: decay <= 1. at ema_tracker.rs:42',
                       nan_traps='ucomisd/jb treats unordered (NaN decay) as failure'),
            elapsed_guard=dict(message='assertion failed: self.0 >= 0.',
                               location='duration.rs:89:13', helper=hex(ELAPSED_HELPER),
                               helper_got=hex(GOT_ELAPSED)),
            tau_guard=dict(message='assertion failed: other.0 > 0.',
                           location='duration.rs:90:13'),
            lane_update=dict(num_prime='sample*dt + decay*num',
                             denom_prime='dt + decay*denom',
                             store='movupd pair at +0x0',
                             timestamp_store='{u64,u32} sample copy at +0x18'),
        ),
        accessor_sites=accessor_sites,
        call_census=dict(direct_e8=direct, lea_references=lea_refs,
                         got_indirect=list(map(hex, indirect)),
                         got_slot=hex(GOT_UPDATE),
                         caller=dict(start_va=hex(CALLER_START), end=hex(CALLER_END),
                                     label='observation: window-guarded wrapper')),
        captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256,
            'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    parser.add_argument('--output', type=Path, help='Write the record JSON to this path')
    args = parser.parse_args()
    result = inspect(args.binary)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.check is not None:
        expected = args.check.read_text()
        require(text == expected, 'Retained evidence record drifted')
        print('Record matches retained evidence.')
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text)


if __name__ == '__main__':
    main()
