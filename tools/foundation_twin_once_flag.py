#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 twin once-flag evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.

The two windows are [0x15080c0, 0x150811b), 91 bytes, and [0x15081b0,
0x1508202), 82 bytes, followed by five and fourteen int3 padding bytes.
Each implements an observed 0/1/2 flag state machine around one atomic swap:
the first reads its flag byte from the incoming sil byte, the second reads
the byte at 8(rdi) after loading the pointer at [rdi] into rbx. Both share
one global-slot check, one tiny TLS-zero-test callee, and one tail jump
through the imported syscall slot with immediates (202, 129, 1). No stdlib
type or source-level function name is claimed for either window.
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
T1_START, T1_END = 0x15080c0, 0x150811b
T2_START, T2_END = 0x15081b0, 0x1508202
T1 = bytes.fromhex(
    '534080fe02742140f6c6017512488b054c662604488b0048d1e04885c0752631c08707'
    '83f80274025bc34889febfca000000ba81000000b90100000031c05bff253b692604488'
    '9fbff158a6a26044889df84c075cac6470401ebc4')
T2 = bytes.fromhex(
    '53488b1f807f08007512488b055f652604488b0048d1e04885c0752631c0870383f80274'
    '025bc3bfca0000004889deba81000000b90100000031c05bff254e682604ff15a0692604'
    '84c075d0c6430401ebca')
CALLEE_START, CALLEE_END = 0x4eef080, 0x4eef08e
CALLEE = bytes.fromhex('6448833c25d8fbffff000f94c0c3')
GLOBAL_SLOT = 0x576e720
GLOBAL_CELL = 0x5788598
CALL_SLOT = 0x576eb98
SYSCALL_SLOT = 0x576ea40
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
T1_FDE = bytes.fromhex('2000000004360100a03581005b00000000410e108302680e08410e10550e08460e100000')
T2_FDE = bytes.fromhex('20000000283601006c3681005200000000410e108302650e08410e10550e08460e100000')
CALLEE_FDE = bytes.fromhex('10000000540d280010cef8030e00000000000000')
GLOBAL_INFO = 0x8
CALL_INFO = 0x8
SYSCALL_INFO = 0x1300000006


def require(condition, message):
    if not condition:
        raise ValueError(message)


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    w1 = read(T1_START, T1_END - T1_START)
    require(w1 == T1, 'Twin 1 window changed')
    require(len(w1) == 91, 'Twin 1 length changed')
    w2 = read(T2_START, T2_END - T2_START)
    require(w2 == T2, 'Twin 2 window changed')
    require(len(w2) == 82, 'Twin 2 length changed')
    # Twin 1 entry: push rbx; cmp $2, %sil; je return; test $1, %sil; jne swap.
    require(w1[0] == 0x53, 'Twin 1 entry push changed')
    require(w1[1:5] == b'\x40\x80\xfe\x02', 'Twin 1 flag-2 compare changed')
    require(w1[5] == 0x74 and T1_START + 5 + 2 + w1[6] == 0x15080e8,
            'Twin 1 flag-2 return branch changed')
    require(w1[7:11] == b'\x40\xf6\xc6\x01', 'Twin 1 low-bit test changed')
    require(w1[11] == 0x75 and T1_START + 11 + 2 + w1[12] == 0x15080df,
            'Twin 1 low-bit swap branch changed')
    # Twin 2 entry: push rbx; rbx = [rdi]; cmpb $0, 8(rdi); jne swap.
    require(w2[0] == 0x53, 'Twin 2 entry push changed')
    require(w2[1:4] == b'\x48\x8b\x1f', 'Twin 2 pointer load changed')
    require(w2[4:8] == b'\x80\x7f\x08\x00', 'Twin 2 flag-byte compare changed')
    require(w2[8] == 0x75 and T2_START + 8 + 2 + w2[9] == 0x15081cc,
            'Twin 2 nonzero swap branch changed')
    # Shared global check: mov slot(%rip), %rax; mov (%rax), %rax; shl $1;
    # test %rax, %rax; jne call arm.
    for w, start, call_arm in ((w1, T1_START, 0x1508105), (w2, T2_START, 0x15081f2)):
        base = 13 if w is w1 else 10
        require(w[base] == 0x48 and w[base + 1] == 0x8b and w[base + 2] == 0x05,
                'Global slot load opcode changed')
        disp = struct.unpack_from('<i', w, base + 3)[0]
        require(start + base + 7 + disp == GLOBAL_SLOT, 'Global slot changed')
        require(w[base + 7:base + 10] == b'\x48\x8b\x00', 'Global dereference changed')
        require(w[base + 10:base + 13] == b'\x48\xd1\xe0', 'Global shift changed')
        require(w[base + 13:base + 16] == b'\x48\x85\xc0', 'Global test changed')
        jne = base + 16
        require(w[jne] == 0x75 and start + jne + 2 + w[jne + 1] == call_arm,
                'Global-nonzero call branch changed')
    # Shared swap: xor %eax, %eax; xchg %eax, (target); cmp $2, %eax;
    # je syscall arm; else pop rbx; ret.
    require(w1[31:33] == b'\x31\xc0' and w1[33:35] == b'\x87\x07',
            'Twin 1 swap changed')
    require(w2[28:30] == b'\x31\xc0' and w2[30:32] == b'\x87\x03',
            'Twin 2 swap changed')
    require(w1[35:38] == b'\x83\xf8\x02' and w1[38] == 0x74
            and T1_START + 38 + 2 + w1[39] == 0x15080ea, 'Twin 1 old-2 branch changed')
    require(w2[32:35] == b'\x83\xf8\x02' and w2[35] == 0x74
            and T2_START + 35 + 2 + w2[36] == 0x15081d7, 'Twin 2 old-2 branch changed')
    require(w1[40:42] == b'\x5b\xc3' and w2[37:39] == b'\x5b\xc3',
            'Swap return epilogue changed')
    # Syscall arms: edi = 0xca, rsi = flag object, edx = 0x81, ecx = 1,
    # eax = 0, pop rbx, tail jump through the syscall slot.
    require(w1[42:45] == b'\x48\x89\xfe', 'Twin 1 syscall object move changed')
    require(w1[45:50] == b'\xbf\xca\x00\x00\x00', 'Twin 1 syscall edi immediate changed')
    require(w1[50:55] == b'\xba\x81\x00\x00\x00', 'Twin 1 syscall edx immediate changed')
    require(w1[55:60] == b'\xb9\x01\x00\x00\x00', 'Twin 1 syscall ecx immediate changed')
    require(w1[60:62] == b'\x31\xc0' and w1[62] == 0x5b, 'Twin 1 syscall setup changed')
    require(w1[63] == 0xff and w1[64] == 0x25, 'Twin 1 syscall tail-jump opcode changed')
    disp = struct.unpack_from('<i', w1, 65)[0]
    require(T1_START + 63 + 6 + disp == SYSCALL_SLOT, 'Twin 1 syscall slot changed')
    require(w2[39:44] == b'\xbf\xca\x00\x00\x00', 'Twin 2 syscall edi immediate changed')
    require(w2[44:47] == b'\x48\x89\xde', 'Twin 2 syscall object move changed')
    require(w2[47:52] == b'\xba\x81\x00\x00\x00', 'Twin 2 syscall edx immediate changed')
    require(w2[52:57] == b'\xb9\x01\x00\x00\x00', 'Twin 2 syscall ecx immediate changed')
    require(w2[57:59] == b'\x31\xc0' and w2[59] == 0x5b, 'Twin 2 syscall setup changed')
    require(w2[60] == 0xff and w2[61] == 0x25, 'Twin 2 syscall tail-jump opcode changed')
    disp = struct.unpack_from('<i', w2, 62)[0]
    require(T2_START + 60 + 6 + disp == SYSCALL_SLOT, 'Twin 2 syscall slot changed')
    # Call arms: indirect call through the shared call slot; test %al, %al;
    # jne swap; else movb $1, 4(object); jmp swap.
    require(w1[69:72] == b'\x48\x89\xfb', 'Twin 1 call-arm save changed')
    require(w1[72] == 0xff and w1[73] == 0x15, 'Twin 1 call opcode changed')
    disp = struct.unpack_from('<i', w1, 74)[0]
    require(T1_START + 72 + 6 + disp == CALL_SLOT, 'Twin 1 call slot changed')
    require(w1[78:81] == b'\x48\x89\xdf', 'Twin 1 call-arm restore changed')
    require(w1[81:83] == b'\x84\xc0' and w1[83] == 0x75
            and T1_START + 83 + 2 + struct.unpack_from('<b', w1, 84)[0] == 0x15080df,
            'Twin 1 call-result branch changed')
    require(w1[85:89] == b'\xc6\x47\x04\x01', 'Twin 1 flag-byte set changed')
    require(w1[89] == 0xeb
            and T1_START + 89 + 2 + struct.unpack_from('<b', w1, 90)[0] == 0x15080df,
            'Twin 1 set-to-swap jump changed')
    require(w2[66] == 0xff and w2[67] == 0x15, 'Twin 2 call opcode changed')
    disp = struct.unpack_from('<i', w2, 68)[0]
    require(T2_START + 66 + 6 + disp == CALL_SLOT, 'Twin 2 call slot changed')
    require(w2[72:74] == b'\x84\xc0' and w2[74] == 0x75
            and T2_START + 74 + 2 + struct.unpack_from('<b', w2, 75)[0] == 0x15081cc,
            'Twin 2 call-result branch changed')
    require(w2[76:80] == b'\xc6\x43\x04\x01', 'Twin 2 flag-byte set changed')
    require(w2[80] == 0xeb
            and T2_START + 80 + 2 + struct.unpack_from('<b', w2, 81)[0] == 0x15081cc,
            'Twin 2 set-to-swap jump changed')
    # Callee: cmpq $0, %fs:-0x428; sete %al; ret. Returns 1 exactly when
    # the thread-local cell is zero.
    c = read(CALLEE_START, CALLEE_END - CALLEE_START)
    require(c == CALLEE, 'TLS-zero-test callee changed')
    require(len(c) == 14, 'Callee length changed')
    require(c[0:10] == bytes.fromhex('6448833c25d8fbffff00'),
            'Callee thread-local compare changed')
    require(c[10:13] == b'\x0f\x94\xc0' and c[13] == 0xc3, 'Callee sete/ret changed')
    # Padding: five int3 bytes after twin 1, fourteen after twin 2.
    require(read(T1_END, 5) == b'\xcc' * 5, 'Twin 1 padding changed')
    require(read(T2_END, 14) == b'\xcc' * 14, 'Twin 2 padding changed')
    # FDE/CIE locks.
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in ((0x13600, T1_FDE, T1_START, T1_END),
                                    (0x13624, T2_FDE, T2_START, T2_END),
                                    (0x280d50, CALLEE_FDE, CALLEE_START, CALLEE_END)):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Relocations: both code slots are RELATIVE; the syscall slot is a
    # GLOB_DAT import whose dynamic symbol is syscall. Stored file bytes
    # at all three slots are zero, as expected before dynamic relocation.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    require(rels.get(GLOBAL_SLOT) == (GLOBAL_INFO, GLOBAL_CELL),
            'Global slot relocation changed')
    require(rels.get(CALL_SLOT) == (CALL_INFO, CALLEE_START),
            'Call slot relocation changed')
    require(rels.get(SYSCALL_SLOT) == (SYSCALL_INFO, 0),
            'Syscall slot relocation changed')
    for slot in (GLOBAL_SLOT, CALL_SLOT, SYSCALL_SLOT):
        require(read(slot, 8) == b'\0' * 8, 'Unexpected pre-relocation pointer')
    dynsym = by_name['.dynsym']
    dynstr = by_name['.dynstr']
    entry = read(dynsym['address'] + 19 * 24, 24)
    nameoff = struct.unpack_from('<I', entry, 0)[0]
    name = read(dynstr['address'] + nameoff, 8)
    require(name == b'syscall\0', 'Syscall symbol name changed')
    # Section containment for the relocated targets.
    require(any(s['address'] <= GLOBAL_CELL < s['address'] + s['size']
                and s['name'] == '.bss' for s in secs), 'Global cell not in .bss')
    require(any(s['address'] <= CALLEE_START < s['address'] + s['size']
                and s['name'] == '.text' for s in secs), 'Callee not in .text')
    # Observed transition model, as pure arithmetic over the inputs the
    # windows actually read. Swap outcomes are stated separately because
    # the old flag value is only known at swap time.
    def twin1_path(flag, global_qword, tls_zero):
        if flag == 2:
            return 'return'
        if flag & 1:
            return 'swap'
        if (global_qword << 1) % (1 << 64) != 0:
            return 'swap-with-byte4-set' if not tls_zero else 'swap'
        return 'swap'

    def twin2_path(flag_byte, global_qword, tls_zero):
        if flag_byte != 0:
            return 'swap'
        if (global_qword << 1) % (1 << 64) != 0:
            return 'swap-with-byte4-set' if not tls_zero else 'swap'
        return 'swap'

    def swap_outcome(old):
        return 'syscall-arm' if old == 2 else 'return'

    require([twin1_path(f, 0, True) for f in (2, 1, 0)] ==
            ['return', 'swap', 'swap'], 'Twin 1 entry transitions changed')
    require(twin1_path(0, 1, False) == 'swap-with-byte4-set',
            'Twin 1 call-arm set transition changed')
    require(twin1_path(0, 1, True) == 'swap', 'Twin 1 call-arm skip transition changed')
    require([twin2_path(b, 0, True) for b in (2, 1, 0)] ==
            ['swap', 'swap', 'swap'], 'Twin 2 entry transitions changed')
    require(twin2_path(0, 1, False) == 'swap-with-byte4-set',
            'Twin 2 call-arm set transition changed')
    require([swap_outcome(o) for o in (2, 1, 0)] ==
            ['syscall-arm', 'return', 'return'], 'Swap outcomes changed')

    return dict(target_release='94', target_sha256=SHA256,
                coordinate_system='ELF virtual addresses, no runtime rebase',
                windows=[
                    dict(start_va=hex(T1_START), fde_end_va_exclusive=hex(T1_END),
                         fde_bytes=91, fde_body_sha256=hashlib.sha256(w1).hexdigest(),
                         fde_section_offset='0x13600', padding_int3_bytes=5),
                    dict(start_va=hex(T2_START), fde_end_va_exclusive=hex(T2_END),
                         fde_bytes=82, fde_body_sha256=hashlib.sha256(w2).hexdigest(),
                         fde_section_offset='0x13624', padding_int3_bytes=14)],
                flag_sources=dict(
                    twin1='incoming sil byte',
                    twin2='byte at 8(rdi) after loading the pointer at [rdi] into rbx'),
                swap_targets=dict(twin1='(rdi)', twin2='(rbx) where rbx holds [rdi]'),
                shared_edges=dict(
                    global_slot=dict(slot=hex(GLOBAL_SLOT), relocation='R_X86_64_RELATIVE',
                                     target_cell=hex(GLOBAL_CELL), cell_section='.bss'),
                    call_slot=dict(slot=hex(CALL_SLOT), relocation='R_X86_64_RELATIVE',
                                   callee=hex(CALLEE_START),
                                   callee_fde_end_va_exclusive=hex(CALLEE_END),
                                   callee_fde_section_offset='0x280d50',
                                   callee_behavior='cmpq $0, %fs:-0x428; sete %al; ret',
                                   callee_body_decoded=True),
                    syscall_slot=dict(slot=hex(SYSCALL_SLOT),
                                      relocation='R_X86_64_GLOB_DAT',
                                      dynamic_symbol='syscall', symbol_index=19, addend=0,
                                      immediates=dict(edi=202, edx=129, ecx=1),
                                      control='tail jump, not a call')),
                behavior=dict(
                    twin1_entry='flag 2 returns; odd flag goes to the swap; even flag '
                                'checks the global cell, nonzero goes to the call arm, '
                                'zero goes to the swap',
                    twin2_entry='nonzero flag byte goes to the swap; zero flag byte '
                                'checks the global cell, nonzero goes to the call arm, '
                                'zero goes to the swap',
                    call_arm='callee returns 1 exactly when the thread-local cell is '
                             'zero; 1 skips the byte-4 set, 0 sets byte 4 of the flag '
                             'object to 1, then both rejoin the swap',
                    swap='atomically exchange 0 into the flag target; old value 2 '
                         'takes the syscall tail jump, any other old value returns',
                    differences='flag source, early flag-2 return only in twin 1, '
                                'swap target register, and call-arm register save; '
                                'global slot, call slot, syscall slot and immediates '
                                'are shared'),
                claim='two near-identical flag state machines differing only in flag '
                      'source, early flag-2 return, swap target and call-arm register '
                      'save',
                inferred_label=None,
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
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        require(result == json.loads(args.check.read_text()), 'Retained evidence differs')
        print('Foundation twin once-flag evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
