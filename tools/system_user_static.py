#!/usr/bin/env python3
"""RE/SystemUser: Node #94 system user table, index iterator, and privilege dispatch static verification tool.

Static, offline verification tool. Zero execution of captured binaries.
Zero external network calls. Standard Python library only.

Target:
    artifacts/node/94/hl-node (SHA-256: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f)

Scope:
    1. Verification of binary byte extents for 3 system user FDEs (8,110 B total):
       - FDE 1 (0x3b9d9b0..0x3b9d9f7, 71 B, sha256: 1b77785b7ec902c12d4792412e3e3d0302844e66d94a947905be97b539ae3d64)
         Routine: SystemUserIndexIter::next_index_with_offset (checked iterator advance, overflow bounds, sentinel 30)
       - FDE 2 (0x3705690..0x37067a9, 4377 B, sha256: 9422fe7f01d5d3470a0435c27ea11b343f2377d3037ece3e9ed0de9a0f6ec6e7)
         Routine: SystemUserPrivilegeCheck::dispatch (privileged user authorization, bitmask 0x40006000, ranges 18..=25, 10)
       - FDE 3 (0x3270830..0x327167e, 3662 B, sha256: 80fab9d404ea8a1c304d44d85ba1bf86f6e5fd3b1782768529cd43b5ea677ecd)
         Routine: SystemUserState::init_system_users (system user account registration and reserved address binding)
    2. Verification of mapped source panic record in .data.rel.ro / .rela.dyn:
       - 0x5712ff0: line 3, col 23 in /home/ubuntu/hl/code_Mainnet/l1/src/system_user.rs
         (string at 0x1f5836, referenced at 0x3b9d9ea: 488d3dff55b701)
    3. Verification of 20-entry privileged system user address table in .rodata:
       - 0x3e35c8..0x3e37a4 (476 B): indices 7..=26 (0x0800, 0x0813, 0x0801..=0x0812)
    4. Verification of reserved address constants in .rodata:
       - 0x5849e4: [0x22; 20] (Index 0)
       - 0x584a00: [0x33; 20] (Index 27)
       - 0x584a14: [0x55; 20] (Index 28)
       - 0x584928: 0x0800 (Index 7)
       - 0x584940: 0x0813 (Index 8)
       - 0x584958: 0x0806 (Index 14)
       - 0x584970: 0x0807 (Index 15)
       - 0x584988: 0x0808 (Index 16)
       - 0x5849a0: 0x080b (Index 19)
       - 0x5849b8: 0x080c (Index 20)
       - 0x5849d0: 0x080e (Index 22)
    5. Numeric Constants:
       - NUM_SYSTEM_USERS = 30 (0x1e)
       - SYSTEM_USER_END_SENTINEL = 30 (0x1e)
       - FIRST_PRIVILEGED_SYSTEM_USER_INDEX = 7
       - PRIVILEGED_SYSTEM_USER_COUNT = 20
       - LAST_PRIVILEGED_SYSTEM_USER_INDEX = 26
       - PRIVILEGED_SYSTEM_USER_BITMASK = 0x40006000 (bits 13, 14, 30)
    6. Verification of 24 exact instruction controls.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BINARY_REL = 'artifacts/node/94/hl-node'
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
EXPECTED_SIZE = 91774280

SOURCE_PATH = '/home/ubuntu/hl/code_Mainnet/l1/src/system_user.rs'
PACKET = ROOT / 'research' / 'work-items' / 'system-user-94'

# Constants
NUM_SYSTEM_USERS = 30
SYSTEM_USER_END_SENTINEL = 30
FIRST_PRIVILEGED_SYSTEM_USER_INDEX = 7
PRIVILEGED_SYSTEM_USER_COUNT = 20
LAST_PRIVILEGED_SYSTEM_USER_INDEX = 26
PRIVILEGED_SYSTEM_USER_BITMASK = 0x40006000  # bits 13, 14, 30

FDES = [
    {
        'name': 'SystemUserIndexIter::next_index_with_offset',
        'start': 0x3b9d9b0,
        'end': 0x3b9d9f7,
        'size': 71,
        'sha256': '1b77785b7ec902c12d4792412e3e3d0302844e66d94a947905be97b539ae3d64',
    },
    {
        'name': 'SystemUserPrivilegeCheck::dispatch',
        'start': 0x3705690,
        'end': 0x37067a9,
        'size': 4377,
        'sha256': '9422fe7f01d5d3470a0435c27ea11b343f2377d3037ece3e9ed0de9a0f6ec6e7',
    },
    {
        'name': 'SystemUserState::init_system_users',
        'start': 0x3270830,
        'end': 0x327167e,
        'size': 3662,
        'sha256': '80fab9d404ea8a1c304d44d85ba1bf86f6e5fd3b1782768529cd43b5ea677ecd',
    },
]

PANIC_LOCATIONS = [
    {
        'record_vaddr': 0x5712ff0,
        'source_path': SOURCE_PATH,
        'line': 3,
        'col': 23,
        'referenced_at': 0x3b9d9ea,
    }
]

PRIVILEGED_SYSTEM_USERS_TABLE_VADDR = 0x3e35c8
PRIVILEGED_SYSTEM_USERS_TABLE_LEN = 476  # 20 entries of 24 bytes (last entry 20 bytes before error string)

RODATA_CONSTANTS = [
    {
        'vaddr': 0x5849e4,
        'length': 20,
        'expected_hex': '22' * 20,
        'desc': 'System user 0: [0x22; 20]',
    },
    {
        'vaddr': 0x584a00,
        'length': 20,
        'expected_hex': '33' * 20,
        'desc': 'System user 27: [0x33; 20]',
    },
    {
        'vaddr': 0x584a14,
        'length': 20,
        'expected_hex': '55' * 20,
        'desc': 'System user 28: [0x55; 20]',
    },
    {
        'vaddr': 0x584928,
        'length': 20,
        'expected_hex': '00' * 18 + '0800',
        'desc': 'System user 7: 0x0800',
    },
    {
        'vaddr': 0x584940,
        'length': 20,
        'expected_hex': '00' * 18 + '0813',
        'desc': 'System user 8: 0x0813',
    },
    {
        'vaddr': 0x584958,
        'length': 20,
        'expected_hex': '00' * 18 + '0806',
        'desc': 'System user 14: 0x0806',
    },
    {
        'vaddr': 0x584970,
        'length': 20,
        'expected_hex': '00' * 18 + '0807',
        'desc': 'System user 15: 0x0807',
    },
    {
        'vaddr': 0x584988,
        'length': 20,
        'expected_hex': '00' * 18 + '0808',
        'desc': 'System user 16: 0x0808',
    },
    {
        'vaddr': 0x5849a0,
        'length': 20,
        'expected_hex': '00' * 18 + '080b',
        'desc': 'System user 19: 0x080b',
    },
    {
        'vaddr': 0x5849b8,
        'length': 20,
        'expected_hex': '00' * 18 + '080c',
        'desc': 'System user 20: 0x080c',
    },
    {
        'vaddr': 0x5849d0,
        'length': 20,
        'expected_hex': '00' * 18 + '080e',
        'desc': 'System user 22: 0x080e',
    },
]

CONTROLS = [
    # SystemUserIndexIter::next_index_with_offset
    {
        'vaddr': 0x3b9d9b0,
        'hex_bytes': '50',
        'desc': 'push %rax (stack alignment)',
    },
    {
        'vaddr': 0x3b9d9b1,
        'hex_bytes': '480337',
        'desc': 'add (%rdi), %rsi (current = cursor + offset)',
    },
    {
        'vaddr': 0x3b9d9b4,
        'hex_bytes': '7234',
        'desc': 'jb 0x3b9d9ea (overflow check 1: jb panic)',
    },
    {
        'vaddr': 0x3b9d9b9,
        'hex_bytes': '48ffc0',
        'desc': 'inc %rax (next = current + 1)',
    },
    {
        'vaddr': 0x3b9d9bc,
        'hex_bytes': '742c',
        'desc': 'je 0x3b9d9ea (overflow check 2: je panic)',
    },
    {
        'vaddr': 0x3b9d9be,
        'hex_bytes': '488b4f08',
        'desc': 'mov 0x8(%rdi), %rcx (load tail_allowance)',
    },
    {
        'vaddr': 0x3b9d9c2,
        'hex_bytes': '4801c1',
        'desc': 'add %rax, %rcx (bounded_next = next + tail_allowance)',
    },
    {
        'vaddr': 0x3b9d9c5,
        'hex_bytes': '7223',
        'desc': 'jb 0x3b9d9ea (overflow check 3: jb panic)',
    },
    {
        'vaddr': 0x3b9d9c7,
        'hex_bytes': '4883f91e',
        'desc': 'cmp $0x1e, %rcx (cmp NUM_SYSTEM_USERS = 30, bounded_next)',
    },
    {
        'vaddr': 0x3b9d9cd,
        'hex_bytes': '48c7071e000000',
        'desc': 'movq $0x1e, (%rdi) (self.cursor = 30 clamp on bound breach)',
    },
    {
        'vaddr': 0x3b9d9d4,
        'hex_bytes': 'b01e',
        'desc': 'mov $0x1e, %al (return SYSTEM_USER_END_SENTINEL = 30)',
    },
    {
        'vaddr': 0x3b9d9d8,
        'hex_bytes': '488907',
        'desc': 'mov %rax, (%rdi) (self.cursor = next)',
    },
    {
        'vaddr': 0x3b9d9db,
        'hex_bytes': '4883fe1e',
        'desc': 'cmp $0x1e, %rsi (cmp 30, current)',
    },
    {
        'vaddr': 0x3b9d9df,
        'hex_bytes': 'b81e000000',
        'desc': 'mov $0x1e, %eax (sentinel fallback)',
    },
    {
        'vaddr': 0x3b9d9e4,
        'hex_bytes': '480f42c6',
        'desc': 'cmovb %rsi, %rax (cmovb current to rax)',
    },
    {
        'vaddr': 0x3b9d9ea,
        'hex_bytes': '488d3dff55b701',
        'desc': 'lea 0x1b755ff(%rip), %rdi (panic record at 0x5712ff0)',
    },
    # SystemUserPrivilegeCheck::dispatch
    {
        'vaddr': 0x3705701,
        'hex_bytes': '410fb64648',
        'desc': 'movzbl 0x48(%r14), %eax (load system user index)',
    },
    {
        'vaddr': 0x3705706,
        'hex_bytes': '8d48ee',
        'desc': 'lea -0x12(%rax), %ecx (ecx = index - 18)',
    },
    {
        'vaddr': 0x3705709,
        'hex_bytes': '83f908',
        'desc': 'cmp $0x8, %ecx (cmp 8, index - 18 for range 18..=25)',
    },
    {
        'vaddr': 0x37065c6,
        'hex_bytes': '83f80a',
        'desc': 'cmp $0xa, %eax (cmp index, 10)',
    },
    {
        'vaddr': 0x37065ee,
        'hex_bytes': 'b900600040',
        'desc': 'mov $0x40006000, %ecx (PRIVILEGED_SYSTEM_USER_BITMASK: bits 13, 14, 30)',
    },
    {
        'vaddr': 0x37065f3,
        'hex_bytes': '0fa3c1',
        'desc': 'bt %eax, %ecx (bit test index in privilege bitmask)',
    },
    # SystemUserState::init_system_users
    {
        'vaddr': 0x327084d,
        'hex_bytes': '488d35ac4131fd',
        'desc': 'lea -0x2cebe54(%rip), %rsi (address at 0x584a00 [0x33; 20])',
    },
    {
        'vaddr': 0x3270863,
        'hex_bytes': '488d357a4131fd',
        'desc': 'lea -0x2cebe86(%rip), %rsi (address at 0x5849e4 [0x22; 20])',
    },
]


class SystemUserIndexIter:
    """Clean-room Python reference implementation of SystemUserIndexIter."""

    def __init__(self, cursor: int = 0, tail_allowance: int = 0):
        self.cursor = cursor
        self.tail_allowance = tail_allowance

    def next_index_with_offset(self, offset: int) -> int:
        current = self.cursor + offset
        if current > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError("cursor + offset overflow")
        next_idx = current + 1
        if next_idx > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError("current + 1 overflow")
        bounded_next = next_idx + self.tail_allowance
        if bounded_next > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError("bounded_next overflow")

        if bounded_next <= NUM_SYSTEM_USERS:
            self.cursor = next_idx
            return current if current < NUM_SYSTEM_USERS else SYSTEM_USER_END_SENTINEL
        else:
            self.cursor = NUM_SYSTEM_USERS
            return SYSTEM_USER_END_SENTINEL


def is_privileged_system_index(index: int) -> bool:
    """Verify if index is in privileged system user index range (7..=26)."""
    return FIRST_PRIVILEGED_SYSTEM_USER_INDEX <= index <= LAST_PRIVILEGED_SYSTEM_USER_INDEX


class EvidenceError(Exception):
    pass


def check_digest(path: Path) -> bytes:
    if not path.is_file():
        raise EvidenceError(f'Target binary missing: {path}')
    data = path.read_bytes()
    if len(data) != EXPECTED_SIZE:
        raise EvidenceError(f'Size mismatch: expected {EXPECTED_SIZE}, got {len(data)}')
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != EXPECTED_SHA256:
        raise EvidenceError(f'SHA-256 mismatch: expected {EXPECTED_SHA256}, got {actual_sha}')
    return data


def sections(data: bytes):
    if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64:
        raise ValueError('Expected ELF64 little-endian input')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, names_index = struct.unpack_from('<HHH', data, 58)
    rows = []
    for index in range(count):
        name, typ, flags, addr, off, size, link, info, align, entry = struct.unpack_from(
            '<IIQQQQIIQQ', data, shoff + index * entsize
        )
        rows.append(dict(name_offset=name, type=typ, flags=flags, address=addr, offset=off, size=size))
    names = rows[names_index]
    table = data[names['offset']:names['offset'] + names['size']]
    for row in rows:
        off = row.pop('name_offset')
        end = table.find(b'\0', off)
        row['name'] = table[off:end].decode('utf-8')
    return rows


class Image:
    def __init__(self, data: bytes):
        self.data = data
        self.sec = sections(data)

    def off(self, vaddr: int) -> int:
        for s in self.sec:
            if s['address'] <= vaddr < s['address'] + s['size']:
                return s['offset'] + (vaddr - s['address'])
        raise ValueError(f'Virtual address {hex(vaddr)} outside mapped sections')

    def read(self, vaddr: int, size: int) -> bytes:
        offset = self.off(vaddr)
        return self.data[offset:offset + size]


def analyse(data: bytes):
    if len(data) != EXPECTED_SIZE:
        raise EvidenceError(f"Size mismatch: expected {EXPECTED_SIZE}, got {len(data)}")

    image = Image(data)

    fde_findings = []
    for fde in FDES:
        actual_bytes = image.read(fde['start'], fde['size'])
        actual_sha = hashlib.sha256(actual_bytes).hexdigest()
        if actual_sha != fde['sha256']:
            raise EvidenceError(
                f"FDE digest mismatch for {fde['name']}: expected {fde['sha256']}, got {actual_sha}"
            )
        fde_findings.append({
            'name': fde['name'],
            'start': hex(fde['start']),
            'end': hex(fde['end']),
            'size': fde['size'],
            'sha256': actual_sha,
            'status': 'MATCH',
        })

    rela_sec = next((s for s in image.sec if s['name'] == '.rela.dyn'), None)
    relocations = {}
    if rela_sec:
        rela_bytes = image.data[rela_sec['offset']:rela_sec['offset'] + rela_sec['size']]
        for i in range(0, len(rela_bytes), 24):
            r_offset, r_info, r_addend = struct.unpack_from('<QQq', rela_bytes, i)
            relocations[r_offset] = (r_info, r_addend)

    panic_findings = []
    for p in PANIC_LOCATIONS:
        record_bytes = image.read(p['record_vaddr'], 24)
        str_ptr, str_len, line, col = struct.unpack_from('<QQII', record_bytes, 0)
        if line != p['line'] or col != p['col']:
            raise EvidenceError(
                f"Panic line/col mismatch at {hex(p['record_vaddr'])}: expected {p['line']}:{p['col']}, got {line}:{col}"
            )
        if p['record_vaddr'] in relocations:
            _, r_addend = relocations[p['record_vaddr']]
            actual_path = image.read(r_addend, str_len).decode('utf-8')
            if actual_path != p['source_path']:
                raise EvidenceError(f"Panic source path mismatch: expected {p['source_path']}, got {actual_path}")
        panic_findings.append({
            'record_vaddr': hex(p['record_vaddr']),
            'line': line,
            'col': col,
            'source_path': p['source_path'],
            'referenced_at': hex(p['referenced_at']),
            'status': 'VERIFIED',
        })

    # Verify privileged 20-entry table
    table_bytes = image.read(PRIVILEGED_SYSTEM_USERS_TABLE_VADDR, PRIVILEGED_SYSTEM_USERS_TABLE_LEN)
    expected_order = [
        0x0800, 0x0813, 0x0801, 0x0802, 0x0803, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808,
        0x0809, 0x080a, 0x080b, 0x080c, 0x080d, 0x080e, 0x080f, 0x0810, 0x0811, 0x0812
    ]
    table_findings = []
    for idx, exp_val in enumerate(expected_order):
        off = idx * 24
        chunk = table_bytes[off:off+20]
        exp_chunk = (b'\x00' * 18) + exp_val.to_bytes(2, 'big')
        if chunk != exp_chunk:
            raise EvidenceError(f"Table entry {idx} mismatch: expected {exp_chunk.hex()}, got {chunk.hex()}")
        table_findings.append({
            'system_user_index': FIRST_PRIVILEGED_SYSTEM_USER_INDEX + idx,
            'address': f"0x{exp_val:04x}",
            'offset': hex(PRIVILEGED_SYSTEM_USERS_TABLE_VADDR + off),
            'status': 'VERIFIED',
        })

    rodata_findings = []
    for r in RODATA_CONSTANTS:
        raw = image.read(r['vaddr'], r['length'])
        if 'expected_hex' in r:
            actual_hex = raw.hex()
            if actual_hex != r['expected_hex']:
                raise EvidenceError(f"Hex mismatch at {hex(r['vaddr'])}: expected {r['expected_hex']}, got {actual_hex}")
        rodata_findings.append({
            'vaddr': hex(r['vaddr']),
            'desc': r['desc'],
            'status': 'VERIFIED',
        })

    control_findings = []
    for ctrl in CONTROLS:
        expected = bytes.fromhex(ctrl['hex_bytes'])
        actual = image.read(ctrl['vaddr'], len(expected))
        if actual != expected:
            raise EvidenceError(
                f"Control mismatch at {hex(ctrl['vaddr'])}: expected {ctrl['hex_bytes']}, got {actual.hex()}"
            )
        control_findings.append({
            'vaddr': hex(ctrl['vaddr']),
            'hex_bytes': ctrl['hex_bytes'],
            'desc': ctrl['desc'],
            'status': 'PASS',
        })

    return {
        'binary': {
            'sha256': hashlib.sha256(data).hexdigest(),
            'size': len(data),
        },
        'fdes': fde_findings,
        'panics': panic_findings,
        'privileged_table': table_findings,
        'rodata': rodata_findings,
        'controls': control_findings,
    }


def generate_packet(data: bytes):
    analysis = analyse(data)
    PACKET.mkdir(parents=True, exist_ok=True)
    (PACKET / 'observed').mkdir(parents=True, exist_ok=True)

    # 1. controls.tsv
    with open(PACKET / 'controls.tsv', 'w', newline='\n', encoding='utf-8') as f:
        f.write('vaddr\thex_bytes\tdesc\tstatus\n')
        for c in analysis['controls']:
            f.write(f"{c['vaddr']}\t{c['hex_bytes']}\t{c['desc']}\t{c['status']}\n")

    # 2. panic_records.tsv
    with open(PACKET / 'panic_records.tsv', 'w', newline='\n', encoding='utf-8') as f:
        f.write('record_vaddr\tline\tcol\tsource_path\treferenced_at\tstatus\n')
        for p in analysis['panics']:
            f.write(f"{p['record_vaddr']}\t{p['line']}\t{p['col']}\t{p['source_path']}\t{p['referenced_at']}\t{p['status']}\n")

    # 3. privileged_users.tsv
    with open(PACKET / 'privileged_users.tsv', 'w', newline='\n', encoding='utf-8') as f:
        f.write('system_user_index\taddress\toffset\tstatus\n')
        for t in analysis['privileged_table']:
            f.write(f"{t['system_user_index']}\t{t['address']}\t{t['offset']}\t{t['status']}\n")

    # 4. rodata_constants.tsv
    with open(PACKET / 'rodata_constants.tsv', 'w', newline='\n', encoding='utf-8') as f:
        f.write('vaddr\tdesc\tstatus\n')
        for r in analysis['rodata']:
            f.write(f"{r['vaddr']}\t{r['desc']}\t{r['status']}\n")

    # 5. records.json
    records = {
        'target': BINARY_REL,
        'target_sha256': EXPECTED_SHA256,
        'fdes': analysis['fdes'],
        'panics': analysis['panics'],
        'privileged_table': analysis['privileged_table'],
        'rodata': analysis['rodata'],
        'controls': analysis['controls'],
    }
    with open(PACKET / 'records.json', 'w', newline='\n', encoding='utf-8') as f:
        json.dump(records, f, indent=2)
        f.write('\n')

    # 6. evidence.json
    evidence = {
        'status': 'VERIFIED',
        'fde_count': len(FDES),
        'total_fde_bytes': sum(f['size'] for f in FDES),
        'panic_count': len(PANIC_LOCATIONS),
        'privileged_user_count': len(analysis['privileged_table']),
        'rodata_constants_count': len(RODATA_CONSTANTS),
        'controls_count': len(CONTROLS),
        'algorithmic_constants': {
            'NUM_SYSTEM_USERS': NUM_SYSTEM_USERS,
            'SYSTEM_USER_END_SENTINEL': SYSTEM_USER_END_SENTINEL,
            'FIRST_PRIVILEGED_SYSTEM_USER_INDEX': FIRST_PRIVILEGED_SYSTEM_USER_INDEX,
            'PRIVILEGED_SYSTEM_USER_COUNT': PRIVILEGED_SYSTEM_USER_COUNT,
            'LAST_PRIVILEGED_SYSTEM_USER_INDEX': LAST_PRIVILEGED_SYSTEM_USER_INDEX,
            'PRIVILEGED_SYSTEM_USER_BITMASK': hex(PRIVILEGED_SYSTEM_USER_BITMASK),
        },
    }
    with open(PACKET / 'evidence.json', 'w', newline='\n', encoding='utf-8') as f:
        json.dump(evidence, f, indent=2)
        f.write('\n')

    # 7. observed objdump disassembly
    objdump_cmd = [
        'objdump', '-d', '--no-show-raw-insn',
        f"--start-address={hex(FDES[0]['start'])}",
        f"--stop-address={hex(FDES[0]['end'])}",
        str(ROOT / BINARY_REL),
    ]
    res = subprocess.run(objdump_cmd, capture_output=True, text=True, check=True)
    with open(PACKET / 'observed' / 'system_user_iter.objdump.txt', 'w', newline='\n', encoding='utf-8') as f:
        f.write(res.stdout)

    with open(PACKET / 'observed' / 'records.json', 'w', newline='\n', encoding='utf-8') as f:
        json.dump(records, f, indent=2)
        f.write('\n')

    # 8. README.md
    readme_content = f"""# System User Evidence Packet (Node #94)

Static verification evidence packet for `l1/src/system_user.rs` extracted from `artifacts/node/94/hl-node`
(SHA-256: `{EXPECTED_SHA256}`). Zero binary execution; offline ELF analysis only.

## Subsystem Extents
Total verified routine footprint: **3 FDEs**, **{sum(f['size'] for f in FDES):,} bytes**.

| Routine | Start | End | Size | SHA-256 |
|---|---|---|---|---|
"""
    for fde in FDES:
        readme_content += f"| `{fde['name']}` | `{hex(fde['start'])}` | `{hex(fde['end'])}` | {fde['size']} B | `{fde['sha256']}` |\n"

    readme_content += f"""
## Panic Records
- `0x5712ff0`: `{SOURCE_PATH}:3:23` (referenced at `0x3b9d9ea`)

## Privileged System User Table
- Extent: `0x3e35c8..0x3e37a4` (20 entries, non-numeric order: `0x0800`, `0x0813`, `0x0801..=0x0812`)
- Bitmask dispatch: `0x40006000` (bits 13, 14, 30)

## Constants & Limits
- `NUM_SYSTEM_USERS`: `30` (`0x1e`)
- `SYSTEM_USER_END_SENTINEL`: `30` (`0x1e`)
- `FIRST_PRIVILEGED_SYSTEM_USER_INDEX`: `7`
- `PRIVILEGED_SYSTEM_USER_COUNT`: `20`
- `LAST_PRIVILEGED_SYSTEM_USER_INDEX`: `26`
"""
    with open(PACKET / 'README.md', 'w', newline='\n', encoding='utf-8') as f:
        f.write(readme_content)

    # 9. MANIFEST.sha256 & manifest.json
    packet_files = sorted([
        'README.md',
        'controls.tsv',
        'evidence.json',
        'observed/records.json',
        'observed/system_user_iter.objdump.txt',
        'panic_records.tsv',
        'privileged_users.tsv',
        'records.json',
        'rodata_constants.tsv',
    ])
    manifest_lines = []
    manifest_entries = []
    for rel_name in packet_files:
        p = PACKET / rel_name
        data_bytes = p.read_bytes()
        digest = hashlib.sha256(data_bytes).hexdigest()
        manifest_lines.append(f"{digest}  {rel_name}")
        manifest_entries.append({
            'path': rel_name,
            'sha256': digest,
            'size': len(data_bytes),
        })

    with open(PACKET / 'MANIFEST.sha256', 'w', newline='\n', encoding='utf-8') as f:
        f.write('\n'.join(manifest_lines) + '\n')

    manifest_json = {
        'target': BINARY_REL,
        'target_sha256': EXPECTED_SHA256,
        'files': manifest_entries,
    }
    with open(PACKET / 'manifest.json', 'w', newline='\n', encoding='utf-8') as f:
        json.dump(manifest_json, f, indent=2)
        f.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / BINARY_REL)
    parser.add_argument('--generate', action='store_true', help='Generate packet files')
    args = parser.parse_args()

    data = check_digest(args.binary)
    if args.generate:
        generate_packet(data)
        print(f'Generated packet at {PACKET}')
    else:
        results = analyse(data)
        print(f"Verified {len(results['fdes'])} FDEs, {len(results['panics'])} panic records, {len(results['privileged_table'])} table entries, {len(results['rodata'])} rodata constants, {len(results['controls'])} opcode controls.")


if __name__ == '__main__':
    main()
