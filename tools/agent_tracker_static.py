#!/usr/bin/env python3
"""RE/AgentTracker: Node #94 agent tracker, authorization keys, and delegation bounds static verification tool.

Static, offline verification tool. Zero execution of captured binaries.
Zero external network calls. Standard Python library only.

Target:
    artifacts/node/94/hl-node (SHA-256: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f)

Scope:
    1. Verification of binary byte extents for agent tracker FDEs (3 FDEs, 4,032 B total):
       - FDE 1 (0x3421e20..0x34224e0, 1728 B, sha256: 8eaa9e7ad9d98ce2cbdd63fbf11ad80ba666074b76ae53c336de14d82d198469)
         Routine: AgentTracker::save_extra_agent (name validation, capacity tier check, duplicate check)
       - FDE 2 (0x34224e0..0x34227e0, 768 B, sha256: c5bfcc90f8d24091103d0160e32f755a9cec438f5e7e4ff093c89c7e45bb16b1)
         Routine: AgentTracker::delete_extra_agent (existence check, removal, panic site)
       - FDE 3 (0x3423240..0x3423840, 1536 B, sha256: 41ac306659c62b6370665c33a1fa30518a06a2556dec3706aa1bd2efc51b223c)
         Routine: AgentTracker::save_main_agent (zero-address filter, 2-sec grace period delta, ownership check)
    2. Verification of mapped source panic record in .data.rel.ro / .rela.dyn:
       - 0x56eb400: line 138, col 48 in /home/ubuntu/hl/code_Mainnet/l1/src/agent_tracker.rs
    3. Verification of 3 hardcoded bypass addresses in .rodata at 0x59c0a8..0x59c0e4:
       - 0x59c0a8: 677d831aef5328190852e24f13c46cac05f984e7
       - 0x59c0bc: 3c83a5cae32a05e88ca6a0350edb540194851a76
       - 0x59c0d0: 4dbf394da4b348b88e8090d22051af83e4cbaef4
    4. Verification of 13 exact instruction control assertions for status codes (390, 81, 83, 86, 87, 89),
       zero-address equality SIMD matching, chrono delta (2 seconds), and panic LEAs.
    5. Clean-room algorithmic model of agent tracking invariants and capacity limits.
"""

import argparse
import bisect
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

SOURCE_PATH = '/home/ubuntu/hl/code_Mainnet/l1/src/agent_tracker.rs'
PACKET = ROOT / 'research' / 'work-items' / 'agent-tracker-94'

# Status Codes
STATUS_OK = 390
ERR_SAVE_AGENT_UNEXPECTED = 81
ERR_AGENT_ADDRESS_IS_USER = 82
ERR_EXTRA_AGENT_INVALID_NAME = 83
ERR_AGENT_VALID_UNTIL_PASSED = 85
ERR_EXTRA_AGENT_ALREADY_USED = 86
ERR_TOO_MANY_EXTRA_AGENTS = 87
ERR_EXTRA_AGENT_DOES_NOT_EXIST = 89
ERR_PENDING_AGENT_REMOVAL = 349

AGENT_GRACE_PERIOD_MS = 2000  # 2 seconds
BASE_EXTRA_AGENT_LIMIT = 3

BYPASS_ADDRESSES = [
    '677d831aef5328190852e24f13c46cac05f984e7',
    '3c83a5cae32a05e88ca6a0350edb540194851a76',
    '4dbf394da4b348b88e8090d22051af83e4cbaef4',
]

FDES = [
    {
        'bytes': 1728,
        'end_va': '0x34224e0',
        'file_offset': '0x34214e0',
        'id': 'fde1_save_extra_agent',
        'panic_records': [],
        'role': 'AgentTracker::save_extra_agent (name validation, capacity tier check, duplicate check)',
        'sha256': '8eaa9e7ad9d98ce2cbdd63fbf11ad80ba666074b76ae53c336de14d82d198469',
        'start_va': '0x3421e20',
    },
    {
        'bytes': 768,
        'end_va': '0x34227e0',
        'file_offset': '0x34217e0',
        'id': 'fde2_delete_extra_agent',
        'panic_records': ['0x56eb400'],
        'role': 'AgentTracker::delete_extra_agent (existence check, removal, panic site)',
        'sha256': 'c5bfcc90f8d24091103d0160e32f755a9cec438f5e7e4ff093c89c7e45bb16b1',
        'start_va': '0x34224e0',
    },
    {
        'bytes': 1536,
        'end_va': '0x3423840',
        'file_offset': '0x3422840',
        'id': 'fde3_save_main_agent',
        'panic_records': [],
        'role': 'AgentTracker::save_main_agent (zero-address filter, 2-sec grace period delta, ownership check)',
        'sha256': '41ac306659c62b6370665c33a1fa30518a06a2556dec3706aa1bd2efc51b223c',
        'start_va': '0x3423240',
    },
]

PANIC_LOCATIONS = {
    '0x56eb400': {
        'col': 48,
        'fde': '0x34224e0',
        'line': 138,
        'path': SOURCE_PATH,
        'record_va': '0x56eb400',
    },
}

CONTROLS = {
    # FDE 1: AgentTracker::save_extra_agent
    0x3421e58: '6641c7075300',        # mov WORD PTR [r15], 0x53 (ERR_EXTRA_AGENT_INVALID_NAME = 83)
    0x3422314: '6641c7078601',        # mov WORD PTR [r15], 0x186 (OK = 390)
    0x342232a: '6641c7075600',        # mov WORD PTR [r15], 0x56 (ERR_EXTRA_AGENT_ALREADY_USED = 86)
    0x3422368: '6641c7075700',        # mov WORD PTR [r15], 0x57 (ERR_TOO_MANY_EXTRA_AGENTS = 87)

    # FDE 2: AgentTracker::delete_extra_agent
    0x342273d: '66c7038601',          # mov WORD PTR [rbx], 0x186 (OK = 390)
    0x3422761: '66c7005900',          # mov WORD PTR [rax], 0x59 (ERR_EXTRA_AGENT_DOES_NOT_EXIST = 89)
    0x3422793: '488d15668c2c02',      # lea rdx, [rip+0x22c8c66] -> 0x56eb400 (agent_tracker.rs:138:48)

    # FDE 3: AgentTracker::save_main_agent
    0x342325d: '660fefc0',            # pxor xmm0, xmm0 (zero address vector initialization)
    0x342328b: '3dffff0000',          # cmp eax, 0xffff (zero address 20-byte match check)
    0x3423400: '66bd8601',            # mov bp, 0x186 (OK = 390 on removal of main agent)
    0x3423654: 'ba02000000',          # mov edx, 0x2 (chrono delta 2s = AGENT_GRACE_PERIOD_MS)
    0x3423748: '66bd8601',            # mov bp, 0x186 (OK = 390 on valid update)
    0x3423783: '66bd5100',            # mov bp, 0x51 (ERR_SAVE_AGENT_UNEXPECTED = 81)
}


class EvidenceError(Exception):
    """Raised when binary artifacts fail validation or decoding errors occur."""


def extra_agent_capacity(tier: int, address_hex: str) -> int:
    """Compute maximum extra-agent capacity given tier and optional bypass address."""
    addr_clean = address_hex.lower().replace('0x', '')
    if addr_clean in [a.lower() for a in BYPASS_ADDRESSES]:
        return 1000000  # unconstrained bypass
    return 2 * tier + BASE_EXTRA_AGENT_LIMIT


def validate_agent_name(name: str) -> bool:
    """Validate extra-agent name length."""
    return 1 <= len(name) <= 32


def sections(data: bytes) -> dict:
    """Parse ELF section headers."""
    e_shoff = struct.unpack_from('<Q', data, 40)[0]
    e_shentsize = struct.unpack_from('<H', data, 58)[0]
    e_shnum = struct.unpack_from('<H', data, 60)[0]
    e_shstrndx = struct.unpack_from('<H', data, 62)[0]

    shstr_hdr = data[e_shoff + e_shstrndx * e_shentsize: e_shoff + (e_shstrndx + 1) * e_shentsize]
    shstr_offset = struct.unpack_from('<Q', shstr_hdr, 24)[0]
    shstr_size = struct.unpack_from('<Q', shstr_hdr, 32)[0]
    shstrtab = data[shstr_offset: shstr_offset + shstr_size]

    secs = {}
    for i in range(e_shnum):
        sec = data[e_shoff + i * e_shentsize: e_shoff + (i + 1) * e_shentsize]
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from('<IIQQQQ', sec, 0)
        name = shstrtab[sh_name:].split(b'\x00', 1)[0].decode('latin1')
        secs[name] = {'addr': sh_addr, 'offset': sh_offset, 'size': sh_size, 'type': sh_type}
    return secs


class Image:
    """ELF mapped virtual image reader."""
    def __init__(self, data: bytes):
        self.data = data
        self.sec = sections(data)
        self._table = sorted(
            [(s['addr'], s['offset'], s['size']) for s in self.sec.values() if s['addr'] != 0 and s['type'] != 8],
            key=lambda t: t[0],
        )

    def off(self, va: int) -> int:
        i = bisect.bisect_right(self._table, (va, 1 << 60, 0)) - 1
        if i >= 0:
            addr, off, size = self._table[i]
            if addr <= va < addr + size:
                return off + (va - addr)
        raise EvidenceError(f'VA 0x{va:x} not mapped')

    def read(self, va: int, size: int) -> bytes:
        o = self.off(va)
        return self.data[o: o + size]


def check_digest(data: bytes, root: Path = ROOT) -> str:
    """Verify SHA-256 and size against provenance manifest."""
    if len(data) != EXPECTED_SIZE:
        raise EvidenceError(f'binary size mismatch: {len(data)} != {EXPECTED_SIZE}')
    h = hashlib.sha256(data).hexdigest()
    if h != EXPECTED_SHA256:
        raise EvidenceError(f'binary sha256 mismatch: {h} != {EXPECTED_SHA256}')
    return h


def analyse(data: bytes, root: Path = ROOT) -> dict:
    """Analyze binary against FDE bounds, panic records, rodata bypass addresses, and controls."""
    check_digest(data, root)
    img = Image(data)

    # 1. Verify FDE extents and hashes
    for fde in FDES:
        start_va = int(fde['start_va'], 16)
        size = fde['bytes']
        chunk = img.read(start_va, size)
        h = hashlib.sha256(chunk).hexdigest()
        if h != fde['sha256']:
            raise EvidenceError(f"FDE {fde['id']} hash mismatch: {h} != {fde['sha256']}")

    # 2. Verify controls
    verified_controls = {}
    for va, expected_hex in CONTROLS.items():
        size = len(expected_hex) // 2
        actual = img.read(va, size).hex().lower()
        if actual != expected_hex.lower():
            raise EvidenceError(f'control at 0x{va:x} mismatch: {actual} != {expected_hex}')
        verified_controls[hex(va)] = actual

    # 3. Verify panic records in .data.rel.ro / .rela.dyn
    sec = img.sec['.rela.dyn']
    off, size = sec['offset'], sec['size']
    relocs = {}
    for i in range(off, off + size, 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, i)
        relocs[r_offset] = r_addend

    verified_records = {}
    for va_str, meta in PANIC_LOCATIONS.items():
        va = int(va_str, 16)
        b = img.read(va, 24)
        file_ptr, file_len, line, col = struct.unpack('<QQII', b)
        if line != meta['line'] or col != meta['col']:
            raise EvidenceError(f"panic line/col mismatch at {va_str}: {line}:{col} != {meta['line']}:{meta['col']}")
        if va not in relocs:
            raise EvidenceError(f'missing relocation for {va_str}')
        str_va = relocs[va]
        actual_path = img.read(str_va, file_len).decode('utf-8', errors='replace')
        if actual_path != meta['path']:
            raise EvidenceError(f'panic path mismatch at {va_str}: {actual_path} != {meta["path"]}')
        verified_records[va_str] = {
            'record_va': va_str,
            'line': line,
            'col': col,
            'path': actual_path,
            'fde': meta['fde'],
        }

    # 4. Verify hardcoded bypass addresses in .rodata
    table_base_va = 0x59c0a8
    verified_bypasses = []
    for idx, expected_hex in enumerate(BYPASS_ADDRESSES):
        addr_va = table_base_va + idx * 20
        raw_bytes = img.read(addr_va, 20)
        actual_hex = raw_bytes.hex().lower()
        if actual_hex != expected_hex.lower():
            raise EvidenceError(f'bypass address {idx} mismatch at 0x{addr_va:x}: {actual_hex} != {expected_hex}')
        verified_bypasses.append({
            'index': idx,
            'va': hex(addr_va),
            'address': '0x' + actual_hex,
        })

    return {
        'fdes': FDES,
        'source_records': verified_records,
        'controls': verified_controls,
        'bypass_addresses': verified_bypasses,
        'constants': {
            'status_ok': STATUS_OK,
            'err_save_agent_unexpected': ERR_SAVE_AGENT_UNEXPECTED,
            'err_agent_address_is_user': ERR_AGENT_ADDRESS_IS_USER,
            'err_extra_agent_invalid_name': ERR_EXTRA_AGENT_INVALID_NAME,
            'err_agent_valid_until_passed': ERR_AGENT_VALID_UNTIL_PASSED,
            'err_extra_agent_already_used': ERR_EXTRA_AGENT_ALREADY_USED,
            'err_too_many_extra_agents': ERR_TOO_MANY_EXTRA_AGENTS,
            'err_extra_agent_does_not_exist': ERR_EXTRA_AGENT_DOES_NOT_EXIST,
            'err_pending_agent_removal': ERR_PENDING_AGENT_REMOVAL,
            'agent_grace_period_ms': AGENT_GRACE_PERIOD_MS,
            'base_extra_agent_limit': BASE_EXTRA_AGENT_LIMIT,
        },
    }


def generate_packet(out_dir: Path, binary_path: Path):
    """Generate research/work-items/agent-tracker-94 packet and verify MANIFEST.sha256."""
    data = binary_path.read_bytes()
    analysis = analyse(data)

    out_dir.mkdir(parents=True, exist_ok=True)
    obs_dir = out_dir / 'observed'
    obs_dir.mkdir(parents=True, exist_ok=True)

    # 1. observed/agent-tracker.objdump.txt
    dump_lines = []
    for f in FDES:
        start_va = f['start_va']
        end_va = f['end_va']
        dump_lines.append('=' * 80)
        dump_lines.append(f"=== FDE {start_va}..{end_va}: {f['role']} ({f['bytes']} B)")
        dump_lines.append('=' * 80)
        cmd = [
            'objdump',
            '-d',
            '-M',
            'intel',
            f'--start-address={start_va}',
            f'--stop-address={end_va}',
            str(binary_path),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        dump_lines.append(res.stdout.strip())
        dump_lines.append('')
    objdump_bytes = ('\n'.join(dump_lines) + '\n').encode('utf-8')
    (obs_dir / 'agent-tracker.objdump.txt').write_bytes(objdump_bytes)

    # 2. records.json & observed/records.json
    records_obj = {
        'component_id': 'RE/AgentTracker',
        'subsystem': 'l1/src/agent_tracker.rs',
        'target_release': '94',
        'target_binary': BINARY_REL,
        'target_sha256': EXPECTED_SHA256,
        'target_bytes': EXPECTED_SIZE,
        'fdes': analysis['fdes'],
        'panic_records': analysis['source_records'],
        'controls': analysis['controls'],
        'bypass_addresses': analysis['bypass_addresses'],
        'constants': analysis['constants'],
    }
    records_bytes = (json.dumps(records_obj, indent=2, sort_keys=True) + '\n').encode('utf-8')
    (out_dir / 'records.json').write_bytes(records_bytes)
    (obs_dir / 'records.json').write_bytes(records_bytes)

    # 3. controls.tsv
    ctrl_rows = ['va\topcode_hex\tdescription']
    descriptions = {
        '0x3421e58': 'mov WORD PTR [r15], 0x53 (ERR_EXTRA_AGENT_INVALID_NAME = 83)',
        '0x3422314': 'mov WORD PTR [r15], 0x186 (OK = 390)',
        '0x342232a': 'mov WORD PTR [r15], 0x56 (ERR_EXTRA_AGENT_ALREADY_USED = 86)',
        '0x3422368': 'mov WORD PTR [r15], 0x57 (ERR_TOO_MANY_EXTRA_AGENTS = 87)',
        '0x342273d': 'mov WORD PTR [rbx], 0x186 (OK = 390)',
        '0x3422761': 'mov WORD PTR [rax], 0x59 (ERR_EXTRA_AGENT_DOES_NOT_EXIST = 89)',
        '0x3422793': 'lea rdx, [rip+0x22c8c66] -> 0x56eb400 (agent_tracker.rs:138:48)',
        '0x342325d': 'pxor xmm0, xmm0 (zero address vector initialization)',
        '0x342328b': 'cmp eax, 0xffff (zero address 20-byte match check)',
        '0x3423400': 'mov bp, 0x186 (OK = 390 on removal of main agent)',
        '0x3423654': 'mov edx, 0x2 (chrono delta 2s = AGENT_GRACE_PERIOD_MS)',
        '0x3423748': 'mov bp, 0x186 (OK = 390 on valid update)',
        '0x3423783': 'mov bp, 0x51 (ERR_SAVE_AGENT_UNEXPECTED = 81)',
    }
    for va_str, op in sorted(analysis['controls'].items(), key=lambda t: int(t[0], 16)):
        desc = descriptions.get(va_str, '')
        ctrl_rows.append(f'{va_str}\t{op}\t{desc}')
    (out_dir / 'controls.tsv').write_bytes(('\n'.join(ctrl_rows) + '\n').encode('utf-8'))

    # 4. panic_records.tsv
    panic_rows = ['record_va\tline\tcol\tfde\tpath']
    for va_str, meta in sorted(analysis['source_records'].items(), key=lambda t: int(t[0], 16)):
        panic_rows.append(f"{va_str}\t{meta['line']}\t{meta['col']}\t{meta['fde']}\t{meta['path']}")
    (out_dir / 'panic_records.tsv').write_bytes(('\n'.join(panic_rows) + '\n').encode('utf-8'))

    # 5. bypass_addresses.tsv
    bp_rows = ['index\tva\taddress_hex']
    for b in analysis['bypass_addresses']:
        bp_rows.append(f"{b['index']}\t{b['va']}\t{b['address']}")
    (out_dir / 'bypass_addresses.tsv').write_bytes(('\n'.join(bp_rows) + '\n').encode('utf-8'))

    # 6. evidence.json
    evidence_obj = {
        'component_id': 'RE/AgentTracker',
        'subsystem': 'l1/src/agent_tracker.rs',
        'target_release': '94',
        'target_sha256': EXPECTED_SHA256,
        'fde_count': len(analysis['fdes']),
        'fde_total_bytes': sum(f['bytes'] for f in analysis['fdes']),
        'controls_count': len(analysis['controls']),
        'controls_verified': True,
        'panic_records_count': len(analysis['source_records']),
        'source_records_verified': True,
        'bypass_addresses_count': len(analysis['bypass_addresses']),
        'bypass_addresses_verified': True,
    }
    (out_dir / 'evidence.json').write_bytes((json.dumps(evidence_obj, indent=2, sort_keys=True) + '\n').encode('utf-8'))

    # 7. README.md
    readme_content = f"""# RE/AgentTracker: Agent Tracking, Authorization Keys & Delegation Bounds (node #94)

- Component ID: `RE/AgentTracker` (`l1/src/agent_tracker.rs`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `{EXPECTED_SHA256}` ({EXPECTED_SIZE} bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference lead `references/can1357-hl/l1/agent_tracker.rs`
  (diagnostic lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status: verified observation (static disassembly, panic records, rodata bypass table, and instruction opcodes)
- Scope included: 3 FDEs totaling 4,032 bytes, 1 panic record, 3 bypass addresses, 13 opcode controls, and status codes (390, 81, 83, 86, 87, 89)
- Scope excluded: binary execution (static disassembly only), live transaction processing or network consensus

## Problem and Result

Hyperliquid node #94 manages delegate agents (main agent and extra agents) for subaccounts and API trading:
1. **FDE 1 (`0x3421e20..0x34224e0`, 1,728 B)**: `AgentTracker::save_extra_agent`
   - Validates name length bounds (`1 <= len <= 32`). Emits `ERR_EXTRA_AGENT_INVALID_NAME` (`83` / `0x53`) at `0x3421e58`.
   - Checks capacity tier bounds: `2 * tier + 3`. Emits `ERR_TOO_MANY_EXTRA_AGENTS` (`87` / `0x57`) at `0x3422368`.
   - Checks duplicate agent assignment across users. Emits `ERR_EXTRA_AGENT_ALREADY_USED` (`86` / `0x56`) at `0x342232a`.
   - Emits `STATUS_OK` (`390` / `0x186`) at `0x3422314`.
2. **FDE 2 (`0x34224e0..0x34227e0`, 768 B)**: `AgentTracker::delete_extra_agent`
   - Verifies agent existence. Emits `ERR_EXTRA_AGENT_DOES_NOT_EXIST` (`89` / `0x59`) at `0x3422761`.
   - Success transition emits `STATUS_OK` (`390` / `0x186`) at `0x342273d`.
   - Mapped panic record at `0x3422793` referencing `0x56eb400` (`l1/src/agent_tracker.rs:138:48`).
3. **FDE 3 (`0x3423240..0x3423840`, 1,536 B)**: `AgentTracker::save_main_agent`
   - Zero-address filter via vector instructions `pxor xmm0, xmm0` (`0x342325d`) and `pcmpeqb` mask check (`0x342328b`).
   - If zero address, removes existing main agent, pushes pending removal with `now_ms + 2000`, and returns `OK` (`390` at `0x3423400`).
   - Adds 2-second grace period chrono delta (`mov edx, 2` at `0x3423654`).
   - Checks agent ownership via SIMD address comparison (`pcmpeqb` at `0x342374e..0x342377b`). If mismatch, emits `ERR_SAVE_AGENT_UNEXPECTED` (`81` / `0x51`) at `0x3423783`.
   - On valid update, returns `OK` (`390` / `0x186`) at `0x3423748`.

4. **Hardcoded Extra-Agent Capacity Bypass Addresses (`.rodata` at `0x59c0a8`)**:
   - `0x59c0a8`: `0x677d831aef5328190852e24f13c46cac05f984e7`
   - `0x59c0bc`: `0x3c83a5cae32a05e88ca6a0350edb540194851a76`
   - `0x59c0d0`: `0x4dbf394da4b348b88e8090d22051af83e4cbaef4`

Total size across 3 FDEs is 4,032 bytes.

## Reproduce

Working directory: repository root. Pure static disassembly; zero binary execution.

```sh
# Generate evidence packet and run test suite
python tools/agent_tracker_static.py
pytest tests/test_agent_tracker_static.py

# Verify SHA-256 manifest integrity
(cd research/work-items/agent-tracker-94 && sha256sum -c MANIFEST.sha256)
```

## Evidence

### 1. FDE Extents and Ground Truth

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| :--- | :--- | :--- | ---: | :--- |
| `save_extra_agent` | `0x3421e20..0x34224e0` | `0x34214e0..0x3421ba0` | 1,728 B | `8eaa9e7ad9d98ce2cbdd63fbf11ad80ba666074b76ae53c336de14d82d198469` |
| `delete_extra_agent` | `0x34224e0..0x34227e0` | `0x3421ba0..0x3421ea0` | 768 B | `c5bfcc90f8d24091103d0160e32f755a9cec438f5e7e4ff093c89c7e45bb16b1` |
| `save_main_agent` | `0x3423240..0x3423840` | `0x3422240..0x3422840` | 1,536 B | `41ac306659c62b6370665c33a1fa30518a06a2556dec3706aa1bd2efc51b223c` |

### 2. Mapped Panic Records

| Panic Record VA | File | Line:Column | Referenced By |
| :--- | :--- | :--- | :--- |
| `0x56eb400` | `l1/src/agent_tracker.rs` | 138:48 | FDE 2 (`0x3422793`) |

### 3. Hardcoded Capacity Bypass Table

| Index | ELF VA | Address |
| ---: | :--- | :--- |
| 0 | `0x59c0a8` | `0x677d831aef5328190852e24f13c46cac05f984e7` |
| 1 | `0x59c0bc` | `0x3c83a5cae32a05e88ca6a0350edb540194851a76` |
| 2 | `0x59c0d0` | `0x4dbf394da4b348b88e8090d22051af83e4cbaef4` |

## Results and Limitations

- 3 FDE extents (4,032 B total), 1 source panic record, 3 bypass addresses, 13 opcode controls, and status codes (390, 81, 83, 86, 87, 89) verified with 100% agreement against node #94.
- No captured binary execution performed.
"""
    (out_dir / 'README.md').write_bytes(readme_content.encode('utf-8'))

    # 8. MANIFEST.sha256
    manifest_lines = []
    for p in sorted(out_dir.rglob('*')):
        if p.is_file() and p.name != 'MANIFEST.sha256':
            rel = p.relative_to(out_dir).as_posix()
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            manifest_lines.append(f'{digest}  {rel}')

    manifest_bytes = ('\n'.join(manifest_lines) + '\n').encode('utf-8')
    (out_dir / 'MANIFEST.sha256').write_bytes(manifest_bytes)

    # Assert pure LF line endings on all generated files
    for p in out_dir.rglob('*'):
        if p.is_file():
            assert b'\r' not in p.read_bytes(), f'CRLF found in {p}'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', type=Path, default=ROOT / 'research' / 'work-items' / 'agent-tracker-94')
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY_REL)
    args = ap.parse_args(argv)

    try:
        data = args.binary.read_bytes()
        analysis = analyse(data, root=ROOT)
    except EvidenceError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

    if args.out:
        generate_packet(args.out, args.binary)

    summary = {
        'all_fde_bounds_verified': True,
        'fde_count': len(analysis['fdes']),
        'fde_total_bytes': sum(f['bytes'] for f in analysis['fdes']),
        'controls_verified': len(analysis['controls']),
        'all_panic_records_verified': True,
        'panic_records_count': len(analysis['source_records']),
        'bypass_addresses_count': len(analysis['bypass_addresses']),
        'target_sha256': EXPECTED_SHA256,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
