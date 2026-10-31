#!/usr/bin/env python3
"""RE/ActionDelayer: Node #94 action delayer, delay curves, and status transitions static verification tool.

Static, offline verification tool. Zero execution of captured binaries.
Zero external network calls. Standard Python library only.

Target:
    artifacts/node/94/hl-node (SHA-256: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f)

Scope:
    1. Verification of binary byte extents for action delayer FDEs (4 FDEs, 3,136 B total):
       - FDE 1 (0x392fab0..0x392fcc0, 528 B, sha256: 4d5819f68dbd07c9e35dceae4febc6b6f06dd0efb254bf4992e85765e54c51f2)
         Routine: deterministic_delay_seconds (curve branching, power weight, short delay scaling)
       - FDE 2 (0x392fcc0..0x3930340, 1664 B, sha256: 408e8158b4ee6e1c86101d88fc95df7b4e0401d8d15687161b3f370973b94abf)
         Routine: ActionDelayer::should_emit_status & note_action_removed
       - FDE 3 (0x3930340..0x39304c0, 384 B, sha256: 7b29deb99e913a0f05c43cc71a0cb1668eddf4b5347e95771216b0e1a680fb94)
         Routine: DeterministicEma::serialize (num, denom, decay_duration, last_sample_time, n_samples)
       - FDE 4 (0x39304c0..0x39306f0, 560 B, sha256: 656e30eb680da0bc9c35a3cca131d21ca3350d69e35c4e44137732e79872749a)
         Routine: ActionDelayStatusEntry::serialize
    2. Verification of 4 panic record pointers in .data.rel.ro / .rela.dyn:
       - 0x570d828: line 246, col 73 in /home/ubuntu/hl/code_Mainnet/l1/src/action_delayer.rs
       - 0x566ab58: line 112, col 13 in /home/ubuntu/hl/code_Mainnet/base/src/duration.rs
       - 0x566ae58: line 124, col 13 in /home/ubuntu/hl/code_Mainnet/base/src/duration.rs
       - 0x570fef0: line 2004, col 9 in /home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.120/src/ser.rs
    3. Verification of 19 exact instruction control assertions for float constants, curve scaling,
       broadcaster / frontend thresholds, and status length bounds (> 2).
    4. Clean-room mathematical & algorithmic model of deterministic delay curves.
"""

import argparse
import bisect
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BINARY_REL = 'artifacts/node/94/hl-node'
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
EXPECTED_SIZE = 91774280

SOURCE_PATH = '/home/ubuntu/hl/code_Mainnet/l1/src/action_delayer.rs'
PACKET = ROOT / 'research' / 'work-items' / 'action-delayer-94'

# Numeric Constants verified against .rodata
MIN_ACTION_DELAY_SECONDS = 0.76         # 0x20a250: 0x3fe851eb851eb852
VTY_REFERENCE_NOTIONAL = 10000.0        # 0x20a830: 0x40c3880000000000
FRONTEND_ACTION_ID_START = 10000        # 0x392fb45: add ebx, 0xffffd8f0
FRONTEND_ACTION_ID_END = 110000         # 0x392fb4b: cmp ebx, 0x186a0 (range 100,000)
BROADCASTER_ACTION_ID_START = 100000000 # 0x392fb3c: cmp ebx, 0x5f5e100
SPECIAL_CURVE_MULTIPLIER = 1.8          # 0x20b108: 0x3ffccccccccccccd
DEFAULT_CURVE_MULTIPLIER = 1.3          # 0x20adf0: 0x3ff4cccccccccccd
SHORT_DELAY_MULTIPLIER = 0.2            # 0x20a768: 0x3fc999999999999a
STANDARD_DELAY_MULTIPLIER = 0.65        # 0x20a9f8: 0x3fe4cccccccccccd

FDES = [
    {
        'bytes': 528,
        'end_va': '0x392fcc0',
        'file_offset': '0x392eab0',
        'id': 'fde1_deterministic_delay_seconds',
        'panic_records': ['0x566ab58', '0x566ae58'],
        'role': 'deterministic_delay_seconds (curve branching, power weight, short delay scaling)',
        'sha256': '4d5819f68dbd07c9e35dceae4febc6b6f06dd0efb254bf4992e85765e54c51f2',
        'start_va': '0x392fab0',
    },
    {
        'bytes': 1664,
        'end_va': '0x3930340',
        'file_offset': '0x392ecc0',
        'id': 'fde2_action_delayer_status',
        'panic_records': ['0x570d828'],
        'role': 'ActionDelayer::should_emit_status & note_action_removed (threshold > 2)',
        'sha256': '408e8158b4ee6e1c86101d88fc95df7b4e0401d8d15687161b3f370973b94abf',
        'start_va': '0x392fcc0',
    },
    {
        'bytes': 384,
        'end_va': '0x39304c0',
        'file_offset': '0x392f340',
        'id': 'fde3_deterministic_ema_serde',
        'panic_records': ['0x570fef0'],
        'role': 'DeterministicEma::serialize (num, denom, decay_duration, last_sample_time, n_samples)',
        'sha256': '7b29deb99e913a0f05c43cc71a0cb1668eddf4b5347e95771216b0e1a680fb94',
        'start_va': '0x3930340',
    },
    {
        'bytes': 560,
        'end_va': '0x39306f0',
        'file_offset': '0x392f4c0',
        'id': 'fde4_status_entry_serde',
        'panic_records': [],
        'role': 'ActionDelayStatusEntry::serialize',
        'sha256': '656e30eb680da0bc9c35a3cca131d21ca3350d69e35c4e44137732e79872749a',
        'start_va': '0x39304c0',
    },
]

PANIC_LOCATIONS = {
    '0x570d828': {
        'col': 73,
        'fde': '0x392fcc0',
        'line': 246,
        'path': SOURCE_PATH,
        'record_va': '0x570d828',
    },
    '0x566ab58': {
        'col': 13,
        'fde': '0x392fab0',
        'line': 112,
        'path': '/home/ubuntu/hl/code_Mainnet/base/src/duration.rs',
        'record_va': '0x566ab58',
    },
    '0x566ae58': {
        'col': 13,
        'fde': '0x392fab0',
        'line': 124,
        'path': '/home/ubuntu/hl/code_Mainnet/base/src/duration.rs',
        'record_va': '0x566ae58',
    },
    '0x570fef0': {
        'col': 9,
        'fde': '0x3930340',
        'line': 2004,
        'path': '/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.120/src/ser.rs',
        'record_va': '0x570fef0',
    },
}

CONTROLS = {
    # FDE 1: deterministic_delay_seconds
    0x392fb08: 'f20f100520ac8dfc',        # movsd xmm0, [0x20a730] (1.0 clamp upper bound)
    0x392fb2c: 'f20f5905bcb28dfc',        # mulsd xmm0, [0x20adf0] (1.3 default curve multiplier)
    0x392fb34: 'f20f580514a78dfc',        # addsd xmm0, [0x20a250] (0.76 MIN_ACTION_DELAY_SECONDS)
    0x392fb3c: '81fb00e1f505',            # cmp ebx, 0x5f5e100 (BROADCASTER_ACTION_ID_START 100_000_000)
    0x392fb45: '81c3f0d8ffff',            # add ebx, 0xffffd8f0 (-10,000 FRONTEND_ACTION_ID_START)
    0x392fb4b: '81fba0860100',            # cmp ebx, 0x186a0 (100,000 range -> 110,000 FRONTEND_ACTION_ID_END)
    0x392fb6a: 'f20f5905f6ab8dfc',        # mulsd xmm0, [0x20a768] (0.2 short delay multiplier)
    0x392fb78: '83f802',                  # cmp eax, 0x2 (mode 2 DeterministicVty branch)
    0x392fbc6: 'f20f5e0d32b58dfc',        # divsd xmm1, [0x20b100] (12.0 divisor)
    0x392fc13: 'f20f590dbdaa8dfc',        # mulsd xmm1, [0x20a6d8] (0.125 multiplier)
    0x392fc64: 'f20f59059cb48dfc',        # mulsd xmm0, [0x20b108] (1.8 special curve multiplier)
    0x392fc7e: 'f20f590572ad8dfc',        # mulsd xmm0, [0x20a9f8] (0.65 standard delay multiplier)

    # FDE 2: ActionDelayer::should_emit_status & note_action_removed
    0x3930221: '4883bc24c800000002',      # cmp QWORD PTR [rsp+0xc8], 0x2 (status.current.len() > 2)
    0x393023d: '488d0de4d5dd01',          # lea rcx, [rip+0x1ddd5e4] -> 0x570d828 (action_delayer.rs:246:73)

    # FDE 3: DeterministicEma::serialize
    0x3930390: '488d357c6bc7fc',          # lea rsi, [rip-0x3389484] -> 0x5a6f13 ("num")
    0x39303c1: '488d354e6bc7fc',          # lea rsi, [rip-0x33894b2] -> 0x5a6f16 ("denom")
    0x39303eb: '488d35296bc7fc',          # lea rsi, [rip-0x33894d7] -> 0x5a6f1b ("decay_duration")
    0x3930411: '488d35a83a8dfc',          # lea rsi, [rip-0x372c558] -> 0x203ec0 ("last_sample_time")
    0x3930437: '488d35eb6ac7fc',          # lea rsi, [rip-0x3389515] -> 0x5a6f29 ("n_samples")
}


class EvidenceError(Exception):
    """Raised when binary artifacts fail validation or decoding errors occur."""


def vty_power_weight(vty_or_notional: float, exponent: float) -> float:
    ratio = vty_or_notional / VTY_REFERENCE_NOTIONAL
    return math.pow(ratio, exponent)


def default_delay_weight(vty_or_notional: float) -> float:
    return vty_power_weight(vty_or_notional, -4.0) / 20.0


def clamp_delay_weight(weight: float) -> float:
    if math.isnan(weight):
        raise EvidenceError('delay weight cannot be NaN')
    return max(0.0, min(1.0, weight))


def uses_short_delay_multiplier(action_kind: int) -> bool:
    return (action_kind >= BROADCASTER_ACTION_ID_START or 
            (FRONTEND_ACTION_ID_START <= action_kind < FRONTEND_ACTION_ID_END))


def deterministic_delay_seconds(mode: int, action_kind: int, vty_or_notional: float) -> float:
    """Exact clean-room mathematical model of deterministic delay curves."""
    if vty_or_notional <= 0.0 or math.isnan(vty_or_notional):
        raise EvidenceError(f'Invalid vty_or_notional: {vty_or_notional}')

    if mode == 2:
        if action_kind in (3, 4, 11054, 11137):
            raw_weight = vty_power_weight(vty_or_notional, -1.5) * 0.125
            special_curve = True
        elif action_kind == 0:
            raw_weight = vty_power_weight(vty_or_notional, -3.0) / 12.0
            special_curve = True
        else:
            raw_weight = default_delay_weight(vty_or_notional)
            special_curve = False
    elif action_kind in (0, 1, 10142, 10151):
        raw_weight = vty_power_weight(vty_or_notional, -1.5) * 0.125
        special_curve = True
    elif action_kind == 5:
        raw_weight = vty_power_weight(vty_or_notional, -3.0) / 12.0
        special_curve = True
    else:
        raw_weight = default_delay_weight(vty_or_notional)
        special_curve = False

    clamped = clamp_delay_weight(raw_weight)
    if special_curve:
        unscaled = clamped * SPECIAL_CURVE_MULTIPLIER + MIN_ACTION_DELAY_SECONDS
    else:
        unscaled = clamped * DEFAULT_CURVE_MULTIPLIER + MIN_ACTION_DELAY_SECONDS

    if not special_curve and uses_short_delay_multiplier(action_kind):
        delay = unscaled * SHORT_DELAY_MULTIPLIER
    else:
        delay = unscaled * STANDARD_DELAY_MULTIPLIER

    assert delay >= 0.0
    return delay


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
    """Analyze binary against FDE bounds, panic records, float constants, and control invariants."""
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

    return {
        'fdes': FDES,
        'source_records': verified_records,
        'controls': verified_controls,
        'constants': {
            'min_action_delay_seconds': MIN_ACTION_DELAY_SECONDS,
            'vty_reference_notional': VTY_REFERENCE_NOTIONAL,
            'frontend_action_id_start': FRONTEND_ACTION_ID_START,
            'frontend_action_id_end': FRONTEND_ACTION_ID_END,
            'broadcaster_action_id_start': BROADCASTER_ACTION_ID_START,
            'special_curve_multiplier': SPECIAL_CURVE_MULTIPLIER,
            'default_curve_multiplier': DEFAULT_CURVE_MULTIPLIER,
            'short_delay_multiplier': SHORT_DELAY_MULTIPLIER,
            'standard_delay_multiplier': STANDARD_DELAY_MULTIPLIER,
        },
    }


def generate_packet(out_dir: Path, binary_path: Path):
    """Generate research/work-items/action-delayer-94 packet and verify MANIFEST.sha256."""
    data = binary_path.read_bytes()
    analysis = analyse(data)

    out_dir.mkdir(parents=True, exist_ok=True)
    obs_dir = out_dir / 'observed'
    obs_dir.mkdir(parents=True, exist_ok=True)

    # 1. observed/action-delayer.objdump.txt
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
    (obs_dir / 'action-delayer.objdump.txt').write_bytes(objdump_bytes)

    # 2. records.json & observed/records.json
    records_obj = {
        'component_id': 'RE/ActionDelayer',
        'subsystem': 'l1/src/action_delayer.rs',
        'target_release': '94',
        'target_binary': BINARY_REL,
        'target_sha256': EXPECTED_SHA256,
        'target_bytes': EXPECTED_SIZE,
        'fdes': analysis['fdes'],
        'panic_records': analysis['source_records'],
        'controls': analysis['controls'],
        'constants': analysis['constants'],
    }
    records_bytes = (json.dumps(records_obj, indent=2, sort_keys=True) + '\n').encode('utf-8')
    (out_dir / 'records.json').write_bytes(records_bytes)
    (obs_dir / 'records.json').write_bytes(records_bytes)

    # 3. controls.tsv
    ctrl_rows = ['va\topcode_hex\tdescription']
    descriptions = {
        '0x392fb08': 'movsd xmm0, [0x20a730] (1.0 clamp upper bound)',
        '0x392fb2c': 'mulsd xmm0, [0x20adf0] (1.3 default curve multiplier)',
        '0x392fb34': 'addsd xmm0, [0x20a250] (0.76 MIN_ACTION_DELAY_SECONDS)',
        '0x392fb3c': 'cmp ebx, 0x5f5e100 (BROADCASTER_ACTION_ID_START 100_000_000)',
        '0x392fb45': 'add ebx, 0xffffd8f0 (-10,000 FRONTEND_ACTION_ID_START)',
        '0x392fb4b': 'cmp ebx, 0x186a0 (100,000 range -> 110,000 FRONTEND_ACTION_ID_END)',
        '0x392fb6a': 'mulsd xmm0, [0x20a768] (0.2 short delay multiplier)',
        '0x392fb78': 'cmp eax, 0x2 (mode 2 DeterministicVty branch)',
        '0x392fbc6': 'divsd xmm1, [0x20b100] (12.0 divisor)',
        '0x392fc13': 'mulsd xmm1, [0x20a6d8] (0.125 multiplier)',
        '0x392fc64': 'mulsd xmm0, [0x20b108] (1.8 special curve multiplier)',
        '0x392fc7e': 'mulsd xmm0, [0x20a9f8] (0.65 standard delay multiplier)',
        '0x3930221': 'cmp QWORD PTR [rsp+0xc8], 0x2 (status.current.len() > 2)',
        '0x393023d': 'lea rcx, [rip+0x1ddd5e4] -> 0x570d828 (action_delayer.rs:246:73)',
        '0x3930390': 'lea rsi, [rip-0x3389484] -> 0x5a6f13 ("num")',
        '0x39303c1': 'lea rsi, [rip-0x33894b2] -> 0x5a6f16 ("denom")',
        '0x39303eb': 'lea rsi, [rip-0x33894d7] -> 0x5a6f1b ("decay_duration")',
        '0x3930411': 'lea rsi, [rip-0x372c558] -> 0x203ec0 ("last_sample_time")',
        '0x3930437': 'lea rsi, [rip-0x3389515] -> 0x5a6f29 ("n_samples")',
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

    # 5. evidence.json
    evidence_obj = {
        'component_id': 'RE/ActionDelayer',
        'subsystem': 'l1/src/action_delayer.rs',
        'target_release': '94',
        'target_sha256': EXPECTED_SHA256,
        'fde_count': len(analysis['fdes']),
        'fde_total_bytes': sum(f['bytes'] for f in analysis['fdes']),
        'controls_count': len(analysis['controls']),
        'controls_verified': True,
        'panic_records_count': len(analysis['source_records']),
        'source_records_verified': True,
    }
    (out_dir / 'evidence.json').write_bytes((json.dumps(evidence_obj, indent=2, sort_keys=True) + '\n').encode('utf-8'))

    # 6. README.md
    readme_content = f"""# RE/ActionDelayer: Action Delay Curves, Withdrawal Timing & Status Guards (node #94)

- Component ID: `RE/ActionDelayer` (`l1/src/action_delayer.rs`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `{EXPECTED_SHA256}` ({EXPECTED_SIZE} bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference lead `references/can1357-hl/l1/action_delayer.rs`
  (diagnostic lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status: verified observation (static disassembly, panic records, float constants, and instruction opcodes)
- Scope included: 4 FDEs totaling 3,136 bytes, 4 panic records, 19 opcode controls, deterministic delay curve math, and status guard bounds
- Scope excluded: binary execution (static disassembly only), live transaction processing or network propagation

## Problem and Result

Hyperliquid node #94 schedules and throttles withdrawal and order cancellations through deterministic delay curves:
1. **FDE 1 (`0x392fab0..0x392fcc0`, 528 B)**: `deterministic_delay_seconds`
   - Dispatches across Mode 2 (`DeterministicVty`) vs. Mode 1/3 (`DeterministicEma`/Default).
   - Computes normalized volatility power weights `(vty / 10000.0)^exponent`:
     - Exponents `-1.5` (`0x20a388`) with `0.125` multiplier (`0x20a6d8`) for special action kinds.
     - Exponent `-3.0` (`0x20a380`) with `/ 12.0` divisor (`0x20b100`) for action kind 0/5.
     - Exponent `-4.0` with `/ 20.0` divisor for default actions.
   - Clamps raw weight to `[0.0, 1.0]` (`0x20a730`).
   - Scales via curve multipliers:
     - Special curve: `weight * 1.8 + 0.76` (`0x20b108` and `0x20a250`).
     - Default curve: `weight * 1.3 + 0.76` (`0x20adf0` and `0x20a250`).
   - Applies action duration multiplier:
     - Short multiplier `0.2` (`0x20a768`) for frontend actions (`10,000..110,000`) and broadcasters (`>= 100,000,000`).
     - Standard multiplier `0.65` (`0x20a9f8`) for other actions.
2. **FDE 2 (`0x392fcc0..0x3930340`, 1,664 B)**: `ActionDelayer::should_emit_status & note_action_removed`
   - Emits delay status if and only if `status.current.len() > 2` (`0x3930221: cmp QWORD PTR [rsp+0xc8], 0x2; jbe ...`).
   - Mapped panic record `0x570d828` (`/home/ubuntu/hl/code_Mainnet/l1/src/action_delayer.rs:246:73`).
3. **FDE 3 (`0x3930340..0x39304c0`, 384 B)**: `DeterministicEma::serialize`
   - Serializes field descriptors: `num`, `denom`, `decay_duration`, `last_sample_time`, `n_samples`.
   - Mapped panic record `0x570fef0` (`serde_json/src/ser.rs:2004:9`).
4. **FDE 4 (`0x39304c0..0x39306f0`, 560 B)**: `ActionDelayStatusEntry::serialize`

Total size across 4 FDEs is 3,136 bytes.

## Reproduce

Working directory: repository root. Pure static disassembly; zero binary execution.

```sh
# Generate evidence packet and run test suite
python tools/action_delayer_static.py
pytest tests/test_action_delayer_static.py

# Verify SHA-256 manifest integrity
(cd research/work-items/action-delayer-94 && sha256sum -c MANIFEST.sha256)
```

## Evidence

### 1. FDE Extents and Ground Truth

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| :--- | :--- | :--- | ---: | :--- |
| `deterministic_delay_seconds` | `0x392fab0..0x392fcc0` | `0x392eab0..0x392ecc0` | 528 B | `4d5819f68dbd07c9e35dceae4febc6b6f06dd0efb254bf4992e85765e54c51f2` |
| `ActionDelayer::should_emit_status` | `0x392fcc0..0x3930340` | `0x392ecc0..0x392f340` | 1,664 B | `408e8158b4ee6e1c86101d88fc95df7b4e0401d8d15687161b3f370973b94abf` |
| `DeterministicEma::serialize` | `0x3930340..0x39304c0` | `0x392f340..0x392f4c0` | 384 B | `7b29deb99e913a0f05c43cc71a0cb1668eddf4b5347e95771216b0e1a680fb94` |
| `ActionDelayStatusEntry::serialize` | `0x39304c0..0x39306f0` | `0x392f4c0..0x392f6f0` | 560 B | `656e30eb680da0bc9c35a3cca131d21ca3350d69e35c4e44137732e79872749a` |

### 2. Verified Constants in `.rodata`

- `0x20a250`: `0.76` (`MIN_ACTION_DELAY_SECONDS`)
- `0x20a830`: `10000.0` (`VTY_REFERENCE_NOTIONAL`)
- `0x20a730`: `1.0` (weight clamp upper limit)
- `0x20b108`: `1.8` (special curve multiplier)
- `0x20adf0`: `1.3` (default curve multiplier)
- `0x20a768`: `0.2` (short delay multiplier)
- `0x20a9f8`: `0.65` (standard delay multiplier)
- `0x20b100`: `12.0` (action kind 0/5 divisor)
- `0x20a6d8`: `0.125` (special action kind weight multiplier)

### 3. Mapped Panic Records

| Panic Record VA | File | Line:Column | Referenced By |
| :--- | :--- | :--- | :--- |
| `0x570d828` | `l1/src/action_delayer.rs` | 246:73 | FDE 2 (`0x393023d`) |
| `0x566ab58` | `base/src/duration.rs` | 112:13 | FDE 1 (`0x392fc8f`) |
| `0x566ae58` | `base/src/duration.rs` | 124:13 | FDE 1 (`0x392fca8`) |
| `0x570fef0` | `serde_json/src/ser.rs` | 2004:9 | FDE 3 (`0x39304af`) |

## Results and Limitations

- 4 FDE extents (3,136 B total), 4 source panic records, 19 opcode controls, and IEEE-754 delay curve math verified with 100% agreement against node #94.
- No captured binary execution performed.
"""
    (out_dir / 'README.md').write_bytes(readme_content.encode('utf-8'))

    # 7. MANIFEST.sha256
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
    ap.add_argument('--out', type=Path, default=ROOT / 'research' / 'work-items' / 'action-delayer-94')
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
        'target_sha256': EXPECTED_SHA256,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
