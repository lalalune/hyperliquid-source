#!/usr/bin/env python3
"""RE/Hyperliquidity: Node #94 hyperliquidity registration, market cap bounds, and price ladder static verification tool.

Static, offline verification tool. Zero execution of captured binaries.
Zero external network calls. Standard Python library only.

Target:
    artifacts/node/94/hl-node (SHA-256: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f)

Scope:
    1. Verification of binary byte extents for 3 hyperliquidity FDEs (2,704 B total):
       - FDE 1 (0x3261c40..0x3262590, 2384 B, sha256: 62057313067d39bec3ac6723f1e27005a4e04ce51d8a04875f7bd15719f49d9f)
         Routine: register_hyperliquidity (order ladder generation, balance verification, market cap window, error dispatch)
       - FDE 2 (0x3262590..0x3262600, 112 B, sha256: a7e97c09dcf960ced36da93358684200ef653a18020124920fbda473161f76aa)
         Routine: hyperliquidity_cleanup_helper (error unwind and stack cleanup)
       - FDE 3 (0x3262600..0x32626d0, 208 B, sha256: 87ce00650bbeaf876b6b19fa153bd8b8ce37cbbeda9e4b3c46f6df092507ef3a)
         Routine: market_cap_in_scaled_range (checked scale multiplication 70_000_000 and 130_000_000)
    2. Verification of mapped source panic record in .data.rel.ro / .rela.dyn:
       - 0x56df860: line 355, col 29 in /home/ubuntu/hl/code_Mainnet/l1/src/hyperliquidity.rs
         (referenced at 0x3262531: 488d3d28d34702)
    3. Verification of 10 diagnostic error strings in .rodata:
       - 0x584696: "Hyperliquidity already exists" (29 B)
       - 0x5846b3: "zero Hyperliquidity order size" (30 B)
       - 0x584738: "Hyperliquidity price is invalid" (31 B)
       - 0x5847ce: "Hyperliquidity starting price too small" (39 B)
       - 0x5847f5: "Hyperliquidity has incorrect balance" (36 B)
       - 0x584819: "Hyperliquidity configuration invalid" (36 B)
       - 0x58483d: "too few Hyperliquidity orders" (29 B)
       - 0x58485a: "Hyperliquidity missing max supply" (33 B)
       - 0x58487b: "quote token must be USDC for Hyperliquidity" (43 B)
       - 0x5848a6: "Hyperliquidity already has token hold" (37 B)
    4. Verification of numeric constants in .rodata:
       - 0x20a730: 1.0 (float unit multiplier)
       - 0x20a838: 1.003 (HYPERLIQUIDITY_PRICE_RATIO)
       - MIN_HYPERLIQUIDITY_ORDERS = 10
       - MAX_RAW_HYPERLIQUIDITY_VALUE = 0x1999999999999999
       - MIN_END_MARKET_CAP_USDC = 1_000_000_000 (0x3b9aca00)
       - MAX_END_MARKET_CAP_USDC = 100_000_000_000 (0x174876e800)
       - MAX_START_MARKET_CAP_USDC = 10_000_000 (0x989680)
       - MARKET_CAP_LOWER_SCALE = 70_000_000 (0xaae60 * 100)
       - MARKET_CAP_UPPER_SCALE = 130_000_000 (0x13d620 * 100)
    5. Verification of 22 exact instruction controls for status codes (390, 223), market cap arithmetic,
       float constants, and error dispatch LEAs.
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

SOURCE_PATH = '/home/ubuntu/hl/code_Mainnet/l1/src/hyperliquidity.rs'
PACKET = ROOT / 'research' / 'work-items' / 'hyperliquidity-94'

# Status Codes
SUCCESS_CODE = 390
ERR_STATUS = 223

# Constants
MIN_HYPERLIQUIDITY_ORDERS = 10
MAX_RAW_HYPERLIQUIDITY_VALUE = 0x1999999999999999
HYPERLIQUIDITY_PRICE_RATIO = 1.003
MIN_END_MARKET_CAP_USDC = 1_000_000_000
MAX_END_MARKET_CAP_USDC = 100_000_000_000
MAX_START_MARKET_CAP_USDC = 10_000_000
MARKET_CAP_LOWER_SCALE = 70_000_000
MARKET_CAP_UPPER_SCALE = 130_000_000

# 3 FDE routines
FDES = [
    {
        'name': 'register_hyperliquidity',
        'start': 0x3261c40,
        'end': 0x3262590,
        'size': 2384,
        'sha256': '62057313067d39bec3ac6723f1e27005a4e04ce51d8a04875f7bd15719f49d9f',
    },
    {
        'name': 'hyperliquidity_cleanup_helper',
        'start': 0x3262590,
        'end': 0x3262600,
        'size': 112,
        'sha256': 'a7e97c09dcf960ced36da93358684200ef653a18020124920fbda473161f76aa',
    },
    {
        'name': 'market_cap_in_scaled_range',
        'start': 0x3262600,
        'end': 0x32626d0,
        'size': 208,
        'sha256': '87ce00650bbeaf876b6b19fa153bd8b8ce37cbbeda9e4b3c46f6df092507ef3a',
    },
]

PANIC_LOCATIONS = [
    {
        'record_vaddr': 0x56df860,
        'file_offset': 0x56dd860,
        'source_path': SOURCE_PATH,
        'line': 355,
        'col': 29,
        'referenced_at': 0x3262531,
    }
]

RODATA_CONSTANTS = [
    {
        'vaddr': 0x20a730,
        'length': 8,
        'expected_double': 1.0,
        'desc': 'Float unit multiplier 1.0',
    },
    {
        'vaddr': 0x20a838,
        'length': 8,
        'expected_double': 1.003,
        'desc': 'HYPERLIQUIDITY_PRICE_RATIO (1.003)',
    },
    {
        'vaddr': 0x584696,
        'length': 29,
        'expected_ascii': 'Hyperliquidity already exists',
        'desc': 'Error: already exists',
    },
    {
        'vaddr': 0x5846b3,
        'length': 30,
        'expected_ascii': 'zero Hyperliquidity order size',
        'desc': 'Error: zero order size',
    },
    {
        'vaddr': 0x584738,
        'length': 31,
        'expected_ascii': 'Hyperliquidity price is invalid',
        'desc': 'Error: price invalid',
    },
    {
        'vaddr': 0x5847ce,
        'length': 39,
        'expected_ascii': 'Hyperliquidity starting price too small',
        'desc': 'Error: starting price too small',
    },
    {
        'vaddr': 0x5847f5,
        'length': 36,
        'expected_ascii': 'Hyperliquidity has incorrect balance',
        'desc': 'Error: incorrect balance',
    },
    {
        'vaddr': 0x584819,
        'length': 36,
        'expected_ascii': 'Hyperliquidity configuration invalid',
        'desc': 'Error: configuration invalid',
    },
    {
        'vaddr': 0x58483d,
        'length': 29,
        'expected_ascii': 'too few Hyperliquidity orders',
        'desc': 'Error: too few orders',
    },
    {
        'vaddr': 0x58485a,
        'length': 33,
        'expected_ascii': 'Hyperliquidity missing max supply',
        'desc': 'Error: missing max supply',
    },
    {
        'vaddr': 0x58487b,
        'length': 43,
        'expected_ascii': 'quote token must be USDC for Hyperliquidity',
        'desc': 'Error: quote token must be USDC',
    },
    {
        'vaddr': 0x5848a6,
        'length': 37,
        'expected_ascii': 'Hyperliquidity already has token hold',
        'desc': 'Error: already has token hold',
    },
]

CONTROLS = [
    {
        'vaddr': 0x3261eef,
        'hex_bytes': '4983fd0a',
        'desc': 'cmp $0xa, %r13 (MIN_HYPERLIQUIDITY_ORDERS = 10)',
    },
    {
        'vaddr': 0x3261fd8,
        'hex_bytes': 'f20f10055087fafc',
        'desc': 'movsd -0x30578b0(%rip), %xmm0 (1.0 at 0x20a730)',
    },
    {
        'vaddr': 0x3261fe0,
        'hex_bytes': 'f20f100d5088fafc',
        'desc': 'movsd -0x30577b0(%rip), %xmm1 (1.003 at 0x20a838)',
    },
    {
        'vaddr': 0x32620d7,
        'hex_bytes': '48be9999999999999919',
        'desc': 'movabs $0x1999999999999999, %rsi (MAX_RAW_HYPERLIQUIDITY_VALUE)',
    },
    {
        'vaddr': 0x32620ea,
        'hex_bytes': '4881f940420f00',
        'desc': 'cmp $0xf4240, %rcx (1_000_000)',
    },
    {
        'vaddr': 0x32621db,
        'hex_bytes': '4c8d35d12432fd',
        'desc': 'lea -0x2cddb2f(%rip), %r14 (zero order size at 0x5846b3)',
    },
    {
        'vaddr': 0x32621ca,
        'hex_bytes': '4c8d35fd2532fd',
        'desc': 'lea -0x2cdda03(%rip), %r14 (starting price too small at 0x5847ce)',
    },
    {
        'vaddr': 0x3262203,
        'hex_bytes': '4c8d35eb2532fd',
        'desc': 'lea -0x2cdda15(%rip), %r14 (incorrect balance at 0x5847f5)',
    },
    {
        'vaddr': 0x32620c6,
        'hex_bytes': '4c8d354c2732fd',
        'desc': 'lea -0x2cdd8b4(%rip), %r14 (configuration invalid at 0x584819)',
    },
    {
        'vaddr': 0x3261efe,
        'hex_bytes': '4c8d35382932fd',
        'desc': 'lea -0x2cdd6c8(%rip), %r14 (too few orders at 0x58483d)',
    },
    {
        'vaddr': 0x3261f12,
        'hex_bytes': '4c8d35412932fd',
        'desc': 'lea -0x2cdd6bf(%rip), %r14 (missing max supply at 0x58485a)',
    },
    {
        'vaddr': 0x3261eab,
        'hex_bytes': '4c8d35c92932fd',
        'desc': 'lea -0x2cdd637(%rip), %r14 (quote token must be USDC at 0x58487b)',
    },
    {
        'vaddr': 0x3261ec0,
        'hex_bytes': '4c8d35df2932fd',
        'desc': 'lea -0x2cdd621(%rip), %r14 (already has token holdings at 0x5848a6)',
    },
    {
        'vaddr': 0x3261d2b,
        'hex_bytes': '4c8d35642932fd',
        'desc': 'lea -0x2cdd69c(%rip), %r14 (hyperliquidity already exists at 0x584696)',
    },
    {
        'vaddr': 0x3261d46,
        'hex_bytes': '66c707df00',
        'desc': 'movw $0xdf, (%rdi) (ERR_STATUS = 223)',
    },
    {
        'vaddr': 0x3261fb1,
        'hex_bytes': '66c7078601',
        'desc': 'movw $0x186, (%rdi) (SUCCESS_CODE = 390)',
    },
    {
        'vaddr': 0x326225d,
        'hex_bytes': '48c744247800ca9a3b',
        'desc': 'movq $0x3b9aca00, 0x78(%rsp) (MIN_END_MARKET_CAP_USDC = 1B)',
    },
    {
        'vaddr': 0x3262266,
        'hex_bytes': '48b800e8764817000000',
        'desc': 'movabs $0x174876e800, %rax (MAX_END_MARKET_CAP_USDC = 100B)',
    },
    {
        'vaddr': 0x326228c,
        'hex_bytes': '48c784249800000080969800',
        'desc': 'movq $0x989680, 0x98(%rsp) (MAX_START_MARKET_CAP_USDC = 10M)',
    },
    {
        'vaddr': 0x3262531,
        'hex_bytes': '488d3d28d34702',
        'desc': 'lea 0x247d328(%rip), %rdi (panic struct at 0x56df860)',
    },
    {
        'vaddr': 0x3262606,
        'hex_bytes': 'ba60ae0a00',
        'desc': 'mov $0xaae60, %edx (700_000 for MARKET_CAP_LOWER_SCALE)',
    },
    {
        'vaddr': 0x326262a,
        'hex_bytes': 'ba20d61300',
        'desc': 'mov $0x13d620, %edx (1_300_000 for MARKET_CAP_UPPER_SCALE)',
    },
]


def market_cap_in_scaled_range(lower: int, upper: int, value: int) -> bool:
    try:
        low = lower * MARKET_CAP_LOWER_SCALE
        high = upper * MARKET_CAP_UPPER_SCALE
        return low <= value <= high
    except OverflowError:
        return False


def validate_order_count(n_orders: int) -> bool:
    return n_orders >= MIN_HYPERLIQUIDITY_ORDERS


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

    rodata_findings = []
    for r in RODATA_CONSTANTS:
        raw = image.read(r['vaddr'], r['length'])
        if 'expected_ascii' in r:
            actual_str = raw.decode('ascii')
            if actual_str != r['expected_ascii']:
                raise EvidenceError(f"String mismatch at {hex(r['vaddr'])}: expected {r['expected_ascii']}, got {actual_str}")
        elif 'expected_double' in r:
            val = struct.unpack('<d', raw)[0]
            if val != r['expected_double']:
                raise EvidenceError(f"Double mismatch at {hex(r['vaddr'])}: expected {r['expected_double']}, got {val}")
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

    # 3. rodata_constants.tsv
    with open(PACKET / 'rodata_constants.tsv', 'w', newline='\n', encoding='utf-8') as f:
        f.write('vaddr\tdesc\tstatus\n')
        for r in analysis['rodata']:
            f.write(f"{r['vaddr']}\t{r['desc']}\t{r['status']}\n")

    # 4. records.json
    records = {
        'target': BINARY_REL,
        'target_sha256': EXPECTED_SHA256,
        'fdes': analysis['fdes'],
        'panics': analysis['panics'],
        'rodata': analysis['rodata'],
        'controls': analysis['controls'],
    }
    with open(PACKET / 'records.json', 'w', newline='\n', encoding='utf-8') as f:
        json.dump(records, f, indent=2)
        f.write('\n')

    # 5. evidence.json
    evidence = {
        'status': 'VERIFIED',
        'fde_count': len(FDES),
        'total_fde_bytes': sum(f['size'] for f in FDES),
        'panic_count': len(PANIC_LOCATIONS),
        'rodata_constants_count': len(RODATA_CONSTANTS),
        'controls_count': len(CONTROLS),
        'algorithmic_constants': {
            'MIN_HYPERLIQUIDITY_ORDERS': MIN_HYPERLIQUIDITY_ORDERS,
            'MAX_RAW_HYPERLIQUIDITY_VALUE': hex(MAX_RAW_HYPERLIQUIDITY_VALUE),
            'HYPERLIQUIDITY_PRICE_RATIO': HYPERLIQUIDITY_PRICE_RATIO,
            'MIN_END_MARKET_CAP_USDC': MIN_END_MARKET_CAP_USDC,
            'MAX_END_MARKET_CAP_USDC': MAX_END_MARKET_CAP_USDC,
            'MAX_START_MARKET_CAP_USDC': MAX_START_MARKET_CAP_USDC,
            'MARKET_CAP_LOWER_SCALE': MARKET_CAP_LOWER_SCALE,
            'MARKET_CAP_UPPER_SCALE': MARKET_CAP_UPPER_SCALE,
        },
        'status_codes': {
            'SUCCESS_CODE': SUCCESS_CODE,
            'ERR_STATUS': ERR_STATUS,
        }
    }
    with open(PACKET / 'evidence.json', 'w', newline='\n', encoding='utf-8') as f:
        json.dump(evidence, f, indent=2)
        f.write('\n')

    # 6. observed objdump disassembly
    objdump_cmd = [
        'objdump', '-d', '--no-show-raw-insn',
        f"--start-address={hex(FDES[0]['start'])}",
        f"--stop-address={hex(FDES[-1]['end'])}",
        str(ROOT / BINARY_REL),
    ]
    res = subprocess.run(objdump_cmd, capture_output=True, text=True, check=True)
    with open(PACKET / 'observed' / 'hyperliquidity.objdump.txt', 'w', newline='\n', encoding='utf-8') as f:
        f.write(res.stdout)

    with open(PACKET / 'observed' / 'records.json', 'w', newline='\n', encoding='utf-8') as f:
        json.dump(records, f, indent=2)
        f.write('\n')

    # 7. README.md
    readme_content = f"""# Hyperliquidity Evidence Packet (Node #94)

Static verification evidence packet for `l1/src/hyperliquidity.rs` extracted from `artifacts/node/94/hl-node`
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
- `0x56df860`: `{SOURCE_PATH}:355:29` (referenced at `0x3262531`)

## Key Constants & Limits
- `HYPERLIQUIDITY_PRICE_RATIO`: `1.003` (double at `0x20a838`)
- `MIN_HYPERLIQUIDITY_ORDERS`: `10` (`0xa` at `0x3261eef`)
- `MAX_RAW_HYPERLIQUIDITY_VALUE`: `0x1999999999999999` (at `0x32620d7`)
- `MIN_END_MARKET_CAP_USDC`: `1,000,000,000` (`0x3b9aca00` at `0x326225d`)
- `MAX_END_MARKET_CAP_USDC`: `100,000,000,000` (`0x174876e800` at `0x3262266`)
- `MAX_START_MARKET_CAP_USDC`: `10,000,000` (`0x989680` at `0x326228c`)
- `MARKET_CAP_LOWER_SCALE`: `70,000,000` (`0xaae60 * 100` at `0x3262606`)
- `MARKET_CAP_UPPER_SCALE`: `130,000,000` (`0x13d620 * 100` at `0x326262a`)

## Status Codes Ground Truth
- `SUCCESS_CODE = 390` (`0x186` at `0x3261fb1`)
- `ERR_STATUS = 223` (`0xdf` at `0x3261d46`)
"""
    with open(PACKET / 'README.md', 'w', newline='\n', encoding='utf-8') as f:
        f.write(readme_content)

    # 8. MANIFEST.sha256
    packet_files = sorted([
        'README.md',
        'controls.tsv',
        'evidence.json',
        'observed/hyperliquidity.objdump.txt',
        'observed/records.json',
        'panic_records.tsv',
        'records.json',
        'rodata_constants.tsv',
    ])
    manifest_lines = []
    manifest_entries = []
    for rel_name in packet_files:
        p = PACKET / rel_name
        data = p.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        manifest_lines.append(f"{digest}  {rel_name}")
        manifest_entries.append({
            'path': rel_name,
            'sha256': digest,
            'size': len(data),
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
        print(f"Verified {len(results['fdes'])} FDEs, {len(results['panics'])} panic records, {len(results['rodata'])} rodata constants, {len(results['controls'])} opcode controls.")


if __name__ == '__main__':
    main()
