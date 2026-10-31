#!/usr/bin/env python3
"""RE/OrderWire: Node #94 order wire serialization and stream parsing static verification tool.

Static, offline verification tool. Zero execution of captured binaries.
Zero external network calls. Standard Python library only.

Target:
    artifacts/node/94/hl-node (SHA-256: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f)

Scope:
    1. Verification of binary byte extents for order wire FDEs:
       - FDE 1 (0x3330570..0x3330900, 912 B, sha256: f6b4a1c10d7c42c1a8fefc076610f510d1d26cc13eadb8d85f4a4e3ae2919ad8)
         Routine: decode_compact_orders
       - FDE 2 (0x3340e90..0x3341af0, 3168 B, sha256: 98b28dcb3dc33a259df31a804abcb2b1374598f219ad7b57094f9dbcc9efbec4)
         Routine: OrderWireSerde::to_internal & batch parsing
    2. Verification of 56-byte OrderWire struct layout (0x38 stride at 0x3341602: imul rcx, r13, 0x38).
    3. Verification of 3 panic record pointers in .data.rel.ro / .rela.dyn:
       - 0x56e9a80: line 326, col 35 in /home/ubuntu/hl/code_Mainnet/l1/src/order_wire.rs
       - 0x56e9a98: line 123, col 86 in /home/ubuntu/hl/code_Mainnet/l1/src/order_wire.rs
       - 0x56e9ab0: line 133, col 53 in /home/ubuntu/hl/code_Mainnet/l1/src/order_wire.rs
    4. Exact instruction control assertions for loop bounds, stride, and panic sites (11 controls).
    5. Clean-room mathematical & codec model of WireDecimal parsing, Cloid parsing, compact order entry framing.
"""

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
BINARY_REL = 'artifacts/node/94/hl-node'
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
EXPECTED_SIZE = 91774280

SOURCE_PATH = '/home/ubuntu/hl/code_Mainnet/l1/src/order_wire.rs'
WIRE_DECIMALS = 8
COMPACT_ORDER_BASE_LEN = 21
ORDER_WIRE_STRIDE = 56  # 0x38 bytes

PACKET = ROOT / 'research' / 'work-items' / 'order-wire-94'

FDES = [
    {
        'bytes': 912,
        'end_va': '0x3330900',
        'file_offset': '0x332f570',
        'id': 'fde1_batch_compact_decode',
        'panic_records': [
            '0x56e9a80',
        ],
        'role': 'decode_compact_orders (batch compact order decoding loop / orders.push)',
        'sha256': 'f6b4a1c10d7c42c1a8fefc076610f510d1d26cc13eadb8d85f4a4e3ae2919ad8',
        'start_va': '0x3330570',
    },
    {
        'bytes': 3168,
        'end_va': '0x3341af0',
        'file_offset': '0x333fe90',
        'id': 'fde2_order_wire_parse',
        'panic_records': [
            '0x56e9a98',
            '0x56e9ab0',
        ],
        'role': 'OrderWire::to_internal (string conversion & WireDecimal parse, stride 56 B)',
        'sha256': '98b28dcb3dc33a259df31a804abcb2b1374598f219ad7b57094f9dbcc9efbec4',
        'start_va': '0x3340e90',
    },
]

PANIC_LOCATIONS = {
    '0x56e9a80': {
        'col': 35,
        'fde': '0x3330570',
        'line': 326,
        'path': SOURCE_PATH,
        'record_va': '0x56e9a80',
    },
    '0x56e9a98': {
        'col': 86,
        'fde': '0x3340e90',
        'line': 123,
        'path': SOURCE_PATH,
        'record_va': '0x56e9a98',
    },
    '0x56e9ab0': {
        'col': 53,
        'fde': '0x3340e90',
        'line': 133,
        'path': SOURCE_PATH,
        'record_va': '0x56e9ab0',
    },
}

CONTROLS = {
    0x333057e: '0f8835030000',
    0x33305b2: '4d0fafc149c1e823',
    0x33305fa: '4c39f1',
    0x3330842: '48c744244020000060',
    0x33308c7: '4c8d05b2913b02',
    0x3340fed: '895338',
    0x3341602: '496bcd38',
    0x3341614: '4889740810',
    0x3341619: '4c89440818',
    0x3341a6e: '488d0d3b803a02',
    0x3341a98: '4c8d05f97f3a02',
}


class EvidenceError(Exception):
    """Raised when binary artifacts fail validation or decoding errors occur."""


class WireDecimal:
    """Fixed-point decimal with 8 decimal places (WireDecimal)."""
    def __init__(self, raw: int):
        if not (0 <= raw < (1 << 64)):
            raise EvidenceError(f'WireDecimal raw out of bounds: {raw}')
        self.raw = raw

    @classmethod
    def parse(cls, s: str):
        if not s:
            raise EvidenceError('Empty decimal string')
        parts = s.split('.')
        if len(parts) > 2:
            raise EvidenceError('Multiple decimal points')

        int_part = parts[0]
        frac_part = parts[1] if len(parts) == 2 else ''

        if not int_part.isdigit() and (int_part != '' or not frac_part.isdigit()):
            raise EvidenceError('Invalid integer digits in decimal string')
        if frac_part and not frac_part.isdigit():
            raise EvidenceError('Invalid fractional digits in decimal string')

        if len(frac_part) > WIRE_DECIMALS:
            raise EvidenceError(f'Fraction digits {len(frac_part)} exceed WIRE_DECIMALS ({WIRE_DECIMALS})')

        int_val = int(int_part) if int_part else 0
        frac_padded = frac_part.ljust(WIRE_DECIMALS, '0')
        frac_val = int(frac_padded) if frac_padded else 0

        total = int_val * (10 ** WIRE_DECIMALS) + frac_val
        if total >= (1 << 64):
            raise EvidenceError('WireDecimal overflow (>= 2^64)')
        return cls(total)

    def to_string(self) -> str:
        s = f'{self.raw:0{WIRE_DECIMALS+1}d}'
        int_part = s[:-WIRE_DECIMALS]
        frac_part = s[-WIRE_DECIMALS:].rstrip('0')
        if not frac_part:
            return int_part
        return f'{int_part}.{frac_part}'

    def __eq__(self, other):
        return isinstance(other, WireDecimal) and self.raw == other.raw

    def __repr__(self):
        return f'WireDecimal({self.raw} => {self.to_string()})'


def parse_cloid(s: str) -> bytes:
    """Parse 16-byte hex client order id (0x...)."""
    if not (s.startswith('0x') and len(s) == 34):
        raise EvidenceError(f'Invalid cloid format: {s}')
    try:
        raw = bytes.fromhex(s[2:])
        if len(raw) != 16:
            raise EvidenceError('Cloid must be exactly 16 bytes')
        return raw
    except ValueError as e:
        raise EvidenceError(f'Invalid hex in cloid: {e}')


def format_cloid(raw: bytes) -> str:
    if len(raw) != 16:
        raise EvidenceError('Cloid must be 16 bytes')
    return '0x' + raw.hex()


def encode_compact_order(
    asset: int,
    is_buy: bool,
    limit_px: WireDecimal,
    sz: WireDecimal,
    reduce_only: bool,
    type_code: int,
    trigger_px: WireDecimal | None = None,
    cloid: bytes | None = None,
) -> bytes:
    """Encode a single compact order entry into wire binary format."""
    if not (0 <= asset < (1 << 32)):
        raise EvidenceError(f'Asset id out of u32 range: {asset}')
    if not (1 <= type_code <= 9):
        raise EvidenceError(f'Invalid type_code: {type_code}')

    flags = (type_code << 2) | (1 if is_buy else 0) | (2 if reduce_only else 0)
    if trigger_px is not None:
        flags |= 0x10
    if cloid is not None:
        flags |= 0x40

    out = bytearray()
    out.extend(struct.pack('>I', asset))
    out.extend(struct.pack('>Q', limit_px.raw))
    out.extend(struct.pack('>Q', sz.raw))
    out.append(flags)
    if trigger_px is not None:
        out.extend(struct.pack('>Q', trigger_px.raw))
    if cloid is not None:
        if len(cloid) != 16:
            raise EvidenceError('Cloid must be 16 bytes')
        out.extend(cloid)
    return bytes(out)


def decode_compact_order(buf: bytes, offset: int = 0) -> tuple[dict, int]:
    """Decode a single compact order entry from bytes at offset."""
    if len(buf) - offset < COMPACT_ORDER_BASE_LEN:
        raise EvidenceError('Buffer too short for compact order entry')

    asset = struct.unpack_from('>I', buf, offset)[0]
    limit_px = WireDecimal(struct.unpack_from('>Q', buf, offset + 4)[0])
    sz = WireDecimal(struct.unpack_from('>Q', buf, offset + 12)[0])
    flags = buf[offset + 20]
    is_buy = bool(flags & 1)
    reduce_only = bool(flags & 2)
    type_code = (flags >> 2) & 0x0f
    has_trigger_px = (flags & 0x30) == 0x10
    has_cloid = bool(flags & 0x40)

    pos = offset + COMPACT_ORDER_BASE_LEN
    trigger_px = None
    if has_trigger_px:
        if len(buf) - pos < 8:
            raise EvidenceError('Buffer too short for trigger_px')
        trigger_px = WireDecimal(struct.unpack_from('>Q', buf, pos)[0])
        pos += 8

    cloid = None
    if has_cloid:
        if len(buf) - pos < 16:
            raise EvidenceError('Buffer too short for cloid')
        cloid = buf[pos:pos + 16]
        pos += 16

    order = {
        'asset': asset,
        'is_buy': is_buy,
        'limit_px': limit_px,
        'sz': sz,
        'reduce_only': reduce_only,
        'type_code': type_code,
        'trigger_px': trigger_px,
        'cloid': cloid,
    }
    return order, pos - offset


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
    """Analyze binary against FDE bounds, panic records, stride, and control invariants."""
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
        'stride': ORDER_WIRE_STRIDE,
        'source_records': verified_records,
        'controls': verified_controls,
    }


def generate_packet(out_dir: Path, binary_path: Path):
    """Generate research/work-items/order-wire-94 packet and verify MANIFEST.sha256."""
    data = binary_path.read_bytes()
    analysis = analyse(data)

    out_dir.mkdir(parents=True, exist_ok=True)
    obs_dir = out_dir / 'observed'
    obs_dir.mkdir(parents=True, exist_ok=True)

    # Copy observed objdump if available in repository packet
    repo_objdump = PACKET / 'observed' / 'order-wire.objdump.txt'
    if repo_objdump.exists():
        (obs_dir / 'order-wire.objdump.txt').write_bytes(repo_objdump.read_bytes())

    # records.json
    records_obj = {
        'component_id': 'RE/OrderWire',
        'controls': analysis['controls'],
        'fdes': analysis['fdes'],
        'panic_records': analysis['source_records'],
        'struct_stride_bytes': analysis['stride'],
        'subsystem': 'l1/src/order_wire.rs',
        'target_bytes': EXPECTED_SIZE,
        'target_sha256': EXPECTED_SHA256,
    }
    records_bytes = (json.dumps(records_obj, indent=2, sort_keys=True) + '\n').encode('utf-8')
    (out_dir / 'records.json').write_bytes(records_bytes)
    (obs_dir / 'records.json').write_bytes(records_bytes)

    # controls.tsv
    if (PACKET / 'controls.tsv').exists():
        (out_dir / 'controls.tsv').write_bytes((PACKET / 'controls.tsv').read_bytes())

    # evidence.json
    evidence_obj = {
        'component_id': 'RE/OrderWire',
        'controls_count': len(analysis['controls']),
        'controls_verified': True,
        'fde_count': len(analysis['fdes']),
        'fde_total_bytes': sum(f['bytes'] for f in analysis['fdes']),
        'panic_records_count': len(analysis['source_records']),
        'source_records_verified': True,
        'struct_stride': analysis['stride'],
        'target_release': '94',
        'target_sha256': EXPECTED_SHA256,
    }
    (out_dir / 'evidence.json').write_bytes((json.dumps(evidence_obj, indent=2, sort_keys=True) + '\n').encode('utf-8'))

    # panic_records.tsv
    if (PACKET / 'panic_records.tsv').exists():
        (out_dir / 'panic_records.tsv').write_bytes((PACKET / 'panic_records.tsv').read_bytes())

    # README.md
    if (PACKET / 'README.md').exists():
        (out_dir / 'README.md').write_bytes((PACKET / 'README.md').read_bytes())

    # MANIFEST.sha256
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
    ap.add_argument('--out', type=Path, default=ROOT / 'research' / 'work-items' / 'order-wire-94')
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
        'order_wire_stride': analysis['stride'],
        'stride_verified': True,
        'controls_verified': len(analysis['controls']),
        'all_panic_records_verified': True,
        'panic_records_count': len(analysis['source_records']),
        'target_sha256': EXPECTED_SHA256,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
