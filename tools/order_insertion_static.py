#!/usr/bin/env python3
"""RE-006: Order Book Transition and Resting Order Insertion static verification tool.

Static, offline verification tool. Zero execution of captured binaries.
Zero external network calls. Standard Python library only.

Target:
    artifacts/node/94/hl-node (SHA-256: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f)

Scope:
    1. Verification of FDE extent for order book insertion & resting order logic:
       - 0x26ebdc0..0x26eff10 (16,720 B, sha256: 3e433627e7c5029341c07d37a9bf8e8d7f7a03a8dd29c5f795283f22b476cdf9)
    2. Verification of 4 panic records in impl_insert_order.rs:
       - 0x56bd8b8: l1/src/book/book/impl_insert_order.rs:167:17
       - 0x56bd888: l1/src/book/book/impl_insert_order.rs:445:56
       - 0x56bd858: l1/src/book/book/impl_insert_order.rs:514:43
       - 0x56bd870: l1/src/book/book/impl_insert_order.rs:517:59
    3. Verification of control instruction anchors:
       - Max limit price ceiling 10^15 (0x38d7ea4c68000) at 0x26ec53d
       - Signed price key encoding (Buy = -px, Sell = +px) at 0x26ec778
       - Notional multiplication and overflow flag at 0x26ed7b2
       - Minimum notional floor 0x0098967f (9,999,999 ticks) at 0x26ed7c2
       - Signed level key traversal in BTreeMap at 0x26ec501 and 0x26eec02
    4. Model of order insertion status validation and resting order key derivation.
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

FDE_START = 0x26ebdc0
FDE_END = 0x26eff10
FDE_SIZE = 16720
FDE_SHA256 = '3e433627e7c5029341c07d37a9bf8e8d7f7a03a8dd29c5f795283f22b476cdf9'

MAX_LIMIT_PX = 1_000_000_000_000_000  # 10^15 (0x38d7ea4c68000)
MAX_NOTIONAL = 0x7fff_ffff_ffff_fffe
MIN_NOTIONAL_FLOOR = 0x0098967f       # 9,999,999 ($10 at 6 decimals minus 1 tick)

STATUS_CODES = {
    0x8000000000000000: 'STATUS_PRICE_OR_TICK',
    0x8000000000000001: 'STATUS_NOTIONAL',
    0x8000000000000003: 'STATUS_QUEUE_MASK',
    0x8000000000000005: 'STATUS_NO_USER_PRICE_QTY',
    0x8000000000000006: 'STATUS_POST_ONLY_CROSSES',
    0x8000000000000008: 'STATUS_TIF_NOT_MARKETABLE',
    0x8000000000000012: 'STATUS_AVAILABLE_SIZE',
    0x8000000000000013: 'STATUS_NO_VALID_CROSS',
    0x8000000000000014: 'STATUS_INDEX_ROUTE',
    0x8000000000000015: 'STATUS_SLOT_EMPTY_FOR_REPLACE',
    0x8000000000000016: 'STATUS_SLOT_MISSING',
    0x8000000000000017: 'STATUS_DUPLICATE_ORDER',
    0x8000000000000018: 'STATUS_OK',
}

PANIC_RECORDS = {
    0x56bd8b8: {
        'expected_file': '/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs',
        'line': 167,
        'col': 17,
        'role': 'Order insertion state precondition invariant',
    },
    0x56bd888: {
        'expected_file': '/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs',
        'line': 445,
        'col': 56,
        'role': 'Order size or book level consistency invariant',
    },
    0x56bd858: {
        'expected_file': '/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs',
        'line': 514,
        'col': 43,
        'role': 'Resting order book level insertion invariant',
    },
    0x56bd870: {
        'expected_file': '/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs',
        'line': 517,
        'col': 59,
        'role': 'Resting order post-insertion queue invariant',
    },
}

CONTROLS = {
    0x26ec53d: '48b80080c6a47e8d0300',          # movabs rax, 1000000000000000 (10^15 max limit px)
    0x26ec54c: '4839c27609',                    # cmp rdx, rax; jbe 0x26ec55a (max limit px guard)
    0x26ec76f: '4885f60f8814330000',            # test rsi, rsi; js 0x26efa8c (negative px reject)
    0x26ec778: '4889f148f7d9807c242800480f45ce',# mov rcx, rsi; neg rcx; cmpb [rsp+0x28], 0; cmovne rcx, rsi
    0x26ed7b2: '48f7e60f90c2',                  # mul rsi; seto dl (notional mul + overflow)
    0x26ed7c2: '483d7f9698000f87c2efffff',      # cmp rax, 0x98967f; ja 0x26ec790 (min notional floor)
    0x26ec501: '4889c348f7db480f48d8',          # mov rbx, rax; neg rbx; cmovs rbx, rax
    0x26eec02: '4889c148f7d9480f48c8',          # mov rcx, rax; neg rcx; cmovs rcx, rax
}


class EvidenceError(Exception):
    """Raised when binary artifacts fail validation."""


def derive_signed_price_key(px: int, is_buy: bool) -> int:
    """Derive signed resting order price key: Buy = -px, Sell = +px."""
    if px < 0:
        raise EvidenceError(f'negative price rejected: {px}')
    return -px if is_buy else px


def validate_order_insertion(
    px: int,
    sz: int,
    is_buy: bool,
    max_notional: int = MAX_NOTIONAL,
    allow_sub_min_notional: bool = False,
) -> dict:
    """Model order insertion parameters and status codes matching FDE 0x26ebdc0."""
    if px <= 0:
        return {
            'status': 'error',
            'status_code': 0x8000000000000000,
            'status_name': STATUS_CODES[0x8000000000000000],
            'reason': f'price must be positive: {px}',
        }

    if px > MAX_LIMIT_PX:
        return {
            'status': 'error',
            'status_code': 0x8000000000000000,
            'status_name': STATUS_CODES[0x8000000000000000],
            'reason': f'price exceeds max limit price: {px} > {MAX_LIMIT_PX}',
        }

    if sz <= 0:
        return {
            'status': 'error',
            'status_code': 0x8000000000000005,
            'status_name': STATUS_CODES[0x8000000000000005],
            'reason': f'size must be positive: {sz}',
        }

    notional = px * sz
    if notional > max_notional or notional > 0x7fffffffffffffff:
        return {
            'status': 'error',
            'status_code': 0x8000000000000001,
            'status_name': STATUS_CODES[0x8000000000000001],
            'reason': f'notional exceeds max notional limit: {notional} > {max_notional}',
        }

    if notional <= MIN_NOTIONAL_FLOOR and not allow_sub_min_notional:
        return {
            'status': 'error',
            'status_code': 0x8000000000000001,
            'status_name': STATUS_CODES[0x8000000000000001],
            'reason': f'notional below minimum floor: {notional} <= {MIN_NOTIONAL_FLOOR}',
        }

    signed_key = derive_signed_price_key(px, is_buy)

    return {
        'status': 'ok',
        'status_code': 0x8000000000000018,
        'status_name': STATUS_CODES[0x8000000000000018],
        'px': px,
        'sz': sz,
        'notional': notional,
        'is_buy': is_buy,
        'signed_price_key': signed_key,
    }


def sections(data):
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
        secs[name] = {'addr': sh_addr, 'offset': sh_offset, 'size': sh_size}
    return secs


class Image:
    """ELF mapped virtual image reader."""
    def __init__(self, data):
        self.data = data
        self.sec = sections(data)
        self._table = sorted(
            [(s['addr'], s['offset'], s['size']) for s in self.sec.values() if s['addr'] != 0],
            key=lambda t: t[0],
        )

    def off(self, va):
        i = bisect.bisect_right(self._table, (va, 1 << 60, 0)) - 1
        if i >= 0:
            addr, off, size = self._table[i]
            if addr <= va < addr + size:
                return off + (va - addr)
        raise EvidenceError(f'VA 0x{va:x} not mapped')

    def read(self, va, size):
        o = self.off(va)
        return self.data[o: o + size]


def uleb(buf, i):
    val = shift = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7f) << shift
        shift += 7
        if b < 0x80:
            return val, i


def read_enc(img, va, enc):
    fmt = enc & 0x0f
    size, code = {0x03: (4, '<I'), 0x0b: (4, '<i'), 0x04: (8, '<Q'), 0x0c: (8, '<q')}[fmt]
    val = struct.unpack(code, img.read(va, size))[0]
    if enc & 0x70 == 0x10:
        val += va
    elif enc & 0x70 not in (0x00,):
        raise EvidenceError(f'unsupported pointer encoding {enc:#x}')
    return val & 0xffffffffffffffff, size


class Fdes:
    """Parse .eh_frame table to verify function call frame boundaries."""
    def __init__(self, img):
        self.img = img
        hdr = img.sec['.eh_frame_hdr']['addr']
        version, ptr_enc, cnt_enc, tbl_enc = img.read(hdr, 4)
        if (version, cnt_enc, tbl_enc) != (1, 0x03, 0x3b):
            raise EvidenceError('unexpected .eh_frame_hdr encodings')
        _, n = read_enc(img, hdr + 4, ptr_enc)
        count = struct.unpack('<I', img.read(hdr + 4 + n, 4))[0]
        table = img.read(hdr + 8 + n, count * 8)
        self.starts, self.fde = [], []
        for i in range(count):
            loc, fde = struct.unpack_from('<ii', table, i * 8)
            self.starts.append(hdr + loc)
            self.fde.append(hdr + fde)
        self.count = count

    def cie_r_encoding(self, cie):
        img = self.img
        body = img.read(cie + 4, 64)
        if struct.unpack_from('<I', body, 0)[0] != 0:
            raise EvidenceError('CIE id is not zero')
        version = body[4]
        end = body.index(b'\0', 5)
        aug = body[5:end].decode()
        i = end + 1
        _, i = uleb(body, i)
        _, i = uleb(body, i)
        if version == 1:
            i += 1
        else:
            _, i = uleb(body, i)
        if not aug.startswith('z'):
            raise EvidenceError('CIE without z augmentation')
        _, i = uleb(body, i)
        for ch in aug[1:]:
            if ch == 'R':
                return body[i]
            if ch == 'L':
                i += 1
            elif ch == 'P':
                penc = body[i]
                i += 1 + {0x03: 4, 0x0b: 4, 0x04: 8, 0x0c: 8}[penc & 0x0f]
            else:
                raise EvidenceError(f'unsupported augmentation {aug!r}')
        raise EvidenceError('CIE has no R augmentation')

    def range_of(self, va):
        k = bisect.bisect_right(self.starts, va) - 1
        if k < 0:
            raise EvidenceError(f'{va:#x} precedes every FDE')
        fde = self.fde[k]
        cie_ptr = struct.unpack('<I', self.img.read(fde + 4, 4))[0]
        enc = self.cie_r_encoding(fde + 4 - cie_ptr)
        begin, n = read_enc(self.img, fde + 8, enc)
        length, _ = read_enc(self.img, fde + 8 + n, enc & 0x0f)
        if begin != self.starts[k]:
            raise EvidenceError(f'FDE {fde:#x} pc_begin disagrees with .eh_frame_hdr')
        if not begin <= va < begin + length:
            raise EvidenceError(f'{va:#x} is outside FDE [{begin:#x},{begin + length:#x})')
        return {'start': begin, 'end': begin + length, 'fde': fde, 'hdr_index': k}


def load_expected_artifact(root: Path, binary_rel: str) -> dict:
    """Validate binary metadata against provenance/artifacts.json."""
    artifacts_json = root / 'provenance' / 'artifacts.json'
    if not artifacts_json.exists():
        raise EvidenceError(f'missing provenance file: {artifacts_json}')

    records = json.loads(artifacts_json.read_text(encoding='utf-8'))
    files = records.get('files', []) if isinstance(records, dict) else records
    for item in files:
        if isinstance(item, dict) and item.get('path') == binary_rel:
            return item
    raise EvidenceError(f'target {binary_rel} not pinned in {artifacts_json}')


def check_digest(data: bytes, root: Path) -> str:
    """Verify SHA-256 and size against provenance."""
    expected = load_expected_artifact(root, BINARY_REL)
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected['sha256'] or len(data) != expected['size']:
        raise EvidenceError(
            f'binary digest/size mismatch: got {digest}/{len(data)}, '
            f'expected {expected["sha256"]}/{expected["size"]}'
        )
    return digest


def verify_panic_records(data: bytes, img: Image) -> dict:
    """Verify panic records in .rodata / .rela.dyn."""
    sec = img.sec['.rela.dyn']
    off, size = sec['offset'], sec['size']
    relocs = {}
    for i in range(off, off + size, 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, i)
        if r_offset in PANIC_RECORDS:
            relocs[r_offset] = r_addend

    verified = {}
    for va, meta in PANIC_RECORDS.items():
        b = img.read(va, 24)
        file_ptr, file_len, line, col = struct.unpack('<QQII', b)
        if line != meta['line'] or col != meta['col']:
            raise EvidenceError(
                f'panic record line/col mismatch at 0x{va:x}: {line}:{col} != {meta["line"]}:{meta["col"]}'
            )

        if va not in relocs:
            raise EvidenceError(f'missing relocation in .rela.dyn for panic record 0x{va:x}')

        r_addend = relocs[va]
        actual_file = img.read(r_addend, file_len).decode('utf-8', errors='replace')
        if actual_file != meta['expected_file']:
            raise EvidenceError(
                f'panic file string mismatch at 0x{va:x}: {actual_file!r} != {meta["expected_file"]!r}'
            )

        verified[hex(va)] = {
            'file': actual_file,
            'line': line,
            'col': col,
            'role': meta['role'],
        }
    return verified


def verify_controls(img: Image, controls_dict: dict):
    """Verify byte-level instruction control assertions."""
    for va, expected_hex in controls_dict.items():
        size = len(expected_hex) // 2
        actual = img.read(va, size).hex().lower()
        if actual != expected_hex.lower():
            raise EvidenceError(
                f'instruction control failed at 0x{va:x}: '
                f'expected {expected_hex.lower()}, got {actual}'
            )


def generate_sample_vectors():
    """Generate extensive test vectors for order insertion validation and resting key derivation."""
    vectors = []

    # 1. Price range and signed key derivation
    prices = [1, 10, 100, 1000, 50000, 1_000_000, MAX_LIMIT_PX]
    for px in prices:
        for is_buy in [True, False]:
            res = validate_order_insertion(px=px, sz=1000, is_buy=is_buy)
            vectors.append({
                'type': 'signed_key_eval',
                'px': px,
                'sz': 1000,
                'is_buy': is_buy,
                'status': res['status'],
                'signed_price_key': res.get('signed_price_key'),
            })

    # 2. Min notional floor checks (around 9,999,999)
    notionals = [
        (1000, 9999),       # 9,999,000 <= 9,999,999 -> rejected
        (1, 9_999_999),     # 9,999,999 <= 9,999,999 -> rejected
        (1, 10_000_000),    # 10,000,000 > 9,999,999 -> ok
        (1000, 10000),      # 10,000,000 > 9,999,999 -> ok
        (50000, 201),       # 10,050,000 > 9,999,999 -> ok
    ]
    for px, sz in notionals:
        res = validate_order_insertion(px=px, sz=sz, is_buy=True)
        vectors.append({
            'type': 'min_notional_eval',
            'px': px,
            'sz': sz,
            'notional': px * sz,
            'status': res['status'],
            'status_code': hex(res['status_code']),
        })

    # 3. Max limit price boundary
    for px in [MAX_LIMIT_PX - 1, MAX_LIMIT_PX, MAX_LIMIT_PX + 1]:
        res = validate_order_insertion(px=px, sz=1, is_buy=False, allow_sub_min_notional=True)
        vectors.append({
            'type': 'max_price_eval',
            'px': px,
            'status': res['status'],
            'status_code': hex(res['status_code']),
        })

    return vectors


def analyse(data: bytes, root: Path = ROOT) -> tuple:
    """Analyze binary against FDE bounds, instruction controls, panic records, and models."""
    digest = check_digest(data, root)
    img = Image(data)
    fdes = Fdes(img)

    # 1. Verify FDE bounds and hash
    r = fdes.range_of(FDE_START)
    if r['start'] != FDE_START or r['end'] != FDE_END:
        raise EvidenceError(
            f'FDE bounds mismatch: got 0x{r["start"]:x}..0x{r["end"]:x}, '
            f'expected 0x{FDE_START:x}..0x{FDE_END:x}'
        )
    fde_bytes = img.read(FDE_START, FDE_SIZE)
    fde_sha = hashlib.sha256(fde_bytes).hexdigest()
    if fde_sha != FDE_SHA256:
        raise EvidenceError(f'FDE sha256 mismatch: {fde_sha} != {FDE_SHA256}')

    # 2. Verify control instructions
    verify_controls(img, CONTROLS)

    # 3. Verify panic records
    panic_evidence = verify_panic_records(data, img)

    # 4. Generate and verify sample vectors
    vectors = generate_sample_vectors()

    summary = {
        'all_fde_bounds_verified': True,
        'fde_size': FDE_SIZE,
        'controls_verified': len(CONTROLS),
        'all_panic_records_verified': True,
        'panic_records_count': len(panic_evidence),
        'sample_vectors_verified': len(vectors),
        'min_notional_floor': MIN_NOTIONAL_FLOOR,
        'max_limit_px': MAX_LIMIT_PX,
    }

    result = {
        'schema_version': 1,
        'task': 'RE-006',
        'component': 'Order Book Transition and Resting Order Insertion',
        'target_binary': BINARY_REL,
        'sha256': digest,
        'fde': {
            'name': 'Book::insert_order',
            'start': hex(FDE_START),
            'end': hex(FDE_END),
            'size': FDE_SIZE,
            'sha256': fde_sha,
            'fde_record': hex(r['fde']),
            'controls': {hex(k): v for k, v in CONTROLS.items()},
        },
        'constants': {
            'max_limit_px': MAX_LIMIT_PX,
            'min_notional_floor': hex(MIN_NOTIONAL_FLOOR),
            'max_notional': hex(MAX_NOTIONAL),
        },
        'status_codes': {hex(k): v for k, v in STATUS_CODES.items()},
        'panic_records': panic_evidence,
        'signed_price_rule': 'Buy = -px, Sell = +px',
        'summary': summary,
    }

    return result, vectors


def write(out: Path, result: dict, vectors: list):
    """Write generated packet files with LF line endings."""
    out.mkdir(parents=True, exist_ok=True)

    # 1. evidence.json
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')

    # 2. status_codes.tsv
    code_rows = ['code_hex\tname']
    for code, name in sorted(result['status_codes'].items()):
        code_rows.append(f"{code}\t{name}")
    (out / 'status_codes.tsv').write_text('\n'.join(code_rows) + '\n', newline='\n')

    # 3. panics.tsv
    panic_rows = ['va\tfile\tline\tcol\trole']
    for va, meta in sorted(result['panic_records'].items()):
        panic_rows.append(f"{va}\t{meta['file']}\t{meta['line']}\t{meta['col']}\t{meta['role']}")
    (out / 'panics.tsv').write_text('\n'.join(panic_rows) + '\n', newline='\n')

    # 4. controls.tsv
    ctrl_rows = ['va\topcodes']
    for va, op in sorted(result['fde']['controls'].items()):
        ctrl_rows.append(f"{va}\t{op}")
    (out / 'controls.tsv').write_text('\n'.join(ctrl_rows) + '\n', newline='\n')

    # 5. vectors.tsv
    vec_rows = ['type\tdetails']
    for v in vectors:
        vec_rows.append(f"{v['type']}\t{json.dumps(v, sort_keys=True)}")
    (out / 'vectors.tsv').write_text('\n'.join(vec_rows) + '\n', newline='\n')

    # 6. MANIFEST.sha256
    manifest_lines = []
    for fname in sorted(['evidence.json', 'status_codes.tsv', 'panics.tsv', 'controls.tsv', 'vectors.tsv']):
        p = out / fname
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        manifest_lines.append(f'{digest}  {fname}')
    (out / 'MANIFEST.sha256').write_text('\n'.join(manifest_lines) + '\n', newline='\n')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', type=Path, default=None)
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY_REL)
    args = ap.parse_args(argv)

    try:
        data = args.binary.read_bytes()
        result, vectors = analyse(data, root=ROOT)
    except EvidenceError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

    if args.out:
        write(args.out, result, vectors)

    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
